// cel_policy.go — Sweeper entry point, typed VAP/MAP v1 census, and
// hot-reloaded feature gates for the CEL Admission Policy Guard.
package celpolicy

import (
	"context"
	"errors"
	"fmt"
	"time"

	admissionv1 "k8s.io/api/admissionregistration/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	logf "sigs.k8s.io/controller-runtime/pkg/log"

	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-automation-controller/internal/apiserver/webhookguard/guardstate"
	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-automation-controller/internal/platform/kube"
	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-automation-controller/internal/platform/state"
	"github.com/passiontech-global/kubernetes-cluster-automation/libs/hostkit/envx"
)

const (
	// KindValidatingPolicy / KindMutatingPolicy are the metric "kind"
	// label values emitted by celpolicy.
	KindValidatingPolicy = "validating_admission_policy"
	KindMutatingPolicy   = "mutating_admission_policy"

	defaultTripWindow       = 5 * time.Minute
	defaultMinMissingCycles = 2
	defaultRecoverCycles    = 2
)

// CriticalNSEnforceEnabled reads the critical-NS auto-patch gate per
// sweep (the sanctioned webhookguard hot-reload exception). Default: true.
func CriticalNSEnforceEnabled() bool {
	return envx.Gate("CEL_POLICY_CRITICAL_NS_ENFORCE_ENABLED", true)
}

// CircuitBreakerEnabled reads the CEL circuit-breaker trip gate per
// sweep (the sanctioned webhookguard hot-reload exception). Default: true.
// Recovery (Ignore -> Fail) still runs when disabled (RestoreOnly parity).
func CircuitBreakerEnabled() bool {
	return envx.Gate("CEL_POLICY_CIRCUIT_BREAKER_ENABLED", true)
}

// Sweeper holds the per-sweep persistence ledgers and gauge ledgers for
// the CEL Admission Policy Guard. Zero value is ready to use.
type Sweeper struct {
	paramMissingSince  state.FirstSeenLedger
	paramMissingStreak state.StreakLedger
	celErrorSince      state.FirstSeenLedger
	recoverStreak      state.StreakLedger
	brokenEmitted      state.GaugeLedger[string]
	critNSEmitted      state.GaugeLedger[string]
	heals              state.CooldownSet

	// Test seams (zero = production defaults).
	tripWindow       time.Duration
	minMissingCycles int
	recoverCycles    int
}

func (s *Sweeper) effTripWindow() time.Duration {
	if s.tripWindow > 0 {
		return s.tripWindow
	}
	return defaultTripWindow
}

func (s *Sweeper) effMinMissingCycles() int {
	if s.minMissingCycles > 0 {
		return s.minMissingCycles
	}
	return defaultMinMissingCycles
}

func (s *Sweeper) effRecoverCycles() int {
	if s.recoverCycles > 0 {
		return s.recoverCycles
	}
	return defaultRecoverCycles
}

type policyView struct {
	Kind             string
	Name             string
	Annotations      map[string]string
	Object           metav1.Object
	FailurePolicy    *admissionv1.FailurePolicyType
	MatchConstraints *admissionv1.MatchResources
	ParamKind        *admissionv1.ParamKind
	patchFn          func(ctx context.Context, payload []byte) (*policyView, error)
}

func (p *policyView) key() string {
	return p.Kind + "/" + p.Name
}

func (p *policyView) applyPatched(next *policyView) {
	p.Annotations = next.Annotations
	p.Object = next.Object
	p.FailurePolicy = next.FailurePolicy
	p.MatchConstraints = next.MatchConstraints
	p.ParamKind = next.ParamKind
}

type bindingView struct {
	Name           string
	PolicyName     string
	ParamRef       *admissionv1.ParamRef
	MatchResources *admissionv1.MatchResources
}

type kindCensus struct {
	kind     string
	policies []policyView
	bindings map[string][]bindingView
	skipped  bool // true when 403 Forbidden or transient error (carry gauges forward)
	absent   bool // true when 404/NoMatch (API not served on cluster; prune gauges)
	err      error
}

// Sweep audits ValidatingAdmissionPolicies and MutatingAdmissionPolicies
// (and their bindings) for critical-namespace exposure and runtime faults.
func (s *Sweeper) Sweep(ctx context.Context, snap *guardstate.Snapshot) error {
	if snap == nil || snap.G == nil || snap.G.CS == nil {
		return nil
	}
	g := snap.G
	log := logf.FromContext(ctx)

	valCensus := loadValidatingPolicies(ctx, g)
	mutCensus := loadMutatingPolicies(ctx, g)

	var errs []error
	if valCensus.err != nil {
		log.Error(valCensus.err, "list ValidatingAdmissionPolicy/Bindings failed")
		errs = append(errs, valCensus.err)
	}
	if mutCensus.err != nil {
		log.Error(mutCensus.err, "list MutatingAdmissionPolicy/Bindings failed")
		errs = append(errs, mutCensus.err)
	}

	censuses := []*kindCensus{&valCensus, &mutCensus}
	breakerErr := s.sweepCircuitBreaker(ctx, snap, censuses)
	if breakerErr != nil {
		errs = append(errs, breakerErr)
	}
	s.sweepCriticalNS(ctx, snap, censuses)
	return errors.Join(errs...)
}

func loadValidatingPolicies(ctx context.Context, g *guardstate.Guard) kindCensus {
	log := logf.FromContext(ctx)
	opts := metav1.ListOptions{ResourceVersion: "0", Limit: kube.DefaultListPageSize}

	policies, err := kube.ListAll(ctx, opts, func(ctx context.Context, o metav1.ListOptions) ([]admissionv1.ValidatingAdmissionPolicy, string, error) {
		l, e := g.CS.AdmissionregistrationV1().ValidatingAdmissionPolicies().List(ctx, o)
		if e != nil {
			return nil, "", e
		}
		return l.Items, l.Continue, nil
	})
	if err != nil {
		if kube.IsCRDAbsent(err) {
			log.V(1).Info("ValidatingAdmissionPolicy API not served — skipping", "error", err)
			return kindCensus{kind: KindValidatingPolicy, absent: true}
		}
		if apierrors.IsForbidden(err) {
			log.V(1).Info("ValidatingAdmissionPolicy list forbidden (403) — skipping", "error", err)
			return kindCensus{kind: KindValidatingPolicy, skipped: true}
		}
		return kindCensus{kind: KindValidatingPolicy, skipped: true, err: fmt.Errorf("list validatingadmissionpolicies: %w", err)}
	}

	bindings, err := kube.ListAll(ctx, opts, func(ctx context.Context, o metav1.ListOptions) ([]admissionv1.ValidatingAdmissionPolicyBinding, string, error) {
		l, e := g.CS.AdmissionregistrationV1().ValidatingAdmissionPolicyBindings().List(ctx, o)
		if e != nil {
			return nil, "", e
		}
		return l.Items, l.Continue, nil
	})
	if err != nil {
		if kube.IsCRDAbsent(err) {
			log.V(1).Info("ValidatingAdmissionPolicyBinding API not served — skipping", "error", err)
			return kindCensus{kind: KindValidatingPolicy, absent: true}
		}
		if apierrors.IsForbidden(err) {
			log.V(1).Info("ValidatingAdmissionPolicyBinding list forbidden (403) — skipping", "error", err)
			return kindCensus{kind: KindValidatingPolicy, skipped: true}
		}
		return kindCensus{kind: KindValidatingPolicy, skipped: true, err: fmt.Errorf("list validatingadmissionpolicybindings: %w", err)}
	}

	out := kindCensus{
		kind:     KindValidatingPolicy,
		policies: make([]policyView, len(policies)),
		bindings: make(map[string][]bindingView),
	}
	for i := range policies {
		out.policies[i] = validatingPolicyView(g, &policies[i])
	}
	for i := range bindings {
		b := &bindings[i]
		out.bindings[b.Spec.PolicyName] = append(out.bindings[b.Spec.PolicyName], bindingView{
			Name:           b.Name,
			PolicyName:     b.Spec.PolicyName,
			ParamRef:       b.Spec.ParamRef,
			MatchResources: b.Spec.MatchResources,
		})
	}
	return out
}

func validatingPolicyView(g *guardstate.Guard, p *admissionv1.ValidatingAdmissionPolicy) policyView {
	return policyView{
		Kind:             KindValidatingPolicy,
		Name:             p.Name,
		Annotations:      p.Annotations,
		Object:           p,
		FailurePolicy:    p.Spec.FailurePolicy,
		MatchConstraints: p.Spec.MatchConstraints,
		ParamKind:        p.Spec.ParamKind,
		patchFn: func(ctx context.Context, payload []byte) (*policyView, error) {
			patched, err := g.CS.AdmissionregistrationV1().ValidatingAdmissionPolicies().
				Patch(ctx, p.Name, types.MergePatchType, payload, metav1.PatchOptions{})
			if err != nil {
				return nil, err
			}
			v := validatingPolicyView(g, patched)
			return &v, nil
		},
	}
}

func loadMutatingPolicies(ctx context.Context, g *guardstate.Guard) kindCensus {
	log := logf.FromContext(ctx)
	opts := metav1.ListOptions{ResourceVersion: "0", Limit: kube.DefaultListPageSize}

	policies, err := kube.ListAll(ctx, opts, func(ctx context.Context, o metav1.ListOptions) ([]admissionv1.MutatingAdmissionPolicy, string, error) {
		l, e := g.CS.AdmissionregistrationV1().MutatingAdmissionPolicies().List(ctx, o)
		if e != nil {
			return nil, "", e
		}
		return l.Items, l.Continue, nil
	})
	if err != nil {
		if kube.IsCRDAbsent(err) {
			log.V(1).Info("MutatingAdmissionPolicy API not served — skipping", "error", err)
			return kindCensus{kind: KindMutatingPolicy, absent: true}
		}
		if apierrors.IsForbidden(err) {
			log.V(1).Info("MutatingAdmissionPolicy list forbidden (403) — skipping", "error", err)
			return kindCensus{kind: KindMutatingPolicy, skipped: true}
		}
		return kindCensus{kind: KindMutatingPolicy, skipped: true, err: fmt.Errorf("list mutatingadmissionpolicies: %w", err)}
	}

	bindings, err := kube.ListAll(ctx, opts, func(ctx context.Context, o metav1.ListOptions) ([]admissionv1.MutatingAdmissionPolicyBinding, string, error) {
		l, e := g.CS.AdmissionregistrationV1().MutatingAdmissionPolicyBindings().List(ctx, o)
		if e != nil {
			return nil, "", e
		}
		return l.Items, l.Continue, nil
	})
	if err != nil {
		if kube.IsCRDAbsent(err) {
			log.V(1).Info("MutatingAdmissionPolicyBinding API not served — skipping", "error", err)
			return kindCensus{kind: KindMutatingPolicy, absent: true}
		}
		if apierrors.IsForbidden(err) {
			log.V(1).Info("MutatingAdmissionPolicyBinding list forbidden (403) — skipping", "error", err)
			return kindCensus{kind: KindMutatingPolicy, skipped: true}
		}
		return kindCensus{kind: KindMutatingPolicy, skipped: true, err: fmt.Errorf("list mutatingadmissionpolicybindings: %w", err)}
	}

	out := kindCensus{
		kind:     KindMutatingPolicy,
		policies: make([]policyView, len(policies)),
		bindings: make(map[string][]bindingView),
	}
	for i := range policies {
		out.policies[i] = mutatingPolicyView(g, &policies[i])
	}
	for i := range bindings {
		b := &bindings[i]
		out.bindings[b.Spec.PolicyName] = append(out.bindings[b.Spec.PolicyName], bindingView{
			Name:           b.Name,
			PolicyName:     b.Spec.PolicyName,
			ParamRef:       b.Spec.ParamRef,
			MatchResources: b.Spec.MatchResources,
		})
	}
	return out
}

func mutatingPolicyView(g *guardstate.Guard, p *admissionv1.MutatingAdmissionPolicy) policyView {
	return policyView{
		Kind:             KindMutatingPolicy,
		Name:             p.Name,
		Annotations:      p.Annotations,
		Object:           p,
		FailurePolicy:    p.Spec.FailurePolicy,
		MatchConstraints: p.Spec.MatchConstraints,
		ParamKind:        p.Spec.ParamKind,
		patchFn: func(ctx context.Context, payload []byte) (*policyView, error) {
			patched, err := g.CS.AdmissionregistrationV1().MutatingAdmissionPolicies().
				Patch(ctx, p.Name, types.MergePatchType, payload, metav1.PatchOptions{})
			if err != nil {
				return nil, err
			}
			v := mutatingPolicyView(g, patched)
			return &v, nil
		},
	}
}
