// cel_circuit_breaker.go — missing paramRef and PromQL CEL evaluation
// error-storm circuit breaking + 2-clean-cycle auto-restore for CEL policies.
package celpolicy

import (
	"context"
	json "encoding/json/v2"
	"errors"
	"fmt"
	"strings"
	"time"

	admissionv1 "k8s.io/api/admissionregistration/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/api/meta"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime/schema"
	logf "sigs.k8s.io/controller-runtime/pkg/log"

	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-automation-controller/internal/apiserver/webhookguard/guardstate"
	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-automation-controller/internal/metrics"
	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-automation-controller/internal/platform/heal"
	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-automation-controller/internal/platform/kube"
)

const (
	celVAPErrorRateQuery = `sum by (policy) (rate(apiserver_validating_admission_policy_check_total{error_type!="no_error"}[5m])) > 0`
	celMAPErrorRateQuery = `sum by (policy) (rate(apiserver_mutating_admission_policy_check_total{error_type!="no_error"}[5m])) > 0`
)

func (s *Sweeper) sweepCircuitBreaker(ctx context.Context, snap *guardstate.Snapshot, censuses []*kindCensus) error {
	s.brokenEmitted.Begin()
	g := snap.G
	log := logf.FromContext(ctx)
	now := g.Now.Now()
	allowTrips := CircuitBreakerEnabled()

	var errPolicies map[string]bool
	var promErrs map[string]error
	if allowTrips || hasAnyBrokenPolicy(censuses) {
		errPolicies, promErrs = queryCELErrorPolicies(ctx, g)
		if joined := errors.Join(promErrs[KindValidatingPolicy], promErrs[KindMutatingPolicy]); joined != nil {
			metrics.IncError(g.Queue)
			log.Error(joined, "CEL policy evaluation error-rate Prometheus query failed")
		}
	}

	liveKeys := map[string]bool{}
	faultSeen := map[string]bool{}
	celErrFaultSeen := map[string]bool{}
	allKindsReadable := true
	var patchErrs []error

	for _, c := range censuses {
		if c.absent {
			continue
		}
		if c.skipped {
			allKindsReadable = false
			s.carryBrokenKind(c.kind)
			continue
		}

		kindPromErr := promErrs[c.kind] != nil

		for i := range c.policies {
			p := &c.policies[i]
			key := p.key()
			liveKeys[key] = true
			broken := p.Annotations[kube.AnnoCircuitBrokenCELPolicy] != ""

			if !allowTrips && !broken {
				s.recoverStreak.Reset(key)
				continue
			}

			paramMissing, paramUnverifiable := checkMissingParamRef(ctx, g, p, c.bindings[p.Name])
			celErrActive := errPolicies[key]

			var paramTripped, celErrTripped bool
			if allowTrips {
				faultSeen[key] = true
				switch {
				case paramMissing:
					cycles := s.paramMissingStreak.Hit(key)
					since, _ := s.paramMissingSince.Observe(key, now)
					paramTripped = cycles >= s.effMinMissingCycles() && now.Sub(since) >= s.effTripWindow()
				case !paramUnverifiable:
					s.paramMissingSince.Forget(key)
					s.paramMissingStreak.Reset(key)
				}

				switch {
				case celErrActive:
					celErrFaultSeen[key] = true
					since, _ := s.celErrorSince.Observe(key, now)
					celErrTripped = now.Sub(since) >= s.effTripWindow()
				case !kindPromErr:
					s.celErrorSince.Forget(key)
				default:
					celErrFaultSeen[key] = true
				}
			}

			faultActive := paramMissing || celErrActive
			faultTripped := paramTripped || celErrTripped
			faultUnverifiable := paramUnverifiable || kindPromErr

			if !broken {
				s.recoverStreak.Reset(key)
				if !allowTrips || !guardstate.FailClosed(p.FailurePolicy) || !faultTripped {
					continue
				}
				reason := tripReason(paramTripped, celErrTripped)
				tripped, vanished, err := s.tripPolicy(ctx, snap, p, reason, now)
				if err != nil {
					patchErrs = append(patchErrs, err)
					continue
				}
				if vanished {
					delete(liveKeys, key)
					delete(faultSeen, key)
					delete(celErrFaultSeen, key)
					continue
				}
				if tripped {
					s.brokenEmitted.Set(metrics.CELPolicyCircuitBroken, 1, key, p.Kind, p.Name)
				}
				continue
			}

			// Policy currently carries AnnoCircuitBrokenCELPolicy.
			if faultActive || faultUnverifiable {
				s.recoverStreak.Reset(key)
				vanished := false
				if allowTrips && guardstate.FailClosed(p.FailurePolicy) {
					reason := tripReason(paramMissing, celErrActive)
					if reason == "" {
						reason = "fault_reassert"
					}
					var err error
					_, vanished, err = s.tripPolicy(ctx, snap, p, reason, now)
					if err != nil {
						patchErrs = append(patchErrs, err)
					}
				}
				if vanished {
					delete(liveKeys, key)
					delete(faultSeen, key)
					delete(celErrFaultSeen, key)
					continue
				}
				s.brokenEmitted.Set(metrics.CELPolicyCircuitBroken, 1, key, p.Kind, p.Name)
				continue
			}

			// Clean cycle on a previously tripped policy (runs even when
			// CircuitBreakerEnabled() == false — RestoreOnly parity).
			cleanCycles := s.recoverStreak.Hit(key)
			if cleanCycles < s.effRecoverCycles() {
				s.brokenEmitted.Set(metrics.CELPolicyCircuitBroken, 1, key, p.Kind, p.Name)
				continue
			}
			restored, vanished, err := s.restorePolicy(ctx, snap, p, now)
			if err != nil {
				patchErrs = append(patchErrs, err)
				s.brokenEmitted.Set(metrics.CELPolicyCircuitBroken, 1, key, p.Kind, p.Name)
				continue
			}
			if vanished {
				s.recoverStreak.Reset(key)
				delete(liveKeys, key)
				continue
			}
			if !restored {
				s.brokenEmitted.Set(metrics.CELPolicyCircuitBroken, 1, key, p.Kind, p.Name)
				continue
			}
			s.recoverStreak.Reset(key)
			// Omitted from brokenEmitted so Prune deletes the gauge series.
		}
	}

	s.brokenEmitted.Prune(metrics.CELPolicyCircuitBroken.DeleteLabelValues)
	if allKindsReadable {
		s.paramMissingSince.Prune(func(k string) bool { return faultSeen[k] })
		s.paramMissingStreak.Prune(func(k string) bool { return faultSeen[k] })
		s.celErrorSince.Prune(func(k string) bool { return celErrFaultSeen[k] })
		s.recoverStreak.Prune(func(k string) bool { return liveKeys[k] })
	} else if !allowTrips {
		s.paramMissingSince.Prune(func(string) bool { return false })
		s.paramMissingStreak.Prune(func(string) bool { return false })
		s.celErrorSince.Prune(func(string) bool { return false })
	}
	return errors.Join(patchErrs...)
}

func hasAnyBrokenPolicy(censuses []*kindCensus) bool {
	for _, c := range censuses {
		if c.absent || c.skipped {
			continue
		}
		for i := range c.policies {
			if c.policies[i].Annotations[kube.AnnoCircuitBrokenCELPolicy] != "" {
				return true
			}
		}
	}
	return false
}

func (s *Sweeper) carryBrokenKind(kind string) {
	for k, lv := range s.brokenEmitted.Last() {
		if len(lv) >= 1 && lv[0] == kind {
			s.brokenEmitted.Emit(k, lv...)
		}
	}
}

func tripReason(paramFault, celErrFault bool) string {
	switch {
	case paramFault && celErrFault:
		return "missing_param_ref+cel_eval_error"
	case paramFault:
		return "missing_param_ref"
	case celErrFault:
		return "cel_eval_error"
	default:
		return ""
	}
}

func queryCELErrorPolicies(ctx context.Context, g *guardstate.Guard) (map[string]bool, map[string]error) {
	if g == nil || g.PromEndpoint == "" {
		return nil, nil
	}
	out := map[string]bool{}
	errs := map[string]error{}
	queries := []struct {
		kind  string
		query string
	}{
		{kind: KindValidatingPolicy, query: celVAPErrorRateQuery},
		{kind: KindMutatingPolicy, query: celMAPErrorRateQuery},
	}
	for _, q := range queries {
		samples, err := g.PromClient.InstantQuery(ctx, g.PromEndpoint, q.query)
		if err != nil {
			errs[q.kind] = err
			continue
		}
		for _, s := range samples {
			if s.Value <= 0 {
				continue
			}
			if name := s.Label("policy", "name"); name != "" {
				out[q.kind+"/"+name] = true
			}
		}
	}
	return out, errs
}

func checkMissingParamRef(ctx context.Context, g *guardstate.Guard,
	p *policyView, bindings []bindingView) (missing bool, unverifiable bool) {

	if p.ParamKind == nil || len(bindings) == 0 {
		return false, false
	}
	if g.Dyn == nil {
		return false, true
	}
	gv, err := schema.ParseGroupVersion(p.ParamKind.APIVersion)
	if err != nil {
		logf.FromContext(ctx).V(1).Info("invalid paramKind apiVersion",
			"kind", p.Kind, "policy", p.Name, "apiVersion", p.ParamKind.APIVersion, "error", err)
		return false, true
	}
	gvr, _ := meta.UnsafeGuessKindToResource(gv.WithKind(p.ParamKind.Kind))
	log := logf.FromContext(ctx)

	for _, b := range bindings {
		if b.ParamRef == nil {
			continue
		}
		if b.ParamRef.ParameterNotFoundAction != nil &&
			*b.ParamRef.ParameterNotFoundAction == admissionv1.AllowAction {
			continue
		}
		switch {
		case b.ParamRef.Name != "":
			ri := g.Dyn.Resource(gvr)
			if b.ParamRef.Namespace != "" {
				_, err = ri.Namespace(b.ParamRef.Namespace).Get(ctx, b.ParamRef.Name, metav1.GetOptions{})
			} else {
				_, err = ri.Get(ctx, b.ParamRef.Name, metav1.GetOptions{})
			}
			switch {
			case err == nil:
			case apierrors.IsNotFound(err) || kube.IsCRDAbsent(err):
				return true, false
			case apierrors.IsForbidden(err):
				log.V(1).Info("paramRef Get forbidden (403) — skipping",
					"kind", p.Kind, "policy", p.Name, "param", b.ParamRef.Name, "error", err)
				unverifiable = true
			default:
				metrics.IncError(g.Queue)
				log.Error(err, "paramRef Get failed", "kind", p.Kind, "policy", p.Name, "param", b.ParamRef.Name)
				unverifiable = true
			}
		case b.ParamRef.Selector != nil:
			sel := metav1.FormatLabelSelector(b.ParamRef.Selector)
			ri := g.Dyn.Resource(gvr)
			var listErr error
			var count int
			if b.ParamRef.Namespace != "" {
				l, e := ri.Namespace(b.ParamRef.Namespace).List(ctx, metav1.ListOptions{LabelSelector: sel, Limit: 1})
				listErr = e
				if l != nil {
					count = len(l.Items)
				}
			} else {
				l, e := ri.List(ctx, metav1.ListOptions{LabelSelector: sel, Limit: 1})
				listErr = e
				if l != nil {
					count = len(l.Items)
				}
			}
			switch {
			case listErr == nil && count == 0:
				return true, false
			case listErr == nil:
			case kube.IsCRDAbsent(listErr):
				return true, false
			case apierrors.IsForbidden(listErr):
				log.V(1).Info("paramRef List forbidden (403) — skipping",
					"kind", p.Kind, "policy", p.Name, "selector", sel, "error", listErr)
				unverifiable = true
			default:
				metrics.IncError(g.Queue)
				log.Error(listErr, "paramRef List failed", "kind", p.Kind, "policy", p.Name, "selector", sel)
				unverifiable = true
			}
		}
	}
	return false, unverifiable
}

func (s *Sweeper) tripPolicy(ctx context.Context, snap *guardstate.Snapshot,
	p *policyView, reason string, now time.Time) (tripped bool, vanished bool, err error) {

	g := snap.G
	log := logf.FromContext(ctx)
	gateKey := "cel_breaker/" + p.key()
	// Emergency Fail -> Ignore flip bypasses FluxPatchGate (matches
	// circuitbreaker/circuit_sweep.go emergencyPatch).
	proceed, unverifiable := heal.AllowedV(ctx, log, g.Verdict, g.CS, g.Dyn, &s.heals, gateKey, 0, now)
	if unverifiable {
		metrics.IncError(g.Queue)
	}
	if !proceed {
		return false, false, nil
	}

	stamp := strings.TrimSpace(now.UTC().Format(time.RFC3339) + " " + reason)
	payload, err := json.Marshal(map[string]any{
		"metadata": map[string]any{
			"annotations": map[string]any{
				kube.AnnoCircuitBrokenCELPolicy: stamp,
			},
		},
		"spec": map[string]any{
			"failurePolicy": string(admissionv1.Ignore),
		},
	})
	if err != nil {
		heal.RefundGrant(now)
		return false, false, fmt.Errorf("marshal CEL trip patch %s: %w", p.key(), err)
	}

	log.Info("PATCH: circuit-breaking CEL policy to failurePolicy=Ignore",
		"kind", p.Kind, "policy", p.Name, "reason", reason)
	patched, err := p.patchFn(ctx, payload)
	if err != nil {
		switch {
		case apierrors.IsForbidden(err):
			heal.RefundGrant(now)
			log.V(1).Info("WARN: CEL circuit-breaker trip patch forbidden (403) — skipping",
				"kind", p.Kind, "policy", p.Name, "error", err)
			return false, false, nil
		case kube.IsCRDAbsent(err):
			heal.RefundGrant(now)
			log.V(1).Info("WARN: CEL circuit-breaker trip patch target not found (404) — skipping",
				"kind", p.Kind, "policy", p.Name, "error", err)
			return false, true, nil
		default:
			log.Error(err, "CEL circuit-breaker trip patch failed", "kind", p.Kind, "policy", p.Name)
			return false, false, fmt.Errorf("trip CEL policy %s: %w", p.key(), err)
		}
	}
	p.applyPatched(patched)
	metrics.CELPolicyActionsTotal.WithLabelValues(p.Kind, "trip").Inc()
	return true, false, nil
}

func (s *Sweeper) restorePolicy(ctx context.Context, snap *guardstate.Snapshot,
	p *policyView, now time.Time) (restored bool, vanished bool, err error) {

	g := snap.G
	log := logf.FromContext(ctx)
	gateKey := "cel_breaker_restore/" + p.key()
	// Recovery Ignore -> Fail bypasses FluxPatchGate so a Flux loop never
	// strands a healthy policy fail-open.
	proceed, unverifiable := heal.AllowedV(ctx, log, g.Verdict, g.CS, g.Dyn, &s.heals, gateKey, 0, now)
	if unverifiable {
		metrics.IncError(g.Queue)
	}
	if !proceed {
		return false, false, nil
	}

	payload, err := json.Marshal(map[string]any{
		"metadata": map[string]any{
			"annotations": map[string]any{
				kube.AnnoCircuitBrokenCELPolicy: nil,
			},
		},
		"spec": map[string]any{
			"failurePolicy": string(admissionv1.Fail),
		},
	}, json.FormatNilMapAsNull(true))
	if err != nil {
		heal.RefundGrant(now)
		return false, false, fmt.Errorf("marshal CEL restore patch %s: %w", p.key(), err)
	}

	log.Info("PATCH: restoring CEL policy to failurePolicy=Fail",
		"kind", p.Kind, "policy", p.Name)
	patched, err := p.patchFn(ctx, payload)
	if err != nil {
		switch {
		case apierrors.IsForbidden(err):
			heal.RefundGrant(now)
			log.V(1).Info("WARN: CEL circuit-breaker restore patch forbidden (403) — skipping",
				"kind", p.Kind, "policy", p.Name, "error", err)
			return false, false, nil
		case kube.IsCRDAbsent(err):
			heal.RefundGrant(now)
			log.V(1).Info("WARN: CEL circuit-breaker restore patch target not found (404) — skipping",
				"kind", p.Kind, "policy", p.Name, "error", err)
			return false, true, nil
		default:
			log.Error(err, "CEL circuit-breaker restore patch failed", "kind", p.Kind, "policy", p.Name)
			return false, false, fmt.Errorf("restore CEL policy %s: %w", p.key(), err)
		}
	}
	p.applyPatched(patched)
	metrics.CELPolicyActionsTotal.WithLabelValues(p.Kind, "restore").Inc()
	return true, false, nil
}
