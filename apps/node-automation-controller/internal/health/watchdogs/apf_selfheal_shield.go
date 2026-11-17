// apf_selfheal_shield.go — the apf-selfheal-shield check: keeps the
// APF (API Priority and Fairness) shield for the self-healing control
// plane converged. During an apiserver overload event the self-heal
// traffic — node-host-agent latch reports, this controller's
// cordon/drain/evict sweeps, CoreDNS reloads — is exactly the traffic
// that must keep flowing, yet the stock FlowSchemas park
// kube-system ServiceAccounts under workload-* priority levels whose
// queues saturate first. This check ensures two cluster-scoped
// objects exist with the pinned spec:
//
//   - PriorityLevelConfiguration/selfheal-critical — a Limited level
//     with nominalConcurrencyShares 40 and lendablePercent 50: it
//     lends half its share to the cluster when idle and reclaims it
//     the instant an API storm hits.
//   - FlowSchema/selfheal-controllers — matchingPrecedence 500 (ahead
//     of every workload-* schema at 1000..9000) matching the
//     node-automation-controller, node-host-agent and coredns
//     ServiceAccounts plus NODE_AUTOMATION_APF_SHIELD_EXTRA_SAS.
//
// Drift is repaired in place (spec replace on the fetched object) and
// every write passes heal.FluxPatchGate — a Git source pinning these
// objects would otherwise ping-pong the check every sweep. A missing
// RBAC grant (403) degrades to the node_automation_apf_shield_degraded
// gauge + WARN instead of failing the sweep: the shield is protection,
// not a workload, and an ungrantable cluster must still report.
package watchdogs

import (
	"context"
	"strings"
	"time"

	"github.com/go-logr/logr"
	"github.com/prometheus/client_golang/prometheus"
	flowcontrolv1 "k8s.io/api/flowcontrol/v1"
	apiequality "k8s.io/apimachinery/pkg/api/equality"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/utils/ptr"
	logf "sigs.k8s.io/controller-runtime/pkg/log"
	ctrlmetrics "sigs.k8s.io/controller-runtime/pkg/metrics"

	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-automation-controller/internal/platform/heal"
	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-automation-controller/internal/probefw"
	"github.com/passiontech-global/kubernetes-cluster-automation/libs/hostkit/envx"
)

const (
	// CheckNameAPFSelfHealShield is the kuberhealthy_check label and
	// the check's registry Name.
	CheckNameAPFSelfHealShield = "apf-selfheal-shield"

	// apfShieldPLCName / apfShieldFlowSchemaName are the pinned object
	// names — ops contract, referenced by kubectl runbooks.
	apfShieldPLCName        = "selfheal-critical"
	apfShieldFlowSchemaName = "selfheal-controllers"

	// apfShieldMatchingPrecedence sits ahead of every stock
	// workload-* FlowSchema (1000..9000) so the self-heal SAs win the
	// priority contest during an API storm.
	apfShieldMatchingPrecedence int32 = 500

	// apfShieldControllerSA is the controller's own ServiceAccount
	// name; its namespace comes from the shield namespace knob.
	apfShieldControllerSA = "node-automation-controller"
)

// apfShieldConfig is the check's env-resolved knob set — read ONCE
// at construction (the New func runs inside Setup, never inside a
// sweep).
type apfShieldConfig struct {
	// enforce gates the create/update writes; false leaves the check
	// report-only (degraded gauge + FAIL still fire on drift).
	enforce bool
	// namespace is the namespace of the node-automation-controller
	// ServiceAccount subject (NODE_AUTOMATION_APF_SHIELD_NAMESPACE,
	// default "node-ops").
	namespace string
	// extraSAs are additional "namespace/name" ServiceAccount
	// subjects appended to the FlowSchema rule.
	extraSAs []apfShieldSA
}

// apfShieldSA is one ServiceAccount subject (namespace + name).
type apfShieldSA struct {
	namespace, name string
}

// apfSelfHealShieldCheck ensures the APF shield objects exist and
// match the pinned spec.
type apfSelfHealShieldCheck struct {
	*probefw.Deps
	cfg apfShieldConfig
}

// NewAPFSelfHealShieldCheck builds the apf-selfheal-shield check.
func NewAPFSelfHealShieldCheck(d *probefw.Deps) probefw.Check {
	return &apfSelfHealShieldCheck{Deps: d, cfg: apfShieldConfigFromEnv()}
}

// apfShieldConfigFromEnv resolves the NODE_AUTOMATION_APF_SHIELD_*
// knobs. Malformed EXTRA_SAS entries warn and are skipped — a typo
// must not take the shield down.
func apfShieldConfigFromEnv() apfShieldConfig {
	cfg := apfShieldConfig{
		enforce:   envx.Gate("NODE_AUTOMATION_APF_SHIELD_ENFORCE", true),
		namespace: envx.Getenv("NODE_AUTOMATION_APF_SHIELD_NAMESPACE", "node-ops"),
	}
	for _, entry := range envx.List("NODE_AUTOMATION_APF_SHIELD_EXTRA_SAS") {
		ns, name, ok := strings.Cut(entry, "/")
		if !ok || ns == "" || name == "" {
			envx.Warnf("NODE_AUTOMATION_APF_SHIELD_EXTRA_SAS entry is not namespace/name — skipped",
				"value", entry)
			continue
		}
		cfg.extraSAs = append(cfg.extraSAs, apfShieldSA{namespace: ns, name: name})
	}
	return cfg
}

var (
	// node_automation_apf_shield_degraded — 1 while the
	// selfheal-critical PLC or selfheal-controllers FlowSchema is
	// missing, spec-drifted, or unwritable (RBAC 403); 0 when both
	// objects match the pinned spec.
	apfShieldDegraded = prometheus.NewGauge(prometheus.GaugeOpts{
		Name: "node_automation_apf_shield_degraded",
		Help: "1 while the apf-selfheal-shield PriorityLevelConfiguration/FlowSchema is missing, drifted, or unwritable — apf-selfheal-shield.",
	})
)

func init() {
	ctrlmetrics.Registry.MustRegister(apfShieldDegraded)
}

// apfShieldPLCDesired is the pinned PriorityLevelConfiguration spec:
// Limited, 40 nominal shares, 50% lendable — idle capacity flows to
// the cluster, reclaimed instantly under API pressure.
func (c apfShieldConfig) plcDesired() *flowcontrolv1.PriorityLevelConfiguration {
	return &flowcontrolv1.PriorityLevelConfiguration{
		ObjectMeta: metav1.ObjectMeta{Name: apfShieldPLCName},
		Spec: flowcontrolv1.PriorityLevelConfigurationSpec{
			Type: flowcontrolv1.PriorityLevelEnablementLimited,
			Limited: &flowcontrolv1.LimitedPriorityLevelConfiguration{
				NominalConcurrencyShares: ptr.To(int32(40)),
				LendablePercent:          ptr.To(int32(50)),
				LimitResponse: flowcontrolv1.LimitResponse{
					Type: flowcontrolv1.LimitResponseTypeQueue,
					Queuing: &flowcontrolv1.QueuingConfiguration{
						Queues:           64,
						HandSize:         6,
						QueueLengthLimit: 50,
					},
				},
			},
		},
	}
}

// apfShieldFlowSchemaDesired is the pinned FlowSchema spec: precedence
// 500 ahead of workload-*, ByUser distinguisher so each shielded SA
// gets its own flow, and resource rules covering both namespaced
// (all namespaces) and cluster-scoped requests — self-heal touches
// nodes, leases and cluster-scoped config alike.
func (c apfShieldConfig) flowSchemaDesired() *flowcontrolv1.FlowSchema {
	subjects := []flowcontrolv1.Subject{
		apfShieldSubject(c.namespace, "node-ops-operator"),
		apfShieldSubject(c.namespace, apfShieldControllerSA),
		apfShieldSubject(c.namespace, "node-host-agent"),
		apfShieldSubject("kube-system", "node-host-agent"),
		apfShieldSubject("kube-system", "coredns"),
	}
	for _, sa := range c.extraSAs {
		subjects = append(subjects, apfShieldSubject(sa.namespace, sa.name))
	}
	return &flowcontrolv1.FlowSchema{
		ObjectMeta: metav1.ObjectMeta{Name: apfShieldFlowSchemaName},
		Spec: flowcontrolv1.FlowSchemaSpec{
			MatchingPrecedence: apfShieldMatchingPrecedence,
			PriorityLevelConfiguration: flowcontrolv1.PriorityLevelConfigurationReference{
				Name: apfShieldPLCName,
			},
			DistinguisherMethod: &flowcontrolv1.FlowDistinguisherMethod{
				Type: flowcontrolv1.FlowDistinguisherMethodByUserType,
			},
			Rules: []flowcontrolv1.PolicyRulesWithSubjects{{
				Subjects: subjects,
				ResourceRules: []flowcontrolv1.ResourcePolicyRule{
					{
						APIGroups:  []string{"*"},
						Resources:  []string{"*"},
						Verbs:      []string{"*"},
						Namespaces: []string{"*"},
					},
					{
						APIGroups:    []string{"*"},
						Resources:    []string{"*"},
						Verbs:        []string{"*"},
						ClusterScope: true,
					},
				},
			}},
		},
	}
}

// apfShieldSubject builds one ServiceAccount FlowSchema subject.
func apfShieldSubject(namespace, name string) flowcontrolv1.Subject {
	return flowcontrolv1.Subject{
		Kind: flowcontrolv1.SubjectKindServiceAccount,
		ServiceAccount: &flowcontrolv1.ServiceAccountSubject{
			Namespace: namespace,
			Name:      name,
		},
	}
}

// Run reconciles both shield objects and reports convergence as
// OBSERVED at read time: an object that was missing or drifted this
// sweep counts degraded even when the heal write landed — the next
// sweep's clean read is what flips the gauge back to 0. Every
// failure mode — read error, write error, RBAC-403 — degrades to
// the gauge + FAIL reason rather than Infra: the shield is
// protection, not a workload, and an ungrantable or briefly-
// unreachable apiserver must not take the whole sweep down with it.
func (p *apfSelfHealShieldCheck) Run(ctx context.Context) probefw.Result {
	log := logf.FromContext(ctx)
	now := p.Now()
	var rep probefw.SweepReport
	degraded := false

	plc := p.cfg.plcDesired()
	if why, forbidden := p.reconcilePLC(ctx, log, now, plc); why != "" {
		degraded = true
		if !forbidden {
			rep.Find("prioritylevelconfiguration/" + apfShieldPLCName + ": " + why)
		}
	}
	fs := p.cfg.flowSchemaDesired()
	if why, forbidden := p.reconcileFlowSchema(ctx, log, now, fs); why != "" {
		degraded = true
		if !forbidden {
			rep.Find("flowschema/" + apfShieldFlowSchemaName + ": " + why)
		}
	}

	if degraded {
		apfShieldDegraded.Set(1)
	} else {
		apfShieldDegraded.Set(0)
	}
	return rep.Verdict("apf shield degraded: ", "; ")
}

// reconcilePLC ensures selfheal-critical exists with the pinned
// spec. Returns ("", false) when converged; forbidden=true marks RBAC 403
// where the check warns and sets degraded=1 without failing the sweep.
func (p *apfSelfHealShieldCheck) reconcilePLC(ctx context.Context,
	log logr.Logger, now time.Time,
	want *flowcontrolv1.PriorityLevelConfiguration) (string, bool) {

	plcs := p.CS.FlowcontrolV1().PriorityLevelConfigurations()
	existing, err := plcs.Get(ctx, apfShieldPLCName, metav1.GetOptions{})
	switch {
	case apierrors.IsNotFound(err):
		if !p.cfg.enforce {
			return "missing (enforce off)", false
		}
		if _, err := plcs.Create(ctx, want, metav1.CreateOptions{}); err != nil {
			return p.writeFailure(log, "create prioritylevelconfiguration", err)
		}
		log.Info("ACTION: created PriorityLevelConfiguration",
			"name", apfShieldPLCName)
		return "was missing — created", false
	case apierrors.IsForbidden(err):
		log.Info("WARN: apf shield read forbidden — grant RBAC for prioritylevelconfigurations",
			"error", err)
		return "read forbidden (RBAC)", true
	case err != nil:
		return "get failed: " + err.Error(), false
	}
	if apiequality.Semantic.DeepEqual(existing.Spec, want.Spec) {
		return "", false
	}
	if !p.cfg.enforce {
		return "spec drifted (enforce off)", false
	}
	if !heal.FluxPatchGate("prioritylevelconfiguration", existing,
		"prioritylevelconfiguration/"+apfShieldPLCName, now) {
		return "spec drifted — Flux owns the object (heal-revert loop)", false
	}
	existing.Spec = want.Spec
	if _, err := plcs.Update(ctx, existing, metav1.UpdateOptions{}); err != nil {
		return p.writeFailure(log, "update prioritylevelconfiguration", err)
	}
	log.Info("ACTION: repaired PriorityLevelConfiguration spec drift",
		"name", apfShieldPLCName)
	return "spec drifted — repaired", false
}

// reconcileFlowSchema ensures selfheal-controllers exists with the
// pinned spec — same converge contract as reconcilePLC.
func (p *apfSelfHealShieldCheck) reconcileFlowSchema(ctx context.Context,
	log logr.Logger, now time.Time,
	want *flowcontrolv1.FlowSchema) (string, bool) {

	fss := p.CS.FlowcontrolV1().FlowSchemas()
	existing, err := fss.Get(ctx, apfShieldFlowSchemaName, metav1.GetOptions{})
	switch {
	case apierrors.IsNotFound(err):
		if !p.cfg.enforce {
			return "missing (enforce off)", false
		}
		if _, err := fss.Create(ctx, want, metav1.CreateOptions{}); err != nil {
			return p.writeFailure(log, "create flowschema", err)
		}
		log.Info("ACTION: created FlowSchema",
			"name", apfShieldFlowSchemaName)
		return "was missing — created", false
	case apierrors.IsForbidden(err):
		log.Info("WARN: apf shield read forbidden — grant RBAC for flowschemas",
			"error", err)
		return "read forbidden (RBAC)", true
	case err != nil:
		return "get failed: " + err.Error(), false
	}
	if apiequality.Semantic.DeepEqual(existing.Spec, want.Spec) {
		return "", false
	}
	if !p.cfg.enforce {
		return "spec drifted (enforce off)", false
	}
	if !heal.FluxPatchGate("flowschema", existing,
		"flowschema/"+apfShieldFlowSchemaName, now) {
		return "spec drifted — Flux owns the object (heal-revert loop)", false
	}
	existing.Spec = want.Spec
	if _, err := fss.Update(ctx, existing, metav1.UpdateOptions{}); err != nil {
		return p.writeFailure(log, "update flowschema", err)
	}
	log.Info("ACTION: repaired FlowSchema spec drift",
		"name", apfShieldFlowSchemaName)
	return "spec drifted — repaired", false
}

// writeFailure renders a create/update error as the degraded reason:
// RBAC-403 gets forbidden=true so the cluster does not alert FAIL for
// an ungranted optional protection shield.
func (p *apfSelfHealShieldCheck) writeFailure(log logr.Logger,
	op string, err error) (string, bool) {

	if apierrors.IsForbidden(err) {
		log.Info("WARN: apf shield write forbidden — grant RBAC for "+
			"prioritylevelconfigurations/flowschemas "+op, "error", err)
		return "write forbidden (RBAC)", true
	}
	return op + " failed: " + err.Error(), false
}
