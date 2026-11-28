// service_lb_lifecycle_guard.go — health check "service-lb-lifecycle-guard":
// detect-only guard identifying stuck LoadBalancer Services and Ingresses:
//  1. Service(type=LoadBalancer) or Ingress with DeletionTimestamp != nil aged
//     >= 15m inside a NON-terminating Namespace ("terminating_stuck").
//  2. Service(type=LoadBalancer) without DeletionTimestamp and empty
//     status.loadBalancer.ingress aged >= 10m ("pending_lb_ingress").
//
// Emits node_automation_service_lb_lifecycle_stuck{namespace,kind,name,reason}
// and cooldown-deduped Warning Events (ServiceLBLifecycleStuck).
package nethealth

import (
	"cmp"
	"context"
	"fmt"
	"slices"
	"time"

	"github.com/go-logr/logr"
	"github.com/prometheus/client_golang/prometheus"
	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/types"
	logf "sigs.k8s.io/controller-runtime/pkg/log"
	ctrlmetrics "sigs.k8s.io/controller-runtime/pkg/metrics"

	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-automation-controller/internal/platform/kube"
	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-automation-controller/internal/platform/state"
	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-automation-controller/internal/probefw"
)

const (
	// CheckNameServiceLBLifecycleGuard is the registry check name for service-lb-lifecycle-guard.
	CheckNameServiceLBLifecycleGuard = "service-lb-lifecycle-guard"

	svcLBTerminatingMinAge = 15 * time.Minute
	svcLBPendingMinAge     = 10 * time.Minute
	svcLBEventCooldown     = 30 * time.Minute
	svcLBMaxEventsPerSweep = 20
	svcLBEventReason       = "ServiceLBLifecycleStuck"

	svcLBReasonTerminatingStuck = "terminating_stuck"
	svcLBReasonPendingIngress   = "pending_lb_ingress"
)

var serviceLBLifecycleStuckGauge = prometheus.NewGaugeVec(prometheus.GaugeOpts{
	Name: "node_automation_service_lb_lifecycle_stuck",
	Help: "1 while a LoadBalancer Service or Ingress is stuck terminating >=15m in a non-terminating namespace or a LoadBalancer Service lacks ingress >=10m.",
}, []string{"namespace", "kind", "name", "reason"})

func init() {
	ctrlmetrics.Registry.MustRegister(serviceLBLifecycleStuckGauge)
}

type serviceLBLifecycleGuardCheck struct {
	*probefw.Deps

	firstSeen     state.FirstSeenLedger
	emitted       state.GaugeLedger[string]
	eventCooldown state.CooldownSet
}

// NewServiceLBLifecycleGuardCheck constructs the service-lb-lifecycle-guard check.
func NewServiceLBLifecycleGuardCheck(d *probefw.Deps) probefw.Check {
	return &serviceLBLifecycleGuardCheck{Deps: d}
}

type serviceLBFinding struct {
	apiVersion string
	kind       string
	ns         string
	name       string
	uid        types.UID
	reason     string
	detail     string
}

func (c *serviceLBLifecycleGuardCheck) Run(ctx context.Context) probefw.Result {
	log := logf.FromContext(ctx)
	now := c.Now()
	c.eventCooldown.PruneExpired(now, svcLBEventCooldown)

	svcs, err := c.AllServices(ctx)
	if err != nil {
		return probefw.Result{Infra: fmt.Errorf("list services: %w", err)}
	}
	nss, err := c.AllNamespaces(ctx)
	if err != nil {
		return probefw.Result{Infra: fmt.Errorf("list namespaces: %w", err)}
	}

	terminatingNS := make(map[string]bool)
	for i := range nss {
		ns := &nss[i]
		if ns.DeletionTimestamp != nil || ns.Status.Phase == corev1.NamespaceTerminating {
			terminatingNS[ns.Name] = true
		}
	}

	var rep probefw.SweepReport
	var findings []serviceLBFinding
	liveFirstSeen := map[string]bool{}

	for i := range svcs {
		svc := &svcs[i]
		if svc.Spec.Type != corev1.ServiceTypeLoadBalancer {
			continue
		}
		if svc.DeletionTimestamp != nil {
			if !terminatingNS[svc.Namespace] && kube.AgeAtLeast(svc.DeletionTimestamp.Time, now, svcLBTerminatingMinAge) {
				findings = append(findings, serviceLBFinding{
					apiVersion: "v1",
					kind:       "Service",
					ns:         svc.Namespace,
					name:       svc.Name,
					uid:        svc.UID,
					reason:     svcLBReasonTerminatingStuck,
					detail:     fmt.Sprintf("LoadBalancer Service %s/%s stuck terminating >=%s", svc.Namespace, svc.Name, svcLBTerminatingMinAge),
				})
			}
			continue
		}
		if len(svc.Status.LoadBalancer.Ingress) == 0 {
			persisted := false
			if !svc.CreationTimestamp.IsZero() {
				persisted = kube.AgeAtLeast(svc.CreationTimestamp.Time, now, svcLBPendingMinAge)
			} else {
				fsKey := "svc/" + svc.Namespace + "/" + svc.Name + "/" + string(svc.UID)
				liveFirstSeen[fsKey] = true
				persisted = probefw.Persisted(&c.firstSeen, fsKey, now, svcLBPendingMinAge, log)
			}
			if persisted {
				findings = append(findings, serviceLBFinding{
					apiVersion: "v1",
					kind:       "Service",
					ns:         svc.Namespace,
					name:       svc.Name,
					uid:        svc.UID,
					reason:     svcLBReasonPendingIngress,
					detail:     fmt.Sprintf("LoadBalancer Service %s/%s has empty status.loadBalancer.ingress >=%s", svc.Namespace, svc.Name, svcLBPendingMinAge),
				})
			}
		}
	}

	ings, ingErr := c.AllIngresses(ctx)
	switch {
	case ingErr == nil:
		for i := range ings {
			ing := &ings[i]
			if ing.DeletionTimestamp == nil || terminatingNS[ing.Namespace] {
				continue
			}
			if kube.AgeAtLeast(ing.DeletionTimestamp.Time, now, svcLBTerminatingMinAge) {
				findings = append(findings, serviceLBFinding{
					apiVersion: "networking.k8s.io/v1",
					kind:       "Ingress",
					ns:         ing.Namespace,
					name:       ing.Name,
					uid:        ing.UID,
					reason:     svcLBReasonTerminatingStuck,
					detail:     fmt.Sprintf("Ingress %s/%s stuck terminating >=%s", ing.Namespace, ing.Name, svcLBTerminatingMinAge),
				})
			}
		}
	case apierrors.IsForbidden(ingErr) || kube.IsCRDAbsent(ingErr):
		log.V(1).Info("Ingress list skipped", "error", ingErr)
	default:
		return probefw.Result{Infra: fmt.Errorf("list ingresses: %w", ingErr)}
	}

	c.firstSeen.Prune(func(k string) bool { return liveFirstSeen[k] })

	slices.SortFunc(findings, func(a, b serviceLBFinding) int {
		if x := cmp.Compare(a.ns, b.ns); x != 0 {
			return x
		}
		if x := cmp.Compare(a.kind, b.kind); x != 0 {
			return x
		}
		if x := cmp.Compare(a.name, b.name); x != 0 {
			return x
		}
		return cmp.Compare(a.reason, b.reason)
	})

	for _, f := range findings {
		tupleKey := f.ns + "/" + f.kind + "/" + f.name + "/" + f.reason
		rep.Emit(serviceLBLifecycleStuckGauge, tupleKey,
			[]string{f.ns, f.kind, f.name, f.reason},
			fmt.Sprintf("%s/%s/%s (%s)", f.ns, f.kind, f.name, f.reason))
	}

	c.emitEvents(ctx, log, now, findings)

	return rep.Result(&c.emitted, serviceLBLifecycleStuckGauge.DeleteLabelValues,
		"service/ingress lb lifecycle stuck: ", ", ")
}

func (c *serviceLBLifecycleGuardCheck) emitEvents(ctx context.Context, log logr.Logger, now time.Time, findings []serviceLBFinding) {
	emitted := 0
	for _, f := range findings {
		if emitted >= svcLBMaxEventsPerSweep {
			log.Info("SKIP rest: service-lb-lifecycle-guard event cap reached",
				"cap", svcLBMaxEventsPerSweep)
			break
		}
		cooldownKey := "svclb." + f.ns + "." + f.kind + "." + f.name + "." + f.reason
		if probefw.EmitWarningDeduped(ctx, c.CS, log, &c.eventCooldown, cooldownKey, svcLBEventCooldown, now, kube.WarningEvent{
			Namespace: f.ns,
			Regarding: corev1.ObjectReference{
				APIVersion: f.apiVersion,
				Kind:       f.kind,
				Namespace:  f.ns,
				Name:       f.name,
				UID:        f.uid,
			},
			Reason:            svcLBEventReason,
			Note:              f.detail,
			ReportingInstance: cmp.Or(c.Name, CheckNameServiceLBLifecycleGuard),
		}) {
			emitted++
		}
	}
}
