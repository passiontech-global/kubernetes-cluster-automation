// workload_admission_block_guard.go — health check "workload-admission-block-guard" (#73):
// audit-only guard detecting workloads silently blocked at Pod creation by
// admission controls (ResourceQuota, LimitRange, PodSecurity, Admission Webhooks):
//   - ReplicaSet with ReplicaFailure=True
//   - StatefulSet with currentReplicas < desiredReplicas + recent FailedCreate Event (<=15m)
//   - DaemonSet with currentNumberScheduled < desiredNumberScheduled + recent FailedCreate Event (<=15m)
//
// Sustained >= 5m emits node_automation_workload_admission_blocked{namespace,kind,name,reason}
// and a deduped Warning Event (WorkloadAdmissionBlocked).
package watchdogs

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	logf "sigs.k8s.io/controller-runtime/pkg/log"
	ctrlmetrics "sigs.k8s.io/controller-runtime/pkg/metrics"

	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-automation-controller/internal/platform/kube"
	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-automation-controller/internal/platform/state"
	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-automation-controller/internal/probefw"
)

const (
	// CheckNameWorkloadAdmissionBlockGuard is the registry check name for #8/#73.
	CheckNameWorkloadAdmissionBlockGuard = "workload-admission-block-guard"

	admissionBlockMinAge        = 5 * time.Minute
	admissionBlockEventMaxAge   = 15 * time.Minute
	admissionBlockEventCooldown = 30 * time.Minute
	admissionBlockEventReason   = "WorkloadAdmissionBlocked"

	admissionReasonQuotaExceeded       = "quota_exceeded"
	admissionReasonLimitRangeViolation = "limitrange_violation"
	admissionReasonPodSecurityDenied   = "podsecurity_denied"
	admissionReasonWebhookRejected     = "webhook_rejected"
	admissionReasonOther               = "other_admission_error"
)

var (
	workloadAdmissionBlockedGauge = prometheus.NewGaugeVec(prometheus.GaugeOpts{
		Name: "node_automation_workload_admission_blocked",
		Help: "1 while a ReplicaSet, StatefulSet, or DaemonSet is blocked from creating Pods by admission errors past 5m.",
	}, []string{"namespace", "kind", "name", "reason"})
)

func init() {
	ctrlmetrics.Registry.MustRegister(workloadAdmissionBlockedGauge)
}

type workloadAdmissionBlockGuardCheck struct {
	*probefw.Deps

	firstSeen     state.FirstSeenLedger
	emitted       state.GaugeLedger[string]
	eventCooldown state.CooldownSet
}

// NewWorkloadAdmissionBlockGuardCheck builds the workload-admission-block-guard check.
func NewWorkloadAdmissionBlockGuardCheck(d *probefw.Deps) probefw.Check {
	return &workloadAdmissionBlockGuardCheck{Deps: d}
}

type admissionBlockCandidate struct {
	kind    string
	ns      string
	name    string
	uid     types.UID
	condMsg string
	since   time.Time
	require bool // true for ReplicaSet (ReplicaFailure=True already proves creation failure)
}

type failedCreateInfo struct {
	latest   corev1.Event
	earliest time.Time
}

func eventStartTime(e *corev1.Event) time.Time {
	if !e.FirstTimestamp.IsZero() {
		return e.FirstTimestamp.Time
	}
	if !e.EventTime.IsZero() {
		return e.EventTime.Time
	}
	if !e.LastTimestamp.IsZero() {
		return e.LastTimestamp.Time
	}
	return e.CreationTimestamp.Time
}

func (c *workloadAdmissionBlockGuardCheck) Run(ctx context.Context) probefw.Result {
	log := logf.FromContext(ctx)
	now := c.Now()
	c.eventCooldown.PruneExpired(now, admissionBlockEventCooldown)

	holdKinds := map[string]bool{}

	// Full typed ReplicaSet list (AllReplicaSets is PartialObjectMetadata-only).
	rss, err := kube.ListAll(ctx,
		metav1.ListOptions{Limit: kube.DefaultListPageSize},
		kube.ReplicaSets(c.CS, metav1.NamespaceAll))
	if err != nil {
		if apierrors.IsForbidden(err) {
			log.V(1).Info("WARN: ReplicaSet list skipped (403)", "error", err)
			holdKinds["ReplicaSet"] = true
			rss = nil
		} else {
			return probefw.Result{Infra: fmt.Errorf("list replicasets: %w", err)}
		}
	}
	stss, err := c.AllStatefulSets(ctx)
	if err != nil {
		if apierrors.IsForbidden(err) {
			log.V(1).Info("WARN: StatefulSet list skipped (403)", "error", err)
			holdKinds["StatefulSet"] = true
			stss = nil
		} else {
			return probefw.Result{Infra: fmt.Errorf("list statefulsets: %w", err)}
		}
	}
	dss, err := c.AllDaemonSets(ctx)
	if err != nil {
		if apierrors.IsForbidden(err) {
			log.V(1).Info("WARN: DaemonSet list skipped (403)", "error", err)
			holdKinds["DaemonSet"] = true
			dss = nil
		} else {
			return probefw.Result{Infra: fmt.Errorf("list daemonsets: %w", err)}
		}
	}

	var candidates []admissionBlockCandidate

	for i := range rss {
		rs := &rss[i]
		if rs.DeletionTimestamp != nil {
			continue
		}
		desired := int32(1)
		if rs.Spec.Replicas != nil {
			desired = *rs.Spec.Replicas
		}
		if desired <= 0 || kube.IsIntentionallyDownscaled(kube.EffectiveAnnos(ctx, rs), rs.Spec.Replicas) {
			continue
		}
		for _, cond := range rs.Status.Conditions {
			if cond.Type == appsv1.ReplicaSetReplicaFailure && cond.Status == corev1.ConditionTrue {
				candidates = append(candidates, admissionBlockCandidate{
					kind:    "ReplicaSet",
					ns:      rs.Namespace,
					name:    rs.Name,
					uid:     rs.UID,
					condMsg: cond.Message,
					since:   cond.LastTransitionTime.Time,
					require: true,
				})
				break
			}
		}
	}

	for i := range stss {
		sts := &stss[i]
		if sts.DeletionTimestamp != nil {
			continue
		}
		desired := int32(1)
		if sts.Spec.Replicas != nil {
			desired = *sts.Spec.Replicas
		}
		if desired <= 0 || kube.IsIntentionallyDownscaled(kube.EffectiveAnnos(ctx, sts), sts.Spec.Replicas) {
			continue
		}
		if sts.Status.CurrentReplicas < desired {
			var condMsg string
			var since time.Time
			for _, cond := range sts.Status.Conditions {
				if cond.Type == "ReplicaFailure" && cond.Status == corev1.ConditionTrue {
					condMsg = cond.Message
					since = cond.LastTransitionTime.Time
					break
				}
			}
			candidates = append(candidates, admissionBlockCandidate{
				kind:    "StatefulSet",
				ns:      sts.Namespace,
				name:    sts.Name,
				uid:     sts.UID,
				condMsg: condMsg,
				since:   since,
			})
		}
	}

	for i := range dss {
		ds := &dss[i]
		if ds.DeletionTimestamp != nil {
			continue
		}
		desired := ds.Status.DesiredNumberScheduled
		if desired <= 0 || kube.IsIntentionallyDownscaled(kube.EffectiveAnnos(ctx, ds), &desired) {
			continue
		}
		if ds.Status.CurrentNumberScheduled < desired {
			var condMsg string
			var since time.Time
			for _, cond := range ds.Status.Conditions {
				if cond.Type == "ReplicaFailure" && cond.Status == corev1.ConditionTrue {
					condMsg = cond.Message
					since = cond.LastTransitionTime.Time
					break
				}
			}
			candidates = append(candidates, admissionBlockCandidate{
				kind:    "DaemonSet",
				ns:      ds.Namespace,
				name:    ds.Name,
				uid:     ds.UID,
				condMsg: condMsg,
				since:   since,
			})
		}
	}

	var failedCreateByObj map[string]failedCreateInfo
	eventsBlocked := false
	if len(candidates) > 0 {
		evs, err := c.EventsWithReason(ctx, "FailedCreate")
		if err != nil {
			if apierrors.IsForbidden(err) {
				log.V(1).Info("WARN: FailedCreate event list skipped (403)", "error", err)
				eventsBlocked = true
				holdKinds["StatefulSet"] = true
				holdKinds["DaemonSet"] = true
			} else {
				return probefw.Result{Infra: fmt.Errorf("list FailedCreate events: %w", err)}
			}
		} else {
			failedCreateByObj = make(map[string]failedCreateInfo)
			for i := range evs {
				ev := &evs[i]
				evTime := kube.EventTime(ev)
				d := now.Sub(evTime)
				if d < 0 || d > admissionBlockEventMaxAge {
					continue
				}
				ns := ev.InvolvedObject.Namespace
				if ns == "" {
					ns = ev.Namespace
				}
				key := ev.InvolvedObject.Kind + "/" + ns + "/" + ev.InvolvedObject.Name
				start := eventStartTime(ev)
				info, exists := failedCreateByObj[key]
				if !exists || evTime.After(kube.EventTime(&info.latest)) {
					info.latest = *ev
				}
				if !start.IsZero() && (info.earliest.IsZero() || start.Before(info.earliest)) {
					info.earliest = start
				}
				failedCreateByObj[key] = info
			}
		}
	}

	var rep probefw.SweepReport
	liveKeys := map[string]bool{}

	for _, cand := range candidates {
		if !cand.require && eventsBlocked {
			continue
		}
		workloadKey := cand.kind + "/" + cand.ns + "/" + cand.name
		evInfo, hasEv := failedCreateByObj[workloadKey]
		if !cand.require && !hasEv {
			continue
		}

		msg := cand.condMsg
		if hasEv && evInfo.latest.Message != "" {
			if msg != "" {
				msg += " " + evInfo.latest.Message
			} else {
				msg = evInfo.latest.Message
			}
		}
		reason := classifyAdmissionBlockReason(msg)

		since := cand.since
		if since.IsZero() && hasEv {
			since = evInfo.earliest
		}
		persisted := false
		if !since.IsZero() {
			persisted = now.Sub(since) >= admissionBlockMinAge
		} else {
			liveKeys[workloadKey] = true
			persisted = probefw.Persisted(&c.firstSeen, workloadKey, now, admissionBlockMinAge, log)
		}
		if !persisted {
			continue
		}

		rep.Flag(workloadAdmissionBlockedGauge, workloadKey+"/"+reason, []string{cand.ns, cand.kind, cand.name, reason})
		rep.Find(fmt.Sprintf("%s (%s)", workloadKey, reason))

		cooldownKey := "admblock." + cand.kind + "." + cand.ns + "." + cand.name + "." + reason
		if !c.eventCooldown.CooledDown(cooldownKey, admissionBlockEventCooldown, now) {
			note := fmt.Sprintf("%s %s/%s blocked from pod creation (%s): %s",
				cand.kind, cand.ns, cand.name, reason, msg)
			if err := kube.EmitWarningEvent(ctx, c.CS, kube.WarningEvent{
				Name:      fmt.Sprintf("%s.%x", sanitizeEventNamePrefix(cooldownKey), now.UnixNano()),
				Namespace: cand.ns,
				Regarding: corev1.ObjectReference{
					APIVersion: "apps/v1",
					Kind:       cand.kind,
					Namespace:  cand.ns,
					Name:       cand.name,
					UID:        cand.uid,
				},
				Reason:            admissionBlockEventReason,
				Note:              note,
				ReportingInstance: c.Name,
				Now:               now,
			}); err != nil {
				log.Info("WARN: WorkloadAdmissionBlocked event create failed (RBAC?)",
					"workload", workloadKey, "error", err)
			} else {
				c.eventCooldown.Stamp(cooldownKey, now)
				log.Info("EVENT: WorkloadAdmissionBlocked", "workload", workloadKey, "reason", reason)
			}
		}
	}

	for kind := range holdKinds {
		carryAdmissionBlockByKind(&rep, &c.emitted, kind)
	}

	c.firstSeen.Prune(func(k string) bool {
		if liveKeys[k] {
			return true
		}
		kind, _, _ := strings.Cut(k, "/")
		return holdKinds[kind]
	})
	return rep.Result(&c.emitted, workloadAdmissionBlockedGauge.DeleteLabelValues,
		"workload admission blocked: ", ", ")
}

func carryAdmissionBlockByKind(rep *probefw.SweepReport, ledger *state.GaugeLedger[string], kind string) {
	for k, lv := range ledger.Last() {
		if len(lv) >= 2 && lv[1] == kind {
			rep.Carry(k, lv)
		}
	}
}

func classifyAdmissionBlockReason(msg string) string {
	lower := strings.ToLower(msg)
	switch {
	case strings.Contains(lower, "podsecurity") ||
		strings.Contains(lower, "violates podsecurity") ||
		strings.Contains(lower, "pod security"):
		return admissionReasonPodSecurityDenied
	case strings.Contains(lower, "exceeded quota") ||
		strings.Contains(lower, "resourcequota"):
		return admissionReasonQuotaExceeded
	case strings.Contains(lower, "limitrange") ||
		strings.Contains(lower, "minimum cpu") ||
		strings.Contains(lower, "maximum cpu") ||
		strings.Contains(lower, "minimum memory") ||
		strings.Contains(lower, "maximum memory"):
		return admissionReasonLimitRangeViolation
	case strings.Contains(lower, "admission webhook") ||
		strings.Contains(lower, "validatingadmissionpolicy") ||
		strings.Contains(lower, "mutatingadmissionpolicy") ||
		strings.Contains(lower, "denied the request"):
		return admissionReasonWebhookRejected
	default:
		return admissionReasonOther
	}
}
