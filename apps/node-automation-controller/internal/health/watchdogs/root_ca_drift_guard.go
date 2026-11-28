// root_ca_drift_guard.go — health check "root-ca-drift-guard":
// detect-only guard verifying every Active (non-Terminating) namespace carries
// a kube-root-ca.crt ConfigMap whose trimmed data["ca.crt"] SHA-256 matches
// kube-system/kube-root-ca.crt.
//
// Lists all kube-root-ca.crt ConfigMaps cluster-wide in one paged call using
// FieldSelector "metadata.name=kube-root-ca.crt", skipping missing ConfigMaps in
// newly created namespaces (< 2m old) to avoid false positives during namespace
// provisioning races.
package watchdogs

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/go-logr/logr"
	"github.com/prometheus/client_golang/prometheus"
	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	logf "sigs.k8s.io/controller-runtime/pkg/log"
	ctrlmetrics "sigs.k8s.io/controller-runtime/pkg/metrics"

	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-automation-controller/internal/platform/kube"
	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-automation-controller/internal/platform/state"
	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-automation-controller/internal/probefw"
)

const (
	// CheckNameRootCADriftGuard is the registry check name for root-ca-drift-guard.
	CheckNameRootCADriftGuard = "root-ca-drift-guard"

	rootCAConfigMapName  = "kube-root-ca.crt"
	rootCAReferenceNS    = "kube-system"
	rootCAMissingMinAge  = 2 * time.Minute
	rootCAEventReason    = "RootCADrift"
	rootCAEventCooldown  = 30 * time.Minute
	rootCAMaxEventsSweep = 10
	rootCAReasonMissing  = "missing"
	rootCAReasonEmpty    = "empty"
	rootCAReasonMismatch = "hash_mismatch"
)

var rootCADriftGauge = prometheus.NewGaugeVec(prometheus.GaugeOpts{
	Name: "node_automation_root_ca_drift",
	Help: "1 while an active namespace has a missing, empty, or SHA-256-mismatched kube-root-ca.crt ConfigMap.",
}, []string{"namespace", "reason"})

func init() {
	ctrlmetrics.Registry.MustRegister(rootCADriftGauge)
}

type rootCADriftCheck struct {
	*probefw.Deps

	driftSeen     state.FirstSeenLedger
	emitted       state.GaugeLedger[string]
	eventCooldown state.CooldownSet
}

// NewRootCADriftGuardCheck constructs the root-ca-drift-guard check.
func NewRootCADriftGuardCheck(d *probefw.Deps) probefw.Check {
	return &rootCADriftCheck{Deps: d}
}

func (c *rootCADriftCheck) Run(ctx context.Context) probefw.Result {
	log := logf.FromContext(ctx)
	now := c.Now()
	c.eventCooldown.PruneExpired(now, rootCAEventCooldown)

	var rep probefw.SweepReport

	refCM, err := c.CS.CoreV1().ConfigMaps(rootCAReferenceNS).Get(ctx, rootCAConfigMapName, metav1.GetOptions{})
	if err != nil {
		if apierrors.IsNotFound(err) {
			log.V(1).Info("kube-system/kube-root-ca.crt absent — root CA drift check skipped")
			return rep.Result(&c.emitted, rootCADriftGauge.DeleteLabelValues,
				"kube-root-ca.crt drift: ", ", ")
		}
		if apierrors.IsForbidden(err) {
			log.V(1).Info("kube-system/kube-root-ca.crt unreadable (403) — carrying held state", "error", err)
			for k, lv := range c.emitted.Last() {
				rep.Carry(k, lv)
			}
			return rep.Result(&c.emitted, rootCADriftGauge.DeleteLabelValues,
				"kube-root-ca.crt drift: ", ", ")
		}
		return rootCACarryOnErr(&c.emitted, fmt.Errorf("get %s/%s: %w", rootCAReferenceNS, rootCAConfigMapName, err))
	}

	refTrimmed := strings.TrimSpace(refCM.Data["ca.crt"])
	if refTrimmed == "" {
		log.V(1).Info("kube-system/kube-root-ca.crt ca.crt empty — root CA drift check skipped")
		return rep.Result(&c.emitted, rootCADriftGauge.DeleteLabelValues,
			"kube-root-ca.crt drift: ", ", ")
	}
	expectedHash := rootCAHashSHA256(refTrimmed)

	cms, err := kube.ListAll(ctx,
		metav1.ListOptions{
			FieldSelector:   "metadata.name=" + rootCAConfigMapName,
			Limit:           kube.DefaultListPageSize,
			ResourceVersion: "0",
		},
		kube.ConfigMaps(c.CS, metav1.NamespaceAll))
	if err != nil {
		if apierrors.IsForbidden(err) {
			log.V(1).Info("cluster-wide kube-root-ca.crt list skipped (403)", "error", err)
			for k, lv := range c.emitted.Last() {
				rep.Carry(k, lv)
			}
			return rep.Result(&c.emitted, rootCADriftGauge.DeleteLabelValues,
				"kube-root-ca.crt drift: ", ", ")
		}
		return rootCACarryOnErr(&c.emitted, fmt.Errorf("list %s configmaps: %w", rootCAConfigMapName, err))
	}

	cmByNS := make(map[string]*corev1.ConfigMap, len(cms))
	for i := range cms {
		cm := &cms[i]
		// Re-filter in code because fake clientsets ignore FieldSelector.
		if cm.Name != rootCAConfigMapName || cm.DeletionTimestamp != nil {
			continue
		}
		cmByNS[cm.Namespace] = cm
	}

	namespaces, err := c.AllNamespaces(ctx)
	if err != nil {
		return rootCACarryOnErr(&c.emitted, fmt.Errorf("list namespaces: %w", err))
	}

	sort.Slice(namespaces, func(i, j int) bool {
		return namespaces[i].Name < namespaces[j].Name
	})

	eventsSent := 0
	seenKeep := map[string]bool{}
	for i := range namespaces {
		ns := &namespaces[i]
		if ns.DeletionTimestamp != nil || ns.Status.Phase == corev1.NamespaceTerminating {
			continue
		}
		if ns.Name == rootCAReferenceNS {
			continue
		}

		cm, ok := cmByNS[ns.Name]
		var reason, detail string
		switch {
		case !ok:
			if !kube.AgeAtLeast(ns.CreationTimestamp.Time, now, rootCAMissingMinAge) {
				continue
			}
			reason = rootCAReasonMissing
			detail = ns.Name + " (missing)"
		default:
			trimmed := strings.TrimSpace(cm.Data["ca.crt"])
			if trimmed == "" {
				reason = rootCAReasonEmpty
				detail = ns.Name + " (empty ca.crt)"
			} else if actualHash := rootCAHashSHA256(trimmed); actualHash != expectedHash {
				reason = rootCAReasonMismatch
				detail = fmt.Sprintf("%s (sha256=%s want=%s)", ns.Name, actualHash[:12], expectedHash[:12])
			}
		}
		if reason == "" {
			continue
		}

		tupleKey := ns.Name + "/" + reason
		// Gate empty & hash_mismatch behind a 2m persistence window
		// (matching rootCAMissingMinAge) so mid-rotation kube-root-ca.crt
		// propagation sweeps do not false-alarm.
		if reason == rootCAReasonEmpty || reason == rootCAReasonMismatch {
			seenKeep[tupleKey] = true
			if !probefw.Persisted(&c.driftSeen, tupleKey, now, rootCAMissingMinAge, log) {
				continue
			}
		}
		rep.Emit(rootCADriftGauge, tupleKey, []string{ns.Name, reason}, detail)

		if eventsSent < rootCAMaxEventsSweep && c.rootCAEmitWarning(ctx, log, now, ns, reason, detail) {
			eventsSent++
		}
	}
	c.driftSeen.Prune(func(k string) bool { return seenKeep[k] })

	return rep.Result(&c.emitted, rootCADriftGauge.DeleteLabelValues,
		"kube-root-ca.crt drift: ", ", ")
}

func rootCACarryOnErr(ledger *state.GaugeLedger[string], err error) probefw.Result {
	var rep probefw.SweepReport
	for k, lv := range ledger.Last() {
		rep.Carry(k, lv)
	}
	rep.InfraErr(err)
	return rep.Result(ledger, rootCADriftGauge.DeleteLabelValues,
		"kube-root-ca.crt drift: ", ", ")
}

func rootCAHashSHA256(trimmed string) string {
	sum := sha256.Sum256([]byte(trimmed))
	return hex.EncodeToString(sum[:])
}

func (c *rootCADriftCheck) rootCAEmitWarning(
	ctx context.Context,
	log logr.Logger,
	now time.Time,
	ns *corev1.Namespace,
	reason string,
	detail string,
) bool {
	cooldownKey := "root-ca." + ns.Name + "." + reason
	if c.eventCooldown.CooledDown(cooldownKey, rootCAEventCooldown, now) {
		return false
	}
	note := fmt.Sprintf("Namespace %s has drifted %s ConfigMap compared to %s/%s: %s",
		ns.Name, rootCAConfigMapName, rootCAReferenceNS, rootCAConfigMapName, detail)

	if err := kube.EmitWarningEvent(ctx, c.CS, kube.WarningEvent{
		Name:      kube.TruncatedEventName(cooldownKey, cooldownKey, now),
		Namespace: ns.Name,
		Regarding: corev1.ObjectReference{
			APIVersion: "v1",
			Kind:       "Namespace",
			Name:       ns.Name,
			UID:        ns.UID,
		},
		Reason:            rootCAEventReason,
		Note:              note,
		ReportingInstance: c.Name,
		Now:               now,
	}); err != nil {
		log.Info("WARN: RootCADrift event create failed (RBAC?)", "namespace", ns.Name, "error", err)
		return false
	}
	c.eventCooldown.Stamp(cooldownKey, now)
	log.Info("EVENT: RootCADrift", "namespace", ns.Name, "reason", reason)
	return true
}
