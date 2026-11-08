// onepassword_connect_sync_probe.go — the onepassword-connect-sync-probe
// check: the 1Password Connect pod ships two containers — connect-api
// answers Secret reads from a local SQLite cache while connect-sync
// keeps that cache fresh. A wedged or crashlooping connect-sync
// leaves connect-api replying 200 OK on stale data, so pod-level
// readiness stays green while every secret pull silently ages out —
// the exact blind spot that left ExternalSecrets serving stale
// credentials with no alert. The check scans the connect namespaces
// for a degraded connect-sync container and emits
// node_automation_onepassword_connect_sync_unhealthy (the same series
// externalsecret-nudge's auto-heal reads), failing the check while
// any pod is degraded — namespaced constants mirror
// externalsecret-nudge's esConnectNamespaces/esConnectPodPrefix.
package watchdogs

import (
	"context"
	"fmt"
	"strings"
	"time"

	corev1 "k8s.io/api/core/v1"
	logf "sigs.k8s.io/controller-runtime/pkg/log"

	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-automation-controller/internal/health/probefw"
	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-automation-controller/internal/metrics"
	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-automation-controller/internal/platform/state"
)

// onePasswordConnectSyncCheck is the connect-sync stall probe.
type onePasswordConnectSyncCheck struct {
	*probefw.Deps

	// emitted is the emitted-gauge ledger — a pod back to healthy
	// (or gone) gets its series deleted rather than pinning stale.
	emitted state.GaugeLedger[string]
}

// NewOnePasswordConnectSyncCheck builds the
// onepassword-connect-sync-probe check.
func NewOnePasswordConnectSyncCheck(d *probefw.Deps) probefw.Check {
	return &onePasswordConnectSyncCheck{Deps: d}
}

const (
	CheckNameOnePasswordConnectSync = "onepassword-connect-sync-probe"

	// esConnect* mirror externalsecret-nudge's candidate set — the
	// ESO namespace on these clusters or a dedicated connect ns, and
	// the helm-release pod prefix. Kept in parity on purpose: both
	// modules must agree on where the connect pod lives.
	esConnectSyncContainer  = "connect-sync"
	esConnectSyncRestartMax = 3
	// esConnectCrashloopWindow bounds the "recently terminated" half
	// of the crashloop signature: a high RestartCount only counts
	// while the container is in CrashLoopBackOff NOW or its last
	// termination finished inside this window — a pod that crash-
	// looped an hour ago and has been stable since is healthy.
	esConnectCrashloopWindow = 15 * time.Minute
	// esConnectStartGrace exempts freshly started pods from the
	// whole degraded judgment: a just-scheduled pod is legitimately
	// !Ready and its restart counter may tick during init churn
	// before the first stable run.
	esConnectStartGrace = 5 * time.Minute
)

var (
	// esConnectNamespaces/esConnectPodPrefix mirror the
	// externalsecret-nudge candidates — the check reads the same
	// pods the auto-heal bounces.
	esConnectNamespaces = []string{"external-secrets", "onepassword"}
	esConnectPodPrefix  = "onepassword-connect"
)

// checkOnePasswordConnectSync scans every Running onepassword-connect*
// pod for a degraded connect-sync container — !Ready, missing its
// status while declared, or past the crashloop restart ceiling —
// while connect-api can still report Ready on stale data.
func (p *onePasswordConnectSyncCheck) Run(ctx context.Context) probefw.Result {
	log := logf.FromContext(ctx)
	var rep probefw.SweepReport
	for _, ns := range esConnectNamespaces {
		pods, err := p.PodsIn(ctx, ns)
		if err != nil {
			return probefw.Result{Infra: fmt.Errorf("list pods in %s: %w", ns, err)}
		}
		for _, pod := range pods {
			if pod.DeletionTimestamp != nil ||
				pod.Status.Phase != corev1.PodRunning ||
				!strings.HasPrefix(pod.Name, esConnectPodPrefix) {
				continue
			}
			why, bad := connectSyncDegraded(pod, p.Now())
			if !bad {
				continue
			}
			key := pod.Namespace + "/" + pod.Name
			rep.Emit(metrics.OnePasswordConnectSyncUnhealthy, key,
				[]string{pod.Namespace, pod.Name},
				fmt.Sprintf("%s (%s)", key, why))
			log.Info("connect-sync degraded", "pod", key, "why", why)
		}
	}
	return rep.Result(&p.emitted,
		metrics.OnePasswordConnectSyncUnhealthy.DeleteLabelValues,
		"1Password connect-sync degraded: ", ", ")
}

// connectSyncDegraded reports whether the pod's connect-sync
// container is unhealthy — mirrors the externalsecret-nudge
// predicate: !Ready, status missing while the container is declared,
// or past the crashloop ceiling. The crashloop half only fires while
// the container sits in CrashLoopBackOff or its last termination
// finished inside esConnectCrashloopWindow; pods younger than
// esConnectStartGrace get a grace pass (a just-started pod is
// legitimately !Ready while its restart counter ticks through init).
// Pods declaring no connect-sync container are skipped (a different
// connect variant).
func connectSyncDegraded(pod *corev1.Pod, now time.Time) (why string, bad bool) {
	if now.Sub(pod.CreationTimestamp.Time) < esConnectStartGrace {
		return "", false
	}
	declared := false
	for _, c := range pod.Spec.Containers {
		if c.Name == esConnectSyncContainer {
			declared = true
			break
		}
	}
	if !declared {
		return "", false
	}
	for _, cs := range pod.Status.ContainerStatuses {
		if cs.Name != esConnectSyncContainer {
			continue
		}
		switch {
		case !cs.Ready:
			return "connect-sync container not Ready", true
		case cs.RestartCount >= esConnectSyncRestartMax:
			inBackoff := cs.State.Waiting != nil &&
				cs.State.Waiting.Reason == "CrashLoopBackOff"
			finishedRecently := cs.LastTerminationState.Terminated != nil &&
				!cs.LastTerminationState.Terminated.FinishedAt.IsZero() &&
				now.Sub(cs.LastTerminationState.Terminated.FinishedAt.Time) <= esConnectCrashloopWindow
			if inBackoff || finishedRecently {
				return "connect-sync container crashlooping", true
			}
		}
		return "", false
	}
	return "connect-sync container status missing", true
}
