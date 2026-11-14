// scylla_cluster_health.go — the scylla-cluster-health check
// (scylla-cluster-health): audits ScyllaDB operand health — degraded ScyllaCluster
// conditions, per-member Service/EndpointSlice desync, and gossip/
// raft stall signatures in member pod logs — reported on
// node_automation_scylla_unhealthy{reason}.
package scylla

import (
	"context"
	"fmt"
	"regexp"
	"strings"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	logf "sigs.k8s.io/controller-runtime/pkg/log"
	ctrlmetrics "sigs.k8s.io/controller-runtime/pkg/metrics"

	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-automation-controller/internal/platform/kube"
	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-automation-controller/internal/platform/state"
	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-automation-controller/internal/probefw"
)

// scyllaHealthCheck is the scylla-cluster-health scylla cluster health watchdog.
type scyllaHealthCheck struct {
	*probefw.Deps

	// scylla-cluster-health watchdog state (serial sweep — unguarded):
	//   - scyllaFirstSeen: "member/ns/svc" | "gossip/ns/pod/uid" →
	//     first sweep the signature showed; it must persist
	//     scyllaSignatureMinAge before the gauge fires (the
	//     degraded_condition reason carries its own clock — the CR
	//     condition's lastTransitionTime). Pruned on resolve.
	//   - scyllaEmitted: the emitted-gauge ledger for the
	//     "ns/cluster/reason" tuples held at 1 — same
	//     DeleteLabelValues hygiene as the other emitted sets.
	scyllaFirstSeen state.FirstSeenLedger
	scyllaEmitted   state.GaugeLedger[string]
	// lastPending is last sweep's pending-signature map — the carry
	// source for pods whose log scan failed this sweep: their prior
	// "stall/…" entries restore into pending so the first-seen stamp
	// and any emitted tuple survive the inconclusive read.
	lastPending map[string]scyllaFinding
}

// newScyllaHealthCheck builds the scylla-cluster-health check — both ledgers arm
// lazily on first use (the GaugeLedger zero value is ready).
func NewScyllaHealthCheck(d *probefw.Deps) probefw.Check {
	return &scyllaHealthCheck{Deps: d}
}

const (
	// scylla-cluster-health — scylla-cluster-health knobs.
	CheckNameScyllaHealth = "scylla-cluster-health"
	scyllaDegradedMinAge  = 15 * time.Minute
	scyllaSignatureMinAge = 10 * time.Minute

	// The per-pod stall log-fetch fan-out cap (Component 3 pool).
	scyllaStallLogWorkers = 4

	scyllaPodNameLabel       = "scylla.scylladb.com/pod-name"
	scyllaClusterLabel       = "scylla.scylladb.com/cluster"
	scyllaContainerName      = "scylla"
	scyllaReasonDegraded     = "degraded_condition"
	scyllaReasonMemberDesync = "member_service_desync"
	scyllaReasonGossipStall  = "gossip_or_raft_stall"
	// scylla-shard-imbalance — the tombstone-avalanche / overload stall reason.
	scyllaReasonTombstoneStall = "tombstone_overload_stall"
)

// scyllaClusterGVR is the ScyllaCluster CR the scylla-cluster-health auditor reads —
// the same GVR the operator-workqueue-watchdog scylla-operator watchdog scans.
var scyllaClusterGVR = kube.GVRScyllaCluster

var (
	// scylla-cluster-health — the ScyllaDB unhealthy signal: 1 while the
	// ScyllaCluster/member shows a sustained unhealthy signature.
	// reason is degraded_condition | member_service_desync |
	// gossip_or_raft_stall | tombstone_overload_stall (scylla-shard-imbalance).
	scyllaClusterUnhealthyGauge = prometheus.NewGaugeVec(prometheus.GaugeOpts{
		Name: "node_automation_scylla_unhealthy",
		Help: "1 while the ScyllaCluster/member shows a sustained unhealthy signature.",
	}, []string{"namespace", "cluster", "reason"})
)

func init() {
	ctrlmetrics.Registry.MustRegister(
		scyllaClusterUnhealthyGauge)
}

// ---------------------------------------------------------------------------
// scylla-cluster-health — scylla-cluster-health
// ---------------------------------------------------------------------------

// scyllaGossipPatterns are the log signatures of the three ScyllaDB
// failure shapes the operator cannot see from the API (per
// docs/scylladb-troubleshooting.md in passiontech-fluxcd):
//
//   - a ghost gossip entry rejecting a rejoining member
//     ("InetAddress ... is already present in gossip" — needs
//     nodetool removenode / replace_address);
//   - replace_address_first_boot — the member is re-bootstrapping
//     against a stale address;
//   - group0/raft timeouts — quorum loss stalls every cluster-wide
//     change (the deadlock the doc's section 3 describes).
var scyllaGossipPatterns = []*regexp.Regexp{
	regexp.MustCompile(`InetAddress .* is already present in gossip`),
	regexp.MustCompile(`replace_address_first_boot`),
	// Narrow: a bare `raft_group0` matches every log line that even
	// mentions group0 (benign topology chatter included) and would
	// noise gossip_or_raft_stall. Only the failure shapes — a group0
	// operation timing out, failing or retrying — are stall evidence.
	regexp.MustCompile(`group0.*(timed out|failed|retry)`),
}

// scyllaTombstonePatterns are the scylla-shard-imbalance log signatures of a
// tombstone avalanche / overload stall — the failure shape where a
// member stays Running but its reads time out scanning thousands of
// tombstones or one shard's reactor wedges on a hot partition:
//
//   - "Read N live cells and M tombstones" — the tombstone-scan
//     warning a partition avalanche produces on every query path;
//   - tombstone_warn/failure_threshold — Scylla's own scanner
//     guardrails firing;
//   - "Reactor stalled for N ms" — a shard's event loop wedged
//     (hot partition, bad_alloc pressure);
//   - bad_alloc — a shard hit its memory ceiling mid-read.
var scyllaTombstonePatterns = []*regexp.Regexp{
	regexp.MustCompile(`Read \d+ live cells and \d+ tombstones`),
	regexp.MustCompile(`tombstone_(warn|failure)_threshold`),
	regexp.MustCompile(`Reactor stalled for \d+ ms`),
	regexp.MustCompile(`bad_alloc`),
}

// unstructuredCondStatus returns a dynamic-client object's named
// status.conditions entry's status and lastTransitionTime — ""
// and the zero time when absent or malformed.
func unstructuredCondStatus(obj *unstructured.Unstructured, typ string) (string, time.Time) {
	c, ok := kube.ConditionOf(obj.Object, typ)
	if !ok {
		return "", time.Time{}
	}
	return c.Status, c.LastTransitionTime
}

// scyllaFinding is one live unhealthy signature resolved to its gauge
// labels.
type scyllaFinding struct {
	ns, cluster, reason string
}

// scyllaPodTroubled selects the member pods worth a log fetch:
// anything not cleanly Running+Ready — Pending/Failed/Unknown phase,
// a pod that never went Ready, or a container in CrashLoopBackOff
// ("unready/restarting" in the scylla-cluster-health contract). Succeeded pods and
// pods already terminating are skipped — their logs describe a dead
// end, not a live stall.
func scyllaPodTroubled(pod *corev1.Pod) bool {
	if pod.DeletionTimestamp != nil || pod.Status.Phase == corev1.PodSucceeded {
		return false
	}
	if pod.Status.Phase != corev1.PodRunning {
		return true
	}
	if !kube.PodReadyCond(pod) {
		return true
	}
	for _, cs := range pod.Status.ContainerStatuses {
		if cs.State.Waiting != nil && cs.State.Waiting.Reason == "CrashLoopBackOff" {
			return true
		}
	}
	return false
}

// scyllaStallLogHit fetches the last probefw.DefaultTailLines of the
// pod's "scylla" container and returns the reason label of the first
// matching stall signature — scyllaReasonGossipStall for the gossip/
// raft patterns, scyllaReasonTombstoneStall for the scylla-shard-imbalance
// tombstone/overload set. Bounded to probefw.LogTimeout /
// probefw.LogMaxBytes (same posture as the coredns watchdog's log
// probe); a stream/read failure is inconclusive — PodLogTail returns
// it as an error so the caller logs it rather than reading "no
// match" as "healthy".
func (p *scyllaHealthCheck) scyllaStallLogHit(ctx context.Context, pod *corev1.Pod) (string, error) {
	var reason string
	hit, err := kube.ReadPodLogTail(ctx, p.CS, pod, kube.PodLogOpts{
		Container:    scyllaContainerName,
		TailLines:    probefw.DefaultTailLines,
		SinceSeconds: 900,
		MaxBytes:     probefw.LogMaxBytes,
		Timeout:      probefw.LogTimeout,
	}, func(line string) bool {
		for _, re := range scyllaGossipPatterns {
			if re.MatchString(line) {
				reason = scyllaReasonGossipStall
				return true
			}
		}
		for _, re := range scyllaTombstonePatterns {
			if re.MatchString(line) {
				reason = scyllaReasonTombstoneStall
				return true
			}
		}
		return false
	})
	if err != nil || !hit {
		return "", err
	}
	return reason, nil
}

// checkScyllaHealth audits the ScyllaDB operand stack on the three
// failure shapes that leave the cluster degraded without the operator
// noticing (scylla-cluster-health):
//
//	a) degraded_condition — the ScyllaCluster CR itself reports
//	   Degraded=True or Available=False for >=15m (the condition's
//	   own lastTransitionTime is the persistence clock);
//	b) member_service_desync — a per-member Service
//	   (scylla.scylladb.com/pod-name=<pod>) whose EndpointSlice does
//	   not carry the live pod's status.podIP — or carries no endpoint
//	   at all while the pod is Running — for >=10m;
//	c) gossip_or_raft_stall | tombstone_overload_stall — an
//	   unready/restarting member pod
//	   (scylla.scylladb.com/cluster=<name>) whose scylla log tail
//	   matches the ghost-gossip / replace_address_first_boot /
//	   group0-raft-timeout signatures — or, scylla-shard-imbalance, the tombstone-
//	   avalanche / reactor-stall signatures — for >=10m.
//
// Every signature must persist its window before
// node_automation_scylla_unhealthy{reason}=1 fires; a resolved tuple
// is DeleteLabelValues'd, never left stale at 1.
func (p *scyllaHealthCheck) Run(ctx context.Context) probefw.Result {
	log := logf.FromContext(ctx)
	// The CR scan needs dyn — a missing client is a wiring bug, not
	// "no signal" (same posture as the OLM check).
	if r := p.RequireDyn("scylla health check"); r != nil {
		return *r
	}
	now := p.Now()

	// pending: signatures still inside their persistence window,
	// keyed for first-seen tracking. emittedKeys collect the gauge
	// tuples already past their evidence window.
	pending := map[string]scyllaFinding{}
	emitted := map[string]scyllaFinding{} // "ns/cluster/reason" -> finding

	// (a) degraded_condition — the CR's own condition clock.
	crs, err := p.AllUnstructured(ctx, scyllaClusterGVR)
	switch {
	case kube.IsCRDAbsent(err):
		// ScyllaDB stack not installed on this cluster — (b)/(c)
		// still run: member services/pods could outlive the CRD.
	case err != nil:
		return probefw.Result{Infra: fmt.Errorf("list scyllaclusters: %w", err)}
	default:
		for i := range crs {
			cr := &crs[i]
			for _, probe := range []struct{ typ, status string }{
				{"Degraded", "True"},
				{"Available", "False"},
			} {
				status, since := unstructuredCondStatus(cr, probe.typ)
				if status != probe.status || since.IsZero() ||
					now.Sub(since) < scyllaDegradedMinAge {
					continue
				}
				f := scyllaFinding{
					ns: cr.GetNamespace(), cluster: cr.GetName(),
					reason: scyllaReasonDegraded,
				}
				emitted[f.ns+"/"+f.cluster+"/"+f.reason] = f
			}
		}
	}

	// Shared reads for (b) and (c) — one pod/service/EndpointSlice
	// census per sweep.
	pods, err := p.AllPods(ctx)
	if err != nil {
		return probefw.Result{Infra: fmt.Errorf("list pods: %w", err)}
	}
	svcs, err := p.AllServices(ctx)
	if err != nil {
		return probefw.Result{Infra: fmt.Errorf("list services: %w", err)}
	}
	slices, err := p.AllEndpointSlices(ctx)
	if err != nil {
		return probefw.Result{Infra: fmt.Errorf("list endpointslices: %w", err)}
	}
	esAddrs := endpointAddrs(slices) // "ns/svc" -> ready endpoint addresses

	podsByKey := map[string]*corev1.Pod{}
	for i := range pods {
		podsByKey[pods[i].Namespace+"/"+pods[i].Name] = &pods[i]
	}

	// (b) member_service_desync + (c) gossip/raft + tombstone stall
	// — the member-level signature phases (scylla_member_signals.go).
	inconclusive := map[string]bool{} // "ns/pod/uid" — log scan failed
	memberDesyncFindings(svcs, podsByKey, esAddrs, pending)
	p.memberStallFindings(ctx, log, pods, pending, inconclusive)
	// A pod whose log scan failed is "can't tell", not "resolved":
	// restore last sweep's pending entries for it so the first-seen
	// stamp survives and a past-window signature re-emits instead of
	// flapping off for one kubelet read error.
	for ik := range inconclusive {
		prefix := "stall/" + ik + "/"
		for k, f := range p.lastPending {
			if strings.HasPrefix(k, prefix) {
				pending[k] = f
			}
		}
	}
	p.lastPending = pending

	// Persistence window + gauge emission — same first-seen /
	// DeleteLabelValues hygiene as the OLM and masterless checks.
	p.scyllaFirstSeen.Prune(func(k string) bool {
		_, ok := pending[k]
		return ok
	})
	for k, f := range pending {
		if probefw.Persisted(&p.scyllaFirstSeen, k, now,
			scyllaSignatureMinAge, log) {
			emitted[f.ns+"/"+f.cluster+"/"+f.reason] = f
		}
	}
	var rep probefw.SweepReport
	for k, f := range emitted {
		rep.Emit(scyllaClusterUnhealthyGauge, k,
			[]string{f.ns, f.cluster, f.reason}, k)
	}
	return rep.Result(&p.scyllaEmitted, scyllaClusterUnhealthyGauge.DeleteLabelValues,
		"scylla unhealthy signatures: ", ", ")
}
