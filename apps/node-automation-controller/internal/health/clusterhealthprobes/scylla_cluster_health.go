// scylla_cluster_health.go — the scylla-cluster-health check
// (W9-ST1): audits ScyllaDB operand health — degraded ScyllaCluster
// conditions, per-member Service/EndpointSlice desync, and gossip/
// raft stall signatures in member pod logs — reported on
// node_automation_scylla_unhealthy{reason}.
package clusterhealthprobes

import (
	"context"
	"fmt"
	"io"
	"maps"
	"regexp"
	"sort"
	"strings"
	"time"

	corev1 "k8s.io/api/core/v1"
	discoveryv1 "k8s.io/api/discovery/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/api/meta"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	logf "sigs.k8s.io/controller-runtime/pkg/log"

	"github.com/passiontech-global/kubernetes-node-automation/apps/node-automation-controller/internal/metrics"
	"github.com/passiontech-global/kubernetes-node-automation/apps/node-automation-controller/internal/shared"
)

// scyllaHealthCheck is the W9-ST1 scylla cluster health watchdog.
type scyllaHealthCheck struct {
	*deps

	// W9-ST1 watchdog state (under mu):
	//   - scyllaFirstSeen: "member/ns/svc" | "gossip/ns/pod/uid" →
	//     first sweep the signature showed; it must persist
	//     scyllaSignatureMinAge before the gauge fires (the
	//     degraded_condition reason carries its own clock — the CR
	//     condition's lastTransitionTime). Pruned on resolve.
	//   - scyllaEmitted: "ns/cluster/reason" gauge tuples held at 1 —
	//     same DeleteLabelValues hygiene as the other emitted sets.
	scyllaFirstSeen map[string]time.Time
	scyllaEmitted   map[string]bool
}

// newScyllaHealthCheck builds the W9-ST1 check with fresh tracking
// maps — the state-map initialization that used to live in the
// monolithic newClusterHealthProber literal.
func newScyllaHealthCheck(d *deps) checkRunner {
	return &scyllaHealthCheck{deps: d,
		scyllaFirstSeen: map[string]time.Time{},
		scyllaEmitted:   map[string]bool{},
	}
}

const (
	// W9-ST1 — scylla-cluster-health knobs.
	checkNameScyllaHealth    = "scylla-cluster-health"
	scyllaDegradedMinAge     = 15 * time.Minute
	scyllaSignatureMinAge    = 10 * time.Minute
	scyllaGossipTailLines    = int64(200)
	scyllaGossipLogMaxBytes  = 256 * 1024
	scyllaPodNameLabel       = "scylla.scylladb.com/pod-name"
	scyllaClusterLabel       = "scylla.scylladb.com/cluster"
	scyllaContainerName      = "scylla"
	scyllaReasonDegraded     = "degraded_condition"
	scyllaReasonMemberDesync = "member_service_desync"
	scyllaReasonGossipStall  = "gossip_or_raft_stall"
)

// scyllaClusterGVR is the ScyllaCluster CR the W9-ST1 auditor reads —
// the same GVR the W5.8 scylla-operator watchdog scans.
var scyllaClusterGVR = shared.GVRScyllaCluster

// ---------------------------------------------------------------------------
// W9-ST1 — scylla-cluster-health
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
	regexp.MustCompile(`group0.*timed out`),
	regexp.MustCompile(`raft_group0`),
}

// unstructuredCondStatus returns a dynamic-client object's named
// status.conditions entry's status and lastTransitionTime — ""
// and the zero time when absent or malformed.
func unstructuredCondStatus(obj *unstructured.Unstructured, typ string) (string, time.Time) {
	c, ok := shared.ConditionOf(obj.Object, typ)
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
// ("unready/restarting" in the W9-ST1 contract). Succeeded pods and
// pods already terminating are skipped — their logs describe a dead
// end, not a live stall.
func scyllaPodTroubled(pod *corev1.Pod) bool {
	if pod.DeletionTimestamp != nil || pod.Status.Phase == corev1.PodSucceeded {
		return false
	}
	if pod.Status.Phase != corev1.PodRunning {
		return true
	}
	if !shared.PodReadyCond(pod) {
		return true
	}
	for _, cs := range pod.Status.ContainerStatuses {
		if cs.State.Waiting != nil && cs.State.Waiting.Reason == "CrashLoopBackOff" {
			return true
		}
	}
	return false
}

// scyllaGossipLogHit fetches the last scyllaGossipTailLines of the
// pod's "scylla" container and reports whether any line matches a
// gossip/raft stall signature. Bounded to 8s / scyllaGossipLogMaxBytes
// (same posture as the coredns watchdog's log probe); a stream/read
// failure is inconclusive — returned as an error so the caller logs
// it rather than reading "no match" as "healthy".
func (p *scyllaHealthCheck) scyllaGossipLogHit(ctx context.Context, pod *corev1.Pod) (bool, error) {
	lctx, cancel := context.WithTimeout(ctx, 8*time.Second)
	defer cancel()
	tail := scyllaGossipTailLines
	stream, err := p.cs.CoreV1().Pods(pod.Namespace).GetLogs(pod.Name,
		&corev1.PodLogOptions{
			Container: scyllaContainerName,
			TailLines: &tail,
		}).Stream(lctx)
	if err != nil {
		return false, err
	}
	defer stream.Close()
	data, err := io.ReadAll(io.LimitReader(stream, scyllaGossipLogMaxBytes))
	if err != nil {
		return false, err
	}
	for _, line := range strings.Split(string(data), "\n") {
		for _, re := range scyllaGossipPatterns {
			if re.MatchString(line) {
				return true, nil
			}
		}
	}
	return false, nil
}

// checkScyllaHealth audits the ScyllaDB operand stack on the three
// failure shapes that leave the cluster degraded without the operator
// noticing (W9-ST1):
//
//	a) degraded_condition — the ScyllaCluster CR itself reports
//	   Degraded=True or Available=False for >=15m (the condition's
//	   own lastTransitionTime is the persistence clock);
//	b) member_service_desync — a per-member Service
//	   (scylla.scylladb.com/pod-name=<pod>) whose EndpointSlice does
//	   not carry the live pod's status.podIP — or carries no endpoint
//	   at all while the pod is Running — for >=10m;
//	c) gossip_or_raft_stall — an unready/restarting member pod
//	   (scylla.scylladb.com/cluster=<name>) whose scylla log tail
//	   matches the ghost-gossip / replace_address_first_boot /
//	   group0-raft-timeout signatures for >=10m.
//
// Every signature must persist its window before
// node_automation_scylla_unhealthy{reason}=1 fires; a resolved tuple
// is DeleteLabelValues'd, never left stale at 1.
func (p *scyllaHealthCheck) run(ctx context.Context) probeResult {
	log := logf.FromContext(ctx)
	// The CR scan needs dyn — a missing client is a wiring bug, not
	// "no signal" (same posture as the OLM check).
	if p.dyn == nil {
		return probeResult{infra: fmt.Errorf(
			"no dynamic client — scylla health check unverifiable")}
	}
	now := p.now()
	p.mu.Lock()
	if p.scyllaFirstSeen == nil {
		p.scyllaFirstSeen = map[string]time.Time{}
	}
	if p.scyllaEmitted == nil {
		p.scyllaEmitted = map[string]bool{}
	}
	p.mu.Unlock()

	// pending: signatures still inside their persistence window,
	// keyed for first-seen tracking. emittedKeys collect the gauge
	// tuples already past their evidence window.
	pending := map[string]scyllaFinding{}
	emitted := map[string]scyllaFinding{} // "ns/cluster/reason" -> finding

	// (a) degraded_condition — the CR's own condition clock.
	crs, err := p.dyn.Resource(scyllaClusterGVR).List(ctx, metav1.ListOptions{})
	switch {
	case apierrors.IsNotFound(err) || meta.IsNoMatchError(err):
		// ScyllaDB stack not installed on this cluster — (b)/(c)
		// still run: member services/pods could outlive the CRD.
	case err != nil:
		return probeResult{infra: fmt.Errorf("list scyllaclusters: %w", err)}
	default:
		for i := range crs.Items {
			cr := &crs.Items[i]
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
	pods, err := p.cs.CoreV1().Pods(metav1.NamespaceAll).
		List(ctx, metav1.ListOptions{})
	if err != nil {
		return probeResult{infra: fmt.Errorf("list pods: %w", err)}
	}
	svcs, err := p.cs.CoreV1().Services(metav1.NamespaceAll).
		List(ctx, metav1.ListOptions{})
	if err != nil {
		return probeResult{infra: fmt.Errorf("list services: %w", err)}
	}
	esAddrs := map[string]map[string]bool{} // "ns/svc" -> endpoint addresses
	err = shared.ListEach(ctx,
		metav1.ListOptions{Limit: healthListPageSize},
		shared.EndpointSlices(p.cs, metav1.NamespaceAll),
		func(items []discoveryv1.EndpointSlice) error {
			for _, s := range items {
				svc := s.Labels[discoveryv1.LabelServiceName]
				if svc == "" {
					continue
				}
				key := s.Namespace + "/" + svc
				set := esAddrs[key]
				if set == nil {
					set = map[string]bool{}
					esAddrs[key] = set
				}
				for _, ep := range s.Endpoints {
					// Ready-only — a slice holding the pod IP but
					// marked unready is still a desync for traffic.
					// nil Ready counts as ready (k8s convention).
					if ep.Conditions.Ready != nil && !*ep.Conditions.Ready {
						continue
					}
					for _, a := range ep.Addresses {
						set[a] = true
					}
				}
			}
			return nil
		})
	if err != nil {
		return probeResult{infra: fmt.Errorf("list endpointslices: %w", err)}
	}

	podsByKey := map[string]*corev1.Pod{}
	for i := range pods.Items {
		podsByKey[pods.Items[i].Namespace+"/"+pods.Items[i].Name] = &pods.Items[i]
	}

	// (b) member_service_desync — the per-member Service must route
	// to the live pod's IP.
	for i := range svcs.Items {
		svc := &svcs.Items[i]
		podName := svc.Labels[scyllaPodNameLabel]
		if podName == "" {
			continue
		}
		pod := podsByKey[svc.Namespace+"/"+podName]
		if pod == nil || pod.DeletionTimestamp != nil ||
			pod.Status.Phase != corev1.PodRunning ||
			pod.Status.PodIP == "" {
			continue
		}
		if esAddrs[svc.Namespace+"/"+svc.Name][pod.Status.PodIP] {
			continue // EndpointSlice carries the live IP — synced
		}
		cluster := pod.Labels[scyllaClusterLabel]
		if cluster == "" {
			cluster = svc.Name // unlabeled member pod — key the gauge on the service
		}
		pending["member/"+svc.Namespace+"/"+svc.Name] = scyllaFinding{
			ns: svc.Namespace, cluster: cluster,
			reason: scyllaReasonMemberDesync,
		}
	}

	// (c) gossip_or_raft_stall — troubled member pods whose scylla
	// log tail carries a stall signature.
	for i := range pods.Items {
		pod := &pods.Items[i]
		if pod.Labels[scyllaClusterLabel] == "" || !scyllaPodTroubled(pod) {
			continue
		}
		hit, err := p.scyllaGossipLogHit(ctx, pod)
		if err != nil {
			// Inconclusive, not clean — a broken pod-log path must
			// not silently read as "no stall".
			log.Info("WARN: scylla log fetch failed — stall signature inconclusive",
				"pod", pod.Namespace+"/"+pod.Name, "error", err)
			continue
		}
		if !hit {
			continue
		}
		pending["gossip/"+pod.Namespace+"/"+pod.Name+"/"+string(pod.UID)] =
			scyllaFinding{
				ns: pod.Namespace, cluster: pod.Labels[scyllaClusterLabel],
				reason: scyllaReasonGossipStall,
			}
	}

	// Persistence window + gauge emission — same first-seen /
	// DeleteLabelValues hygiene as the OLM and masterless checks.
	p.mu.Lock()
	for k := range p.scyllaFirstSeen {
		if _, ok := pending[k]; !ok {
			delete(p.scyllaFirstSeen, k)
		}
	}
	for k, f := range pending {
		first, ok := p.scyllaFirstSeen[k]
		if !ok {
			p.scyllaFirstSeen[k] = now
			log.Info("scylla unhealthy signature — tracking first-seen",
				"signature", k)
			continue
		}
		if now.Sub(first) < scyllaSignatureMinAge {
			continue
		}
		emitted[f.ns+"/"+f.cluster+"/"+f.reason] = f
	}
	for k := range p.scyllaEmitted {
		if _, ok := emitted[k]; ok {
			continue
		}
		if parts := strings.SplitN(k, "/", 3); len(parts) == 3 {
			metrics.ScyllaClusterUnhealthy.DeleteLabelValues(
				parts[0], parts[1], parts[2])
		}
		delete(p.scyllaEmitted, k)
	}
	emittedKeys := make(map[string]bool, len(emitted))
	for k := range emitted {
		emittedKeys[k] = true
	}
	maps.Copy(p.scyllaEmitted, emittedKeys)
	p.mu.Unlock()

	for _, f := range emitted {
		metrics.ScyllaClusterUnhealthy.
			WithLabelValues(f.ns, f.cluster, f.reason).Set(1)
	}

	if len(emitted) == 0 {
		return probeResult{pass: true}
	}
	keys := make([]string, 0, len(emitted))
	for k := range emitted {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return probeResult{why: fmt.Sprintf(
		"scylla unhealthy signatures: %s", strings.Join(keys, ", "))}
}
