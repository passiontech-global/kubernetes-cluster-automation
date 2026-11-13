// scylla_member_signals.go — the scylla-cluster-health check's
// member-level signature phases: (b) member_service_desync (the
// per-member Service whose EndpointSlice does not carry the live
// pod's IP) and (c) gossip_or_raft_stall / tombstone_overload_stall
// (troubled member pods whose scylla log tail matches a stall
// signature, fetched through a bounded worker pool). Run() in
// scylla_cluster_health.go does the CR-condition phase and the
// persistence/gauge emission; this file holds the member scans.
package scylla

import (
	"context"

	"github.com/go-logr/logr"
	corev1 "k8s.io/api/core/v1"
	discoveryv1 "k8s.io/api/discovery/v1"

	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-automation-controller/internal/platform/kube"
)

// endpointAddrs rolls the Ready endpoints of every EndpointSlice
// into "ns/svc" -> address set — the lookup memberDesyncFindings
// joins the live pod IP against. Ready-only: a slice holding the
// pod IP but marked unready is still a desync for traffic (the
// shared rollup already dropped unready endpoints; nil Ready
// counts as ready).
func endpointAddrs(slices []discoveryv1.EndpointSlice) map[string]map[string]bool {
	esAddrs := map[string]map[string]bool{}
	for key, eps := range kube.ReadyEndpointsByService(slices) {
		set := map[string]bool{}
		for _, e := range eps {
			for _, a := range e.Addresses {
				set[a] = true
			}
		}
		esAddrs[key] = set
	}
	return esAddrs
}

// memberDesyncFindings folds the shared reads into the
// member_service_desync findings: a per-member Service
// (scylla.scylladb.com/pod-name=<pod>) must route to the live pod's
// IP — an EndpointSlice that carries no endpoint for it (or no
// endpoint at all while the pod is Running) is a desync pending
// its persistence window.
func memberDesyncFindings(svcs []corev1.Service,
	podsByKey map[string]*corev1.Pod,
	esAddrs map[string]map[string]bool, pending map[string]scyllaFinding) {
	for i := range svcs {
		svc := &svcs[i]
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
}

// memberStallFindings fans the troubled member pods' scylla-log
// tails through a bounded worker pool (max scyllaStallLogWorkers
// concurrent kubelet log streams) and folds the hits into pending —
// gossip_or_raft_stall / tombstone_overload_stall signatures keyed
// "stall/ns/pod/uid/reason" (the uid makes a recreated pod a fresh
// signature). A fetch error is inconclusive, not clean — a broken
// pod-log path must not silently read as "no stall".
func (p *scyllaHealthCheck) memberStallFindings(ctx context.Context,
	log logr.Logger, pods []corev1.Pod, pending map[string]scyllaFinding,
	inconclusive map[string]bool) {
	var troubled []*corev1.Pod
	for i := range pods {
		pod := &pods[i]
		if pod.Labels[scyllaClusterLabel] != "" && scyllaPodTroubled(pod) {
			troubled = append(troubled, pod)
		}
	}
	scans := kube.ScanPodLogs(ctx, p.CS, troubled, scyllaStallLogWorkers,
		func(ctx context.Context, pod *corev1.Pod) (string, error) {
			return p.scyllaStallLogHit(ctx, pod)
		})
	for j, pod := range troubled {
		s := scans[j]
		if s.Err != nil {
			log.Info("WARN: scylla log fetch failed — stall signature inconclusive",
				"pod", pod.Namespace+"/"+pod.Name, "error", s.Err)
			inconclusive[pod.Namespace+"/"+pod.Name+"/"+string(pod.UID)] = true
			continue
		}
		if s.Value == "" {
			continue
		}
		pending["stall/"+pod.Namespace+"/"+pod.Name+"/"+string(pod.UID)+"/"+s.Value] =
			scyllaFinding{
				ns: pod.Namespace, cluster: pod.Labels[scyllaClusterLabel],
				reason: s.Value,
			}
	}
}
