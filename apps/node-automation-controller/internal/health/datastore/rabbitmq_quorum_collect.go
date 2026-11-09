// rabbitmq_quorum_collect.go — the census + Prometheus signal
// collection half of the rabbitmq-quorum-health check (see
// rabbitmq_quorum_health.go for the check itself and
// rabbitmq_quorum_heals.go for what the findings drive): which pods
// are RabbitMQ cluster members — minus the clusters the
// go-kube-downscaler parked — and the alarm / raft-role / raft-term
// findings each sweep folds into one map.
package datastore

import (
	"context"

	"github.com/go-logr/logr"
	corev1 "k8s.io/api/core/v1"

	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-automation-controller/internal/health/probefw"
	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-automation-controller/internal/platform/kube"
)

// rabbitCensus is one sweep's view of the RabbitMQ fleet: member
// pods keyed both ways a signal can name them, the unlabeled subset
// ReadyByOwner needs for the fallback grouping, and the
// downscaled-cluster set that excuses parked members from every
// finding below.
type rabbitCensus struct {
	byName     map[string]*corev1.Pod // "ns/name" — findings key on it
	byPodName  map[string]*corev1.Pod // bare name — raft-term series fallback
	members    []*corev1.Pod
	unlabeled  []corev1.Pod
	downscaled map[string]bool
}

// collectRabbitCensus lists the pods and the RabbitmqCluster CRs,
// then keeps only live RabbitMQ members outside downscaled clusters.
// A RabbitmqCluster the go-kube-downscaler parked at
// spec.replicas:0 is asleep on purpose — its members' absence and
// any lingering alarm series are intent, not a quorum failure. A CR
// list failure fails open (empty set): the pod signatures keep
// their normal posture.
func collectRabbitCensus(ctx context.Context, d *probefw.Deps,
	log logr.Logger) (*rabbitCensus, error) {
	pods, err := d.AllPods(ctx)
	if err != nil {
		return nil, err
	}
	crs, err := d.AllUnstructured(ctx, kube.GVRRabbitMQCluster)
	downscaled, err := downscaledClusterCRs(crs, err)
	if err != nil {
		log.Info("WARN: list rabbitmqclusters failed — downscaler awareness off",
			"error", err)
	}
	c := &rabbitCensus{
		byName:     map[string]*corev1.Pod{},
		byPodName:  map[string]*corev1.Pod{},
		downscaled: downscaled,
	}
	for i := range pods {
		pod := &pods[i]
		if !isRabbitMQPod(pod) ||
			downscaledMemberPod(pod.Namespace, pod.Name, downscaled) {
			continue
		}
		c.byName[pod.Namespace+"/"+pod.Name] = pod
		c.byPodName[pod.Name] = pod // ns fallback for series w/o namespace label
		c.members = append(c.members, pod)
		if rabbitClusterKey(pod) == "" {
			c.unlabeled = append(c.unlabeled, *pod)
		}
	}
	return c, nil
}

// rabbitPromFindings runs the three Prometheus signal families —
// the alarm/partition queries, quorum-queue raft role, and raft-term
// skew — and folds every attributed series into one findings map
// keyed "ns/pod" (or "cluster/<reason>" for a series with no pod
// label). Query failures warn and skip their family; the pod-side
// signatures are unaffected.
func rabbitPromFindings(ctx context.Context, d *probefw.Deps,
	log logr.Logger, c *rabbitCensus) map[string]map[string]bool {
	findings := rabbitAlarmFindings(ctx, d, log, c)
	rabbitLeaderlessFindings(ctx, d, log, c, findings)
	rabbitSkewFindings(ctx, d, log, c, findings)
	return findings
}

// rabbitAlarmFindings runs the four watermark / dist-partition
// instant queries and seeds the findings map.
func rabbitAlarmFindings(ctx context.Context, d *probefw.Deps,
	log logr.Logger, c *rabbitCensus) map[string]map[string]bool {
	type sig struct{ q, reason string }
	queries := []sig{
		{`rabbitmq_alarms_file_descriptor_limit == 1`, "fd_limit_alarm"},
		{`rabbitmq_alarms_memory_used_watermark == 1`, "memory_watermark_alarm"},
		{`rabbitmq_alarms_free_disk_space_watermark == 1`, "disk_watermark_alarm"},
		{`erlang_vm_dist_node_state != 3`, "mnesia_partition"},
	}
	findings := map[string]map[string]bool{} // "ns/pod" -> reasons
	for _, q := range queries {
		series, err := d.PromQuery(ctx, q.q)
		if err != nil {
			log.Info("WARN: rabbitmq prom query failed — signal skipped",
				"query", q.q, "error", err)
			continue
		}
		for _, s := range series {
			podName := s.Label("pod", "pod_name")
			// Fail-closed: a series without a namespace label cannot
			// be attributed — a bare pod name is ambiguous across
			// namespaces, and guessing would heal the wrong cluster's
			// pod on a name collision.
			ns := s.Metric["namespace"]
			if ns == "" {
				continue
			}
			if podName != "" &&
				downscaledMemberPod(ns, podName, c.downscaled) {
				continue // parked cluster — stale series, not quorum evidence
			}
			key := ns + "/" + podName
			if podName == "" {
				key = "cluster/" + q.reason
			}
			if findings[key] == nil {
				findings[key] = map[string]bool{}
			}
			findings[key][q.reason] = true
		}
	}
	return findings
}

// rabbitLeaderlessFindings adds the quorum_leaderless signal — a
// quorum-queue Raft health check beyond the alarm queries:
//
// A member publishes rabbitmq_raft_role series for the quorum queues
// it replicates; when a member's series exist but its sum is 0,
// none of those queues currently sees it (or anyone, from this
// member's view) as leader — the queue cannot accept writes.
// Diffed client-side across two instant queries (the literal `and`
// form never matches: a ==0 comparison produces an empty vector on
// the leader side, and PromQL `and` intersects it away) — same
// shape as the NATS meta-leaderless check.
func rabbitLeaderlessFindings(ctx context.Context, d *probefw.Deps,
	log logr.Logger, c *rabbitCensus, findings map[string]map[string]bool) {
	counts, errC := d.PromQuery(ctx,
		`count by (namespace, pod) (rabbitmq_raft_role)`)
	sums, errS := d.PromQuery(ctx,
		`sum by (namespace, pod) (rabbitmq_raft_role)`)
	if errC != nil || errS != nil {
		log.Info("WARN: rabbitmq raft-role queries failed — quorum_leaderless signal skipped",
			"countErr", errC, "sumErr", errS)
		return
	}
	sumByPod := map[string]float64{}
	for _, s := range sums {
		sumByPod[s.Label("namespace")+"/"+s.Label("pod", "pod_name")] = s.Value
	}
	for _, s := range counts {
		podName := s.Label("pod", "pod_name")
		// Fail-closed like the alarm loop: no namespace label →
		// unattributable series, never resolved by bare pod name.
		ns := s.Metric["namespace"]
		if ns == "" {
			continue
		}
		if podName == "" || s.Value <= 0 {
			continue
		}
		if sumByPod[ns+"/"+podName] != 0 {
			continue // at least one queue leadership role held — healthy
		}
		if downscaledMemberPod(ns, podName, c.downscaled) {
			continue // parked cluster — stale series, not quorum evidence
		}
		key := ns + "/" + podName
		if findings[key] == nil {
			findings[key] = map[string]bool{}
		}
		findings[key]["quorum_leaderless"] = true
	}
}

// rabbitSkewFindings adds the quorum_skew signal — severe Raft-term
// lag: a member whose max rabbitmq_raft_term lags the cluster's
// highest term by >= 2 missed >= 2 elections — its WAL view is far
// behind the cluster's, and its queue replicas cannot vote
// meaningfully.
func rabbitSkewFindings(ctx context.Context, d *probefw.Deps,
	log logr.Logger, c *rabbitCensus, findings map[string]map[string]bool) {
	terms, errT := d.PromQuery(ctx,
		`max by (namespace, pod) (rabbitmq_raft_term)`)
	if errT != nil {
		log.Info("WARN: rabbitmq raft-term query failed — quorum_skew signal skipped",
			"error", errT)
		return
	}
	// Pool the max term per RabbitmqCLUSTER, not per namespace —
	// two clusters sharing one namespace must not judge each
	// other's terms (same hazard as the Ready-sibling census in
	// rabbitmq_quorum_heals.go, rabbitmq-quorum-heal): the younger
	// cluster's whole membership would lag the older cluster's term
	// and false-flag skew. Pods we cannot group cluster-wise fall
	// back to the namespace bucket (fail-safe, may over-flag) rather
	// than being skipped silently.
	maxTermByCluster := map[string]float64{}
	for _, s := range terms {
		podName := s.Label("pod", "pod_name")
		ns := s.Metric["namespace"]
		pod := c.byPodName[podName]
		if ns == "" && pod != nil {
			ns = pod.Namespace
		}
		ck := ns
		if pod != nil {
			if k := rabbitClusterKey(pod); k != "" {
				ck = k
			}
		}
		if s.Value > maxTermByCluster[ck] {
			maxTermByCluster[ck] = s.Value
		}
	}
	for _, s := range terms {
		podName := s.Label("pod", "pod_name")
		ns := s.Metric["namespace"]
		pod := c.byPodName[podName]
		if ns == "" && pod != nil {
			ns = pod.Namespace
		}
		if podName == "" || s.Value <= 0 {
			continue
		}
		ck := ns
		if pod != nil {
			if k := rabbitClusterKey(pod); k != "" {
				ck = k
			}
		}
		// Only judge members of clusters with a real term spread.
		if maxTermByCluster[ck]-s.Value < 2 {
			continue
		}
		if downscaledMemberPod(ns, podName, c.downscaled) {
			continue
		}
		key := ns + "/" + podName
		if findings[key] == nil {
			findings[key] = map[string]bool{}
		}
		findings[key]["quorum_skew"] = true
	}
}
