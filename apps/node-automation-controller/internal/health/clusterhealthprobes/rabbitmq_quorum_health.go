// rabbitmq_quorum_health.go — the rabbitmq-quorum-health check
// (W10-ST3): RabbitMQ alarms / Mnesia partition signals from
// Prometheus plus the stuck-unready pod heal while >=2 siblings
// stay Ready.
package clusterhealthprobes

import (
	"context"
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	logf "sigs.k8s.io/controller-runtime/pkg/log"
	ctrlmetrics "sigs.k8s.io/controller-runtime/pkg/metrics"

	"github.com/passiontech-global/kubernetes-node-automation/apps/node-automation-controller/internal/shared"
)

const (
	checkNameRabbitMQQuorum = "rabbitmq-quorum-health"

	// W10-ST3 — rabbitmq-quorum-health knobs.
	rabbitUnreadyMinAge  = 10 * time.Minute
	rabbitQuorumHealCool = 30 * time.Minute
)

var (
	// W10-ST3 — RabbitMQ quorum/partition signal.
	rabbitMQQuorumUnhealthyGauge = prometheus.NewGaugeVec(prometheus.GaugeOpts{
		Name: "node_automation_rabbitmq_quorum_unhealthy",
		Help: "1 while the RabbitMQ pod/cluster reports an alarm, partition or stuck-unready signature — W10-ST3.",
	}, []string{"namespace", "pod", "reason"})
)

func init() {
	ctrlmetrics.Registry.MustRegister(
		rabbitMQQuorumUnhealthyGauge)
}

// isRabbitMQPod reports whether the pod belongs to a RabbitMQ
// cluster — the operator stamps app.kubernetes.io/part-of=rabbitmq
// (stable across per-cluster renames) and
// app.kubernetes.io/component=rabbitmq.
func isRabbitMQPod(pod *corev1.Pod) bool {
	return pod.Labels["app.kubernetes.io/part-of"] == "rabbitmq" ||
		pod.Labels["app.kubernetes.io/component"] == "rabbitmq"
}

// checkRabbitMQQuorumHealth watches RabbitMQ quorum/partition
// health two ways: Prometheus alarms (fd-limit / memory / disk
// watermarks, erlang dist node_state != connected) and the
// stuck-unready pod signature — a rabbitmq pod unready >=10m while
// >=2 siblings stay Ready gets deleted (30m cooldown) so the
// cluster re-forms quorum around it.
func (p *clusterHealthProber) checkRabbitMQQuorumHealth(ctx context.Context) probeResult {
	log := logf.FromContext(ctx)
	now := p.now()

	pods, err := p.cs.CoreV1().Pods(metav1.NamespaceAll).
		List(ctx, metav1.ListOptions{})
	if err != nil {
		return probeResult{infra: fmt.Errorf("list pods: %w", err)}
	}
	rabbitByName := map[string]*corev1.Pod{}
	rabbitByPodName := map[string]*corev1.Pod{}
	rabbitByNS := map[string][]*corev1.Pod{}
	for i := range pods.Items {
		pod := &pods.Items[i]
		if !isRabbitMQPod(pod) {
			continue
		}
		rabbitByName[pod.Namespace+"/"+pod.Name] = pod
		rabbitByPodName[pod.Name] = pod // ns fallback for series w/o namespace label
		rabbitByNS[pod.Namespace] = append(rabbitByNS[pod.Namespace], pod)
	}

	// Prometheus alarm/partition signals.
	type sig struct{ q, reason string }
	queries := []sig{
		{`rabbitmq_alarms_file_descriptor_limit == 1`, "fd_limit_alarm"},
		{`rabbitmq_alarms_memory_used_watermark == 1`, "memory_watermark_alarm"},
		{`rabbitmq_alarms_free_disk_space_watermark == 1`, "disk_watermark_alarm"},
		{`erlang_vm_dist_node_state != 3`, "mnesia_partition"},
	}
	findings := map[string]map[string]bool{} // "ns/pod" -> reasons
	for _, q := range queries {
		series, err := p.promInstantQuery(ctx, q.q)
		if err != nil {
			log.Info("WARN: rabbitmq prom query failed — signal skipped",
				"query", q.q, "error", err)
			continue
		}
		for _, s := range series {
			podName := promLabelValue(s, "pod", "pod_name")
			ns := s.metric["namespace"]
			if ns == "" {
				if pod := rabbitByPodName[podName]; pod != nil {
					ns = pod.Namespace
				}
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

	// Ready-sibling census per namespace — the quorum precondition
	// for every heal below (>=2 OTHER replicas Ready).
	readyByNS := map[string]int{}
	for ns, members := range rabbitByNS {
		for _, pod := range members {
			if pod.DeletionTimestamp == nil &&
				pod.Status.Phase == corev1.PodRunning &&
				shared.PodReadyCond(pod) {
				readyByNS[ns]++
			}
		}
	}

	// Stuck-unready pod signature — independent of Prometheus.
	seenKeep := map[string]bool{}
	for ns, members := range rabbitByNS {
		for _, pod := range members {
			if pod.DeletionTimestamp != nil ||
				pod.Status.Phase == corev1.PodSucceeded ||
				pod.Status.Phase == corev1.PodFailed {
				continue
			}
			since, unready := podUnreadySince(pod)
			if !unready {
				continue
			}
			key := ns + "/" + pod.Name
			if now.Sub(since) < rabbitUnreadyMinAge {
				continue
			}
			if findings[key] == nil {
				findings[key] = map[string]bool{}
			}
			findings[key]["stuck_unready"] = true
			// Heal only when quorum survives: >=2 OTHER replicas
			// Ready — the unready pod itself is never Ready, so the
			// running-ready count already excludes it.
			if readyByNS[ns] >= 2 {
				p.deletePodHeal(ctx, log, checkNameRabbitMQQuorum,
					key, pod, rabbitQuorumHealCool, now)
			}
		}
	}

	// Prometheus-flagged pods (alarm / Mnesia partition) get the same
	// heal once the signal persists >=10m and quorum survives — a
	// partitioned-but-Ready member is exactly the "partitioned >10m"
	// shape the plan calls out. The shared cooldown key dedupes pods
	// already healed via the unready path.
	for key := range findings {
		pod, ok := rabbitByName[key]
		if !ok || pod.DeletionTimestamp != nil {
			continue
		}
		sig := "prom/" + key
		seenKeep[sig] = true
		first, _ := seenFirstStreak(checkNameRabbitMQQuorum, sig, now)
		if now.Sub(first) < rabbitUnreadyMinAge {
			continue
		}
		if readyByNS[pod.Namespace] >= 2 {
			p.deletePodHeal(ctx, log, checkNameRabbitMQQuorum,
				key, pod, rabbitQuorumHealCool, now)
		}
	}
	pruneSeenStreaks(checkNameRabbitMQQuorum, seenKeep)

	current := map[string][]string{}
	var out []string
	for key, reasons := range findings {
		rs := make([]string, 0, len(reasons))
		for r := range reasons {
			rs = append(rs, r)
		}
		sort.Strings(rs)
		parts := strings.SplitN(key, "/", 2)
		ns := parts[0]
		if pod, ok := rabbitByName[key]; ok {
			lv := []string{ns, pod.Name, strings.Join(rs, "+")}
			current[key+"/"+strings.Join(rs, "+")] = lv
			rabbitMQQuorumUnhealthyGauge.WithLabelValues(lv...).Set(1)
		}
		out = append(out, key+"("+strings.Join(rs, "+")+")")
	}
	sort.Strings(out)
	reconcileEmittedGauges(checkNameRabbitMQQuorum,
		rabbitMQQuorumUnhealthyGauge, current)
	if len(out) == 0 {
		return probeResult{pass: true}
	}
	return probeResult{why: "rabbitmq quorum/partition signals: " +
		strings.Join(out, ", ")}
}
