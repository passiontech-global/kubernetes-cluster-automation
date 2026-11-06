// scylla_compaction_schema_guard.go — the
// scylla-compaction-schema-guard check: scrapes each Ready member
// pod's :9180/metrics for a compaction backlog (>100 pending) and a
// coordinator schema-version split across members of the same
// cluster — both signatures the ScyllaCluster CR status can't see.
// Detection-only: no heals, the gauges are the alert contract.
package datastore

import (
	"context"
	"fmt"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	logf "sigs.k8s.io/controller-runtime/pkg/log"
	ctrlmetrics "sigs.k8s.io/controller-runtime/pkg/metrics"

	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-automation-controller/internal/health/probefw"
	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-automation-controller/internal/platform/kube"
	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-automation-controller/internal/platform/state"
)

// scyllaCompactionSchemaGuardCheck is the compaction/schema
// split-brain watchdog.
type scyllaCompactionSchemaGuardCheck struct {
	*probefw.Deps

	// emittedBacklog/emittedSplit are the emitted-gauge ledgers —
	// tuples that stop being reported get DeleteLabelValues'd rather
	// than leaking stale values (zero value usable; the serial sweep
	// needs no lock).
	emittedBacklog state.GaugeLedger[string]
	emittedSplit   state.GaugeLedger[string]
}

// NewScyllaCompactionSchemaGuardCheck builds the guard — its only
// state is the two emitted-gauge ledgers; the check is
// detection-only and carries no heal state.
func NewScyllaCompactionSchemaGuardCheck(d *probefw.Deps) probefw.Check {
	return &scyllaCompactionSchemaGuardCheck{Deps: d}
}

const (
	CheckNameScyllaCompactionSchemaGuard = "scylla-compaction-schema-guard"

	// scylla-compaction-schema-guard knobs.
	scyllaCompactionBacklogMax = 100
	scyllaMetricsPort          = 9180
	scyllaMetricsTimeout       = 8 * time.Second
)

var (
	// Compaction backlog per member pod.
	scyllaCompactionBacklogGauge = prometheus.NewGaugeVec(prometheus.GaugeOpts{
		Name: "node_automation_scylla_compaction_backlog",
		Help: "scylla_compaction_manager_pending_compactions per member pod — >100 means compaction cannot keep up.",
	}, []string{"namespace", "pod"})

	// Coordinator schema-version split across a cluster's members.
	scyllaSchemaSplitGauge = prometheus.NewGaugeVec(prometheus.GaugeOpts{
		Name: "node_automation_scylla_schema_split",
		Help: "1 while members of the cluster report divergent coordinator schema versions.",
	}, []string{"namespace", "cluster"})
)

func init() {
	ctrlmetrics.Registry.MustRegister(
		scyllaCompactionBacklogGauge,
		scyllaSchemaSplitGauge)
}

// scyllaPodMetrics fetches the pod's :9180/metrics and returns the
// compaction backlog (max sample) plus the set of coordinator schema
// versions it reports. ok=false on fetch/parse failure —
// inconclusive, not healthy (a dead endpoint and a sick pod are
// indistinguishable from here).
func (p *scyllaCompactionSchemaGuardCheck) scyllaPodMetrics(ctx context.Context,
	pod *corev1.Pod) (backlog float64, versions map[float64]bool, ok bool) {

	body, err := probefw.FetchPodMetrics(ctx, p.HTTPClient,
		pod.Status.PodIP, scyllaMetricsPort, scyllaMetricsTimeout, 4<<20)
	if err != nil {
		return 0, nil, false
	}
	text := string(body)
	for _, v := range probefw.ParseMetricValues(text,
		"scylla_compaction_manager_pending_compactions") {
		if v > backlog {
			backlog = v
		}
	}
	versions = map[float64]bool{}
	for _, v := range probefw.ParseMetricValues(text,
		"scylla_storage_proxy_coordinator_schema_version") {
		versions[v] = true
	}
	return backlog, versions, true
}

// checkScyllaCompactionSchemaGuard scrapes every Ready
// ScyllaCluster member's metrics endpoint: a pending-compactions
// count above scyllaCompactionBacklogMax means the cluster is
// drowning in compaction debt (sstable reads degrade every query
// path), and divergent coordinator schema versions across members
// mean a schema change stalled mid-propagation — the split-brain
// that drops writes on the minority side.
func (p *scyllaCompactionSchemaGuardCheck) Run(ctx context.Context) probefw.Result {
	log := logf.FromContext(ctx)
	pods, err := p.CS.CoreV1().Pods(metav1.NamespaceAll).
		List(ctx, metav1.ListOptions{})
	if err != nil {
		return probefw.Result{Infra: fmt.Errorf("list pods: %w", err)}
	}

	// cluster -> namespace -> distinct schema versions across members.
	clusterVersions := map[string]map[string]map[float64]bool{}
	var backlogRep probefw.SweepReport
	for i := range pods.Items {
		pod := &pods.Items[i]
		cluster := pod.Labels[scyllaClusterLabel]
		if cluster == "" || pod.DeletionTimestamp != nil ||
			pod.Status.Phase != corev1.PodRunning ||
			!kube.PodReadyCond(pod) {
			continue
		}
		backlog, versions, ok := p.scyllaPodMetrics(ctx, pod)
		if !ok {
			// A dead metrics endpoint is inconclusive — the pod may
			// be mid-restart; never read as healthy OR sick.
			log.Info("WARN: scylla pod metrics fetch failed — compaction/schema evidence inconclusive",
				"pod", pod.Namespace+"/"+pod.Name)
			continue
		}
		if backlog > scyllaCompactionBacklogMax {
			backlogRep.Set(scyllaCompactionBacklogGauge, backlog,
				pod.Namespace+"/"+pod.Name,
				[]string{pod.Namespace, pod.Name})
			backlogRep.Find(fmt.Sprintf(
				"%s/%s=%.0f", pod.Namespace, pod.Name, backlog))
		}
		ck := pod.Namespace + "/" + cluster
		set := clusterVersions[ck]
		if set == nil {
			set = map[string]map[float64]bool{}
			clusterVersions[ck] = set
		}
		set[pod.Name] = versions
	}

	var splitRep probefw.SweepReport
	for ck, members := range clusterVersions {
		distinct := map[float64]bool{}
		for _, versions := range members {
			for v := range versions {
				distinct[v] = true
			}
		}
		if len(distinct) <= 1 {
			continue
		}
		ns, cluster, _ := strings.Cut(ck, "/")
		splitRep.Set(scyllaSchemaSplitGauge, 1, ck, []string{ns, cluster})
		var vs []string
		for v := range distinct {
			vs = append(vs, strconv.FormatFloat(v, 'f', -1, 64))
		}
		sort.Strings(vs)
		splitRep.Find(fmt.Sprintf("%s versions=[%s]", ck, strings.Join(vs, ",")))
	}

	backlogRep.Close(&p.emittedBacklog, scyllaCompactionBacklogGauge.DeleteLabelValues)
	splitRep.Close(&p.emittedSplit, scyllaSchemaSplitGauge.DeleteLabelValues)
	var parts []string
	if findings := backlogRep.Sorted(); len(findings) > 0 {
		parts = append(parts, fmt.Sprintf("compaction backlog >%d: %s",
			scyllaCompactionBacklogMax, strings.Join(findings, ", ")))
	}
	if findings := splitRep.Sorted(); len(findings) > 0 {
		parts = append(parts, "schema splits: "+strings.Join(findings, ", "))
	}
	if len(parts) == 0 {
		return probefw.Result{Pass: true}
	}
	return probefw.Result{Why: strings.Join(parts, " | ")}
}
