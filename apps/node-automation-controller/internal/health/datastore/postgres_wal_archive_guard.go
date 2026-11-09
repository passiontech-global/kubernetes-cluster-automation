// postgres_wal_archive_guard.go — the postgres-wal-archive-guard
// check: the WAL runaway signature across the three Postgres
// operator families (Percona pgv2, CloudNativePG, Percona Everest) —
// a stalled archiver, an inactive replication slot retaining WAL, a
// data volume filling past the threshold, or pg_wal disk-full crash
// evidence in pod logs. cnpg-health folds the CloudNativePG cluster-liveness
// guard in on top of the same CR scan: a failover phase wedged past
// CNPGUnhealthyMinAge, a ready<instances shortfall, or disabled
// continuous archiving flags node_automation_cnpg_cluster_unhealthy.
// Detection-only: nothing here execs, deletes or patches — the
// gauges are the alert contract.
package datastore

import (
	"context"
	"fmt"
	"io"
	"strings"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"golang.org/x/sync/errgroup"
	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/api/meta"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime/schema"
	logf "sigs.k8s.io/controller-runtime/pkg/log"
	ctrlmetrics "sigs.k8s.io/controller-runtime/pkg/metrics"

	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-automation-controller/internal/health/probefw"
	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-automation-controller/internal/platform/kube"
	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-automation-controller/internal/platform/state"
	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-automation-controller/internal/promq"
)

// postgresWALArchiveGuardCheck is the WAL-archive stall watchdog.
type postgresWALArchiveGuardCheck struct {
	*probefw.Deps

	// emitted is the emitted-gauge ledger — a tuple that stops
	// being reported gets DeleteLabelValues'd rather than leaking a
	// stale 1 (zero value usable; the serial sweep needs no lock).
	// emittedSlot is the same ledger for the percona-degraded-quorum slot-bloat
	// gauge — a slot that drains or goes active loses its series.
	// emittedCNPG is the cnpg-health cnpg_cluster_unhealthy ledger —
	// a cluster that recovers its phase/quorum/archiving loses the
	// series via DeleteLabelValues.
	emitted     state.GaugeLedger[string]
	emittedSlot state.GaugeLedger[string]
	emittedCNPG state.GaugeLedger[string]

	// cnpgSeen: "phase/ns/name" | "replicas/ns/name" | "primary/ns/name"
	// → first sweep the cnpg-health stuck-phase, under-replicated or
	// primary-mismatch signature held — each must persist
	// p.Cfg.Datastore.CNPGUnhealthyMinAge before it counts; pruned on
	// resolve so a flap re-arms.
	cnpgSeen state.FirstSeenLedger
	// cnpgFenceSeen: "fence/ns/name/instance" → first sweep the
	// cnpg.io/fencedInstances annotation carried that instance —
	// the auto-unfence heal only fires once the fence has persisted
	// CNPGUnhealthyMinAge (a fence the operator just stamped may be
	// mid-failover, not stale).
	cnpgFenceSeen state.FirstSeenLedger
}

// NewPostgresWALArchiveGuardCheck builds the WAL guard — its only
// state is the emitted-gauge ledger; the check is detection-only and
// carries no heal state.
func NewPostgresWALArchiveGuardCheck(d *probefw.Deps) probefw.Check {
	return &postgresWALArchiveGuardCheck{Deps: d}
}

const (
	CheckNamePostgresWALArchiveGuard = "postgres-wal-archive-guard"

	// postgres-wal-archive-guard knobs.
	pgArchiveCondMinAge = 30 * time.Minute
	pgWALSlotRetainMax  = int64(5 << 30) // 5GiB
	pgWALVolumeRatio    = 0.6

	// The per-pod log-fetch fan-out cap (Component 3 worker pool).
	postgresWALLogWorkers = 4
)

// postgresClusterLabels are the pod labels that bind a pod to its
// Postgres operator cluster — CNPG, Crunchy/Percona pgv2 and Everest
// each stamp a different one; the first non-empty wins.
var postgresClusterLabels = []string{
	"cnpg.io/cluster",
	"postgres-operator.crunchydata.com/cluster",
	"pgv2.percona.com/cluster",
	"everest.percona.com/cluster",
}

// postgresCRKinds is the cluster-CR census — each family's status
// conditions carry archive/backup health the operator already
// detected (CNPG ContinuousArchiving, Percona pgbackrest repo
// conditions, Everest backup posture).
var postgresCRKinds = []struct {
	kind string
	gvr  schema.GroupVersionResource
}{
	{"PerconaPGCluster", kube.GVRPerconaPGCluster},
	{"CNPGCluster", kube.GVRCNPGCluster},
	{"EverestDatabaseCluster", kube.GVREverestDatabaseCluster},
}

var (
	// Postgres clusters showing a WAL/archive unhealthy signature.
	postgresWALUnhealthyGauge = prometheus.NewGaugeVec(prometheus.GaugeOpts{
		Name: "node_automation_postgres_wal_archive_unhealthy",
		Help: "1 while the Postgres cluster shows a WAL/archive runaway signature (archive condition, archiver failure, retained slot WAL, volume pressure, disk-full crash evidence).",
	}, []string{"namespace", "cluster", "reason"})

	// percona-degraded-quorum — inactive replication slots retaining WAL, carried
	// with the slot name and the retained size the
	// wal_archive_unhealthy{reason=inactive_slot} flag cannot show.
	postgresInactiveSlotWALGauge = prometheus.NewGaugeVec(prometheus.GaugeOpts{
		Name: "node_automation_postgres_inactive_slot_wal_bloat",
		Help: "Retained WAL bytes behind an inactive replication slot (pg_replication_slots_active==0) past the 5GiB floor — the bloat that precedes the pg_wal disk-full crash.",
	}, []string{"namespace", "cluster", "slot"})

	// cnpg-health — a CloudNativePG Cluster.postgresql.cnpg.io whose
	// failover never lands (phase wedged Failing over / Waiting for
	// the instances to become active), whose ready instances stay
	// short of the declared count, or whose continuous archiving is
	// disabled. reason is stuck_phase | under_replicated |
	// archiving_disabled.
	cnpgClusterUnhealthyGauge = prometheus.NewGaugeVec(prometheus.GaugeOpts{
		Name: "node_automation_cnpg_cluster_unhealthy",
		Help: "1 while a CloudNativePG cluster is stuck mid-failover, under-replicated, or has continuous archiving disabled.",
	}, []string{"namespace", "name", "reason"})
)

func init() {
	ctrlmetrics.Registry.MustRegister(
		postgresWALUnhealthyGauge,
		postgresInactiveSlotWALGauge,
		cnpgClusterUnhealthyGauge)
}

// pgWALConditionUnhealthy reports whether a cluster CR condition is
// archive/backup evidence: a condition type containing archiv/backup/
// wal whose status is False past pgArchiveCondMinAge.
func pgWALConditionUnhealthy(c kube.Condition, now time.Time) bool {
	t := strings.ToLower(c.Type)
	if !strings.Contains(t, "archiv") &&
		!strings.Contains(t, "backup") &&
		!strings.Contains(t, "wal") {
		return false
	}
	if c.Status != "False" {
		return false
	}
	return !c.LastTransitionTime.IsZero() &&
		now.Sub(c.LastTransitionTime) >= pgArchiveCondMinAge
}

// pgWALLogReason matches the log-line signatures of a WAL runaway —
// archiver failures, retained replication-slot WAL and the disk-full
// crash Postgres panics with when pg_wal fills the volume.
func pgWALLogReason(line string) string {
	l := strings.ToLower(line)
	switch {
	case strings.Contains(l, "pg_wal") &&
		(strings.Contains(l, "no space left on device") ||
			strings.Contains(l, "could not write to file")):
		return "wal_disk_full"
	case strings.Contains(l, "archive command failed") ||
		strings.Contains(l, "archiver failed") ||
		(strings.Contains(l, "archive") && strings.Contains(l, "fail") &&
			strings.Contains(l, "wal")):
		return "archiver_failing"
	case strings.Contains(l, "replication slot") &&
		(strings.Contains(l, "inactive") || strings.Contains(l, "retain")):
		return "inactive_slot"
	}
	return ""
}

// pgWALLogSinceWindow bounds the log read: the disk-full/archiver
// signatures only matter while recent (an unbounded tail can span
// the pod's whole lifetime and re-flag a crash that predates every
// other signal in this sweep), so the fetch passes SinceSeconds
// alongside the tail bound — the apiserver ANDs the two.
const pgWALLogSinceWindow = 30 * time.Minute

// pgWALLogHit fetches the postgres container's log tail (bounded by
// TailLines AND SinceSeconds) and returns the first matching WAL
// signature — a fetch failure is inconclusive, not healthy. The
// matched reason rides out through the match closure. This mirrors
// probefw.PodLogTail with the extra SinceSeconds option the shared
// helper does not carry (its other consumers scan whole-lifetime
// signatures by design).
func (p *postgresWALArchiveGuardCheck) pgWALLogHit(ctx context.Context,
	pod *corev1.Pod) (string, error) {

	container := ""
	if kube.PodSpecHasContainer(&pod.Spec, "postgres") {
		container = "postgres"
	} else if len(pod.Spec.Containers) == 1 {
		container = pod.Spec.Containers[0].Name
	} else {
		return "", nil // no unambiguous postgres container — skip
	}
	opts := pgWALLogOptions(container)
	lctx, cancel := context.WithTimeout(ctx, probefw.LogTimeout)
	defer cancel()
	stream, err := p.CS.CoreV1().Pods(pod.Namespace).GetLogs(pod.Name,
		opts).Stream(lctx)
	if err != nil {
		return "", err
	}
	defer func() { _ = stream.Close() }()
	data, err := io.ReadAll(io.LimitReader(stream, probefw.LogMaxBytes))
	if err != nil {
		return "", err
	}
	var reason string
	for _, line := range strings.Split(string(data), "\n") {
		if r := pgWALLogReason(line); r != "" {
			reason = r
			break
		}
	}
	return reason, nil
}

// pgWALLogOptions builds the bounded pod-log read: the tail bound
// AND the SinceSeconds bound (separate for tests — the fake
// clientset reactor cannot surface the options).
func pgWALLogOptions(container string) *corev1.PodLogOptions {
	tail := probefw.DefaultTailLines
	since := int64(pgWALLogSinceWindow.Seconds())
	return &corev1.PodLogOptions{
		Container:    container,
		TailLines:    &tail,
		SinceSeconds: &since,
	}
}

// postgresClusterOf returns the operator cluster a postgres pod
// belongs to — "" when none of the known labels apply.
func postgresClusterOf(pod *corev1.Pod) string {
	for _, label := range postgresClusterLabels {
		if v := pod.Labels[label]; v != "" {
			return v
		}
	}
	return ""
}

// checkPostgresWALArchiveGuard gathers WAL-runaway evidence on four
// fronts — CR archive conditions (>=30m), postgres pod log
// signatures, Prometheus archiver-failure/inactive-slot counters and
// data-volume fill ratios — and reports each on
// node_automation_postgres_wal_archive_unhealthy. Nothing is healed:
// archive repair needs pgbackrest/slot surgery that must stay an
// operator decision; the check's job is making the stall visible
// before the volume actually fills.
func (p *postgresWALArchiveGuardCheck) Run(ctx context.Context) probefw.Result {
	if r := p.RequireDyn("postgres wal archive guard"); r != nil {
		return *r
	}
	log := logf.FromContext(ctx)
	now := p.Now()

	type finding struct {
		ns, cluster, reason string
	}
	var rep probefw.SweepReport
	findings := map[string]finding{}
	emit := func(ns, cluster, reason string) {
		if cluster == "" {
			cluster = "-"
		}
		findings[ns+"/"+cluster+"/"+reason] = finding{ns, cluster, reason}
	}

	// (a) CR conditions — the operator's own archive/backup verdicts.
	var cnpgClusters []*unstructured.Unstructured
	for _, rk := range postgresCRKinds {
		items, err := p.AllUnstructured(ctx, rk.gvr)
		switch {
		case apierrors.IsNotFound(err) || meta.IsNoMatchError(err):
			continue
		case err != nil:
			return probefw.Result{Infra: fmt.Errorf("list %s: %w", rk.gvr.Resource, err)}
		}
		for i := range items {
			cr := &items[i]
			// cnpg-health — CNPG clusters get the dedicated cluster-health
			// pass below on top of the archive-condition scan.
			if rk.gvr == kube.GVRCNPGCluster {
				cnpgClusters = append(cnpgClusters, cr)
			}
			for _, c := range kube.Conditions(cr.Object, "status", "conditions") {
				if pgWALConditionUnhealthy(c, now) {
					emit(cr.GetNamespace(), cr.GetName(), "archive_condition")
				}
			}
		}
	}

	// (b) pod logs — crash/stall evidence the CR status cannot see.
	// The fetches run through a bounded worker pool (max
	// postgresWALLogWorkers concurrent kubelet log streams) so a
	// fleet of postgres pods cannot stampede the apiserver's log
	// proxy; the results are applied serially below.
	pods, err := p.AllPods(ctx)
	if err != nil {
		return probefw.Result{Infra: fmt.Errorf("list pods: %w", err)}
	}
	pgPVCs := map[string]string{} // "ns/pvc" -> owning operator cluster
	var scanIdx []int
	for i := range pods {
		pod := &pods[i]
		cluster := postgresClusterOf(pod)
		if cluster == "" {
			continue
		}
		for _, v := range pod.Spec.Volumes {
			if v.PersistentVolumeClaim != nil &&
				pgPVCs[pod.Namespace+"/"+v.PersistentVolumeClaim.ClaimName] == "" {
				pgPVCs[pod.Namespace+"/"+v.PersistentVolumeClaim.ClaimName] = cluster
			}
		}
		if pod.DeletionTimestamp != nil || pod.Status.Phase == corev1.PodSucceeded {
			continue
		}
		scanIdx = append(scanIdx, i)
	}
	type logScan struct {
		reason string
		err    error
	}
	scans := make([]logScan, len(scanIdx))
	g := errgroup.Group{}
	g.SetLimit(postgresWALLogWorkers)
	for j, i := range scanIdx {
		pod := pods[i]
		g.Go(func() error {
			reason, lerr := p.pgWALLogHit(ctx, &pod)
			scans[j] = logScan{reason: reason, err: lerr}
			return nil // tolerated sub-failure — applied below
		})
	}
	_ = g.Wait()
	for j, i := range scanIdx {
		pod := &pods[i]
		key := pod.Namespace + "/" + pod.Name
		if scans[j].err != nil {
			log.Info("WARN: postgres log fetch failed — WAL signature inconclusive",
				"pod", key, "error", scans[j].err)
			continue
		}
		if scans[j].reason != "" {
			emit(pod.Namespace, postgresClusterOf(pod), scans[j].reason)
		}
	}

	// (c) Prometheus — archiver failure counters and retained slot
	// WAL; a dead Prometheus is inconclusive (http-content-check owns
	// liveness), never a false FAIL.
	if series, qerr := p.PromQuery(ctx,
		`(increase(pg_stat_archiver_failed_count[30m]) > 0) or `+
			`(increase(cnpg_pg_stat_archiver_failed_count[30m]) > 0)`); qerr != nil {
		log.Info("WARN: pg_stat_archiver query failed — archiver evidence incomplete",
			"error", qerr)
	} else {
		for _, s := range series {
			emit(s.Label("namespace"),
				s.Label("cluster", "postgres_cluster", "pod"), "archiver_failing")
		}
	}
	var slotRep probefw.SweepReport
	if series, qerr := p.PromQuery(ctx, fmt.Sprintf(
		`(pg_replication_slots_retained_bytes{active="false"} > %d) or `+
			`(cnpg_pg_replication_slots_retained_bytes{active="false"} > %d)`,
		pgWALSlotRetainMax, pgWALSlotRetainMax)); qerr != nil {
		log.Info("WARN: replication slot query failed — slot evidence incomplete",
			"error", qerr)
	} else {
		for _, s := range series {
			emit(s.Label("namespace"),
				s.Label("cluster", "postgres_cluster", "pod"), "inactive_slot")
			p.emitSlotBloat(&slotRep, &rep, s)
		}
	}
	// percona-degraded-quorum — the postgres_exporter spelling of the same
	// signature: the active flag and the retained-bytes diff live on
	// separate series joined by the slot labels. `and` returns the
	// active==0 samples themselves (value 0) — the bloat gauge
	// flags 1 since this exporter family can't give a byte count.
	if series, qerr := p.PromQuery(ctx, fmt.Sprintf(
		`(pg_replication_slots_active == 0) and on(namespace, pod, slot_name) `+
			`(pg_replication_slots_pg_wal_lsn_diff > %d or `+
			`pg_replication_slots_confirmed_flush_lsn_wal_lsn_diff > %d)`,
		pgWALSlotRetainMax, pgWALSlotRetainMax)); qerr != nil {
		log.Info("WARN: active-flag slot query failed — slot-bloat evidence incomplete",
			"error", qerr)
	} else {
		for _, s := range series {
			emit(s.Label("namespace"),
				s.Label("cluster", "postgres_cluster", "pod"), "inactive_slot")
			p.emitSlotBloat(&slotRep, &rep, s)
		}
	}
	// Volume pressure: the data volume a postgres pod mounts above
	// 60% is the pg_wal runaway we CAN see without exec — the WAL dir
	// lives on that volume and no other signal reaches inside it.
	if series, qerr := p.PromQuery(ctx,
		`kubelet_volume_stats_used_bytes / kubelet_volume_stats_capacity_bytes > `+
			fmt.Sprintf("%.2f", pgWALVolumeRatio)); qerr != nil {
		log.Info("WARN: volume stats query failed — volume evidence incomplete",
			"error", qerr)
	} else {
		for _, s := range series {
			ns := s.Label("namespace")
			pvc := s.Label("persistentvolumeclaim")
			// The finding's entity is the CLUSTER, not the PVC —
			// the gauge series are per operator cluster, and the
			// claim name is an implementation detail of the
			// operator's volume layout (heal-budget: emitting the PVC name
			// produced series that match no alert label set).
			if cluster := pgPVCs[ns+"/"+pvc]; cluster != "" {
				emit(ns, cluster, "wal_volume_pressure")
			}
		}
	}

	// cnpg-health — CloudNativePG cluster liveness: a wedged failover
	// phase, a ready<count shortfall or disabled continuous archiving
	// ride their own gauge — the WAL signatures above say the
	// archiver is sick, these say the cluster underneath is.
	p.checkCNPGClusterHealth(ctx, log, &rep, cnpgClusters, now)

	for k, f := range findings {
		rep.Emit(postgresWALUnhealthyGauge, k,
			[]string{f.ns, f.cluster, f.reason}, k)
	}
	slotRep.Close(&p.emittedSlot, postgresInactiveSlotWALGauge.DeleteLabelValues)
	return rep.Result(&p.emitted, postgresWALUnhealthyGauge.DeleteLabelValues,
		"postgres wal/archive unhealthy: ", ", ")
}

// emitSlotBloat flags one inactive-slot sample on the percona-degraded-quorum
// slot-bloat gauge and records the finding on the shared report.
// The value is the retained byte count where the exporter reports
// one (retained_bytes / lsn-diff families); the `and`-joined
// active-flag spelling returns value-0 samples, which flag 1 — a
// boolean "this slot is bloated" when no byte count exists.
func (p *postgresWALArchiveGuardCheck) emitSlotBloat(
	slotRep, rep *probefw.SweepReport, s promq.Sample) {

	ns := s.Label("namespace")
	cluster := s.Label("cluster", "postgres_cluster", "pod")
	if cluster == "" {
		cluster = "-"
	}
	slot := s.Label("slot_name", "slot")
	if slot == "" {
		slot = "-"
	}
	val := s.Value
	if val <= 0 {
		val = 1
	}
	key := ns + "/" + cluster + "/" + slot
	slotRep.Set(postgresInactiveSlotWALGauge, val, key,
		[]string{ns, cluster, slot})
	rep.Find(fmt.Sprintf("%s/%s slot %s inactive retaining %.1fGiB WAL",
		ns, cluster, slot, s.Value/float64(1<<30)))
}
