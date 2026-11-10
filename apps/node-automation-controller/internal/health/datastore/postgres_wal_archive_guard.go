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
	corev1 "k8s.io/api/core/v1"
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
// detected. pgWALConds is the family's real archive/backup condition
// types (exact-matched by pgWALConditionUnhealthy); pgCondBareFallback
// marks families whose condition types are NOT a closed documented
// enum, so unknown archiv/backup/wal-ish types still substring-match
// there (see pgWALConditionUnhealthy).
var postgresCRKinds = []struct {
	kind string
	gvr  schema.GroupVersionResource
	// pgWALConds: the condition types this family's operator
	// publishes for archive/backup health, False = the WAL-runaway
	// evidence this check exists to surface.
	pgWALConds []string
	// pgCondBareFallback: unknown archiv/backup/wal-ish condition
	// types still count on this family (see pgWALConditionUnhealthy).
	pgCondBareFallback bool
}{
	// Percona Operator for PostgreSQL — the documented
	// status.conditions[].type set. The old bare substring net only
	// ever caught the two types whose spelling contains "backup"
	// ("pgbackrest..." does NOT — "backrest" is not "backup"), so the
	// exact list is exactly that prior coverage: the
	// restore/replica/TLS/repo-host conditions stay out (False there
	// is a normal in-flight state, not WAL evidence).
	{"PerconaPGCluster", kube.GVRPerconaPGCluster, []string{
		"ReadyForBackup",                   // False: repo host not ready / no replica-create backup
		"PGBackRestManualBackupSuccessful", // False: latest on-demand backup failed
	}, false},
	// CloudNativePG — ConditionContinuousArchiving /
	// ConditionBackup (= "LastBackupSucceeded") in the operator's
	// API (api/v1 cluster_types.go).
	{"CNPGCluster", kube.GVRCNPGCluster, []string{
		"ContinuousArchiving", // False: WAL archiving failing
		"LastBackupSucceeded", // False: last backup failed
	}, false},
	// Everest — the databaseclusters CRD's condition set is not a
	// documented closed enum (the operator's own backup posture rides
	// versioned types that drift), so unknown archiv/backup/wal-ish
	// types keep the bare substring net here: the check is
	// detection-only and a missed stall is the expensive failure.
	{"EverestDatabaseCluster", kube.GVREverestDatabaseCluster, nil, true},
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
// archive/backup evidence. The primary gate is an EXACT match
// (case-insensitive) against the family's real condition types —
// operators publish benign custom conditions whose type merely
// contains "backup"/"wal" ("BackupScheduleConfigured"), and the old
// bare substring match flagged them. conds carries the scanned
// family's pgWALConds set; bareFallback keeps the archiv/backup/wal
// substring list alive ONLY for families whose condition types are
// not a documented closed enum (Everest — see postgresCRKinds), so
// an undocumented type spelling still surfaces there. A matched
// condition flags when its status is False past pgArchiveCondMinAge.
func pgWALConditionUnhealthy(c kube.Condition, conds []string,
	bareFallback bool, now time.Time) bool {
	if !walCondTypeMatch(c.Type, conds, bareFallback) {
		return false
	}
	if c.Status != "False" {
		return false
	}
	return !c.LastTransitionTime.IsZero() &&
		now.Sub(c.LastTransitionTime) >= pgArchiveCondMinAge
}

// walCondTypeMatch exact-matches the condition type against the
// family's known archive/backup types (lowercased — operators are
// consistent about their own enum spellings but tests read either),
// falling back to the archiv/backup/wal substring list only where
// the family opted into the bare net.
func walCondTypeMatch(typ string, conds []string, bareFallback bool) bool {
	t := strings.ToLower(typ)
	for _, cond := range conds {
		if t == strings.ToLower(cond) {
			return true
		}
	}
	if !bareFallback {
		return false
	}
	return strings.Contains(t, "archiv") ||
		strings.Contains(t, "backup") ||
		strings.Contains(t, "wal")
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
// before the volume actually fills. Evidence collection lives in
// postgres_wal_archive_guard_scan.go.
func (p *postgresWALArchiveGuardCheck) Run(ctx context.Context) probefw.Result {
	if r := p.RequireDyn("postgres wal archive guard"); r != nil {
		return *r
	}
	log := logf.FromContext(ctx)
	now := p.Now()

	var rep probefw.SweepReport
	s := newWALGuardSweep(p, log, now, &rep)

	// (a) CR conditions — the operator's own archive/backup verdicts.
	cnpgClusters, err := s.scanCRConditions(ctx)
	if err != nil {
		return probefw.Result{Infra: err}
	}

	// (b) pod logs — crash/stall evidence the CR status cannot see.
	if err := s.scanPodLogs(ctx); err != nil {
		return probefw.Result{Infra: err}
	}

	// (c) Prometheus — archiver failure counters and retained slot
	// WAL; a dead Prometheus is inconclusive (http-content-check owns
	// liveness), never a false FAIL.
	s.scanPromSignals(ctx)

	// cnpg-health — CloudNativePG cluster liveness: a wedged failover
	// phase, a ready<count shortfall or disabled continuous archiving
	// ride their own gauge — the WAL signatures above say the
	// archiver is sick, these say the cluster underneath is.
	p.checkCNPGClusterHealth(ctx, log, &rep, cnpgClusters, now)

	for k, f := range s.findings {
		rep.Emit(postgresWALUnhealthyGauge, k,
			[]string{f.ns, f.cluster, f.reason}, k)
	}
	s.slotRep.Close(&p.emittedSlot, postgresInactiveSlotWALGauge.DeleteLabelValues)
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
