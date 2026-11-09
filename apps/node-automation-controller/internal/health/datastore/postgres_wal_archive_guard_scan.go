// postgres_wal_archive_guard_scan.go — the evidence-collection half
// of the postgres-wal-archive-guard check: the three Postgres
// operator families' archive/backup CR conditions, the postgres pod
// log-tail signatures (bounded worker pool), and the Prometheus
// archiver/slot/volume signals, all folded into one findings map
// the Run emit phase reads. Split out of
// postgres_wal_archive_guard.go — see that file for the check.
package datastore

import (
	"context"
	"fmt"
	"time"

	"github.com/go-logr/logr"
	"golang.org/x/sync/errgroup"
	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/api/meta"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"

	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-automation-controller/internal/health/probefw"
	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-automation-controller/internal/platform/kube"
)

// walFinding is one (ns, cluster, reason) unhealthy tuple.
type walFinding struct {
	ns, cluster, reason string
}

// walGuardSweep carries one sweep's evidence state: the report the
// findings emit into, the slot-bloat report, the deduped findings
// map, and the PVC→cluster map the volume-pressure signal resolves
// through.
type walGuardSweep struct {
	p        *postgresWALArchiveGuardCheck
	log      logr.Logger
	now      time.Time
	rep      *probefw.SweepReport
	slotRep  probefw.SweepReport
	findings map[string]walFinding
	pgPVCs   map[string]string // "ns/pvc" -> owning operator cluster
}

func newWALGuardSweep(p *postgresWALArchiveGuardCheck, log logr.Logger,
	now time.Time, rep *probefw.SweepReport) *walGuardSweep {
	return &walGuardSweep{
		p:        p,
		log:      log,
		now:      now,
		rep:      rep,
		findings: map[string]walFinding{},
		pgPVCs:   map[string]string{},
	}
}

// emit records one unhealthy tuple, deduped on "ns/cluster/reason";
// an empty cluster reads "-" so the gauge label set stays stable.
func (s *walGuardSweep) emit(ns, cluster, reason string) {
	if cluster == "" {
		cluster = "-"
	}
	s.findings[ns+"/"+cluster+"/"+reason] = walFinding{ns, cluster, reason}
}

// scanCRConditions runs front (a): the operator's own
// archive/backup verdicts on the three cluster-CR families. An
// absent CRD kind is skipped; a real list error is Infra. CNPG
// clusters are collected for the dedicated cnpg-health pass.
func (s *walGuardSweep) scanCRConditions(ctx context.Context) (
	[]*unstructured.Unstructured, error) {
	var cnpgClusters []*unstructured.Unstructured
	for _, rk := range postgresCRKinds {
		items, err := s.p.AllUnstructured(ctx, rk.gvr)
		switch {
		case apierrors.IsNotFound(err) || meta.IsNoMatchError(err):
			continue
		case err != nil:
			return nil, fmt.Errorf("list %s: %w", rk.gvr.Resource, err)
		}
		for i := range items {
			cr := &items[i]
			// cnpg-health — CNPG clusters get the dedicated cluster-health
			// pass on top of the archive-condition scan.
			if rk.gvr == kube.GVRCNPGCluster {
				cnpgClusters = append(cnpgClusters, cr)
			}
			for _, c := range kube.Conditions(cr.Object, "status", "conditions") {
				if pgWALConditionUnhealthy(c, s.now) {
					s.emit(cr.GetNamespace(), cr.GetName(), "archive_condition")
				}
			}
		}
	}
	return cnpgClusters, nil
}

// scanPodLogs runs front (b): the crash/stall evidence the CR
// status cannot see. The fetches run through a bounded worker pool
// (max postgresWALLogWorkers concurrent kubelet log streams) so a
// fleet of postgres pods cannot stampede the apiserver's log proxy;
// the results are applied serially below. The same pass builds the
// PVC→cluster map the volume-pressure signal resolves through.
func (s *walGuardSweep) scanPodLogs(ctx context.Context) error {
	pods, err := s.p.AllPods(ctx)
	if err != nil {
		return fmt.Errorf("list pods: %w", err)
	}
	var scanIdx []int
	for i := range pods {
		pod := &pods[i]
		cluster := postgresClusterOf(pod)
		if cluster == "" {
			continue
		}
		for _, v := range pod.Spec.Volumes {
			if v.PersistentVolumeClaim != nil &&
				s.pgPVCs[pod.Namespace+"/"+v.PersistentVolumeClaim.ClaimName] == "" {
				s.pgPVCs[pod.Namespace+"/"+v.PersistentVolumeClaim.ClaimName] = cluster
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
			reason, lerr := s.p.pgWALLogHit(ctx, &pod)
			scans[j] = logScan{reason: reason, err: lerr}
			return nil // tolerated sub-failure — applied below
		})
	}
	_ = g.Wait()
	for j, i := range scanIdx {
		pod := &pods[i]
		key := pod.Namespace + "/" + pod.Name
		if scans[j].err != nil {
			s.log.Info("WARN: postgres log fetch failed — WAL signature inconclusive",
				"pod", key, "error", scans[j].err)
			continue
		}
		if scans[j].reason != "" {
			s.emit(pod.Namespace, postgresClusterOf(pod), scans[j].reason)
		}
	}
	return nil
}

// scanPromSignals runs front (c): the Prometheus archiver-failure
// counters, the retained/inactive replication-slot WAL families
// (four spellings — retained_bytes, lsn-diff, the active-flag
// joins and the CNPG exporter variant), and the data-volume fill
// ratio. A dead Prometheus is inconclusive (http-content-check owns
// liveness), never a false FAIL — every query failure warns and
// skips its own signal.
func (s *walGuardSweep) scanPromSignals(ctx context.Context) {
	if series, qerr := s.p.PromQuery(ctx,
		`(increase(pg_stat_archiver_failed_count[30m]) > 0) or `+
			`(increase(cnpg_pg_stat_archiver_failed_count[30m]) > 0)`); qerr != nil {
		s.log.Info("WARN: pg_stat_archiver query failed — archiver evidence incomplete",
			"error", qerr)
	} else {
		for _, series := range series {
			s.emit(series.Label("namespace"),
				series.Label("cluster", "postgres_cluster", "pod"), "archiver_failing")
		}
	}
	if series, qerr := s.p.PromQuery(ctx, fmt.Sprintf(
		`(pg_replication_slots_retained_bytes{active="false"} > %d) or `+
			`(cnpg_pg_replication_slots_retained_bytes{active="false"} > %d)`,
		pgWALSlotRetainMax, pgWALSlotRetainMax)); qerr != nil {
		s.log.Info("WARN: replication slot query failed — slot evidence incomplete",
			"error", qerr)
	} else {
		for _, series := range series {
			s.emit(series.Label("namespace"),
				series.Label("cluster", "postgres_cluster", "pod"), "inactive_slot")
			s.p.emitSlotBloat(&s.slotRep, s.rep, series)
		}
	}
	// percona-degraded-quorum — the postgres_exporter spelling of the same
	// signature: the active flag and the retained-bytes diff live on
	// separate series joined by the slot labels. `and` returns the
	// active==0 samples themselves (value 0) — the bloat gauge
	// flags 1 since this exporter family can't give a byte count.
	if series, qerr := s.p.PromQuery(ctx, fmt.Sprintf(
		`(pg_replication_slots_active == 0) and on(namespace, pod, slot_name) `+
			`(pg_replication_slots_pg_wal_lsn_diff > %d or `+
			`pg_replication_slots_confirmed_flush_lsn_wal_lsn_diff > %d)`,
		pgWALSlotRetainMax, pgWALSlotRetainMax)); qerr != nil {
		s.log.Info("WARN: active-flag slot query failed — slot-bloat evidence incomplete",
			"error", qerr)
	} else {
		for _, series := range series {
			s.emit(series.Label("namespace"),
				series.Label("cluster", "postgres_cluster", "pod"), "inactive_slot")
			s.p.emitSlotBloat(&s.slotRep, s.rep, series)
		}
	}
	// W20-ST2 — the CNPG exporter's own spelling of the same
	// signature: cnpg_pg_replication_slots_active==0 joined to high
	// retained WAL catches the inactive slot even while WAL
	// archiving still reports green (the retained_bytes{active=
	// "false"} branch above only sees slots the exporter already
	// marks inactive; this one catches the lag between the active
	// gauge and the retained-bytes label). `and` returns the
	// active==0 samples (value 0) — emitSlotBloat flags 1.
	if series, qerr := s.p.PromQuery(ctx, fmt.Sprintf(
		`(cnpg_pg_replication_slots_active == 0) and on(namespace, pod, slot_name) `+
			`(cnpg_pg_replication_slots_retained_bytes > %d or `+
			`cnpg_pg_replication_slots_pg_wal_lsn_diff > %d)`,
		pgWALSlotRetainMax, pgWALSlotRetainMax)); qerr != nil {
		s.log.Info("WARN: cnpg active-flag slot query failed — slot-bloat evidence incomplete",
			"error", qerr)
	} else {
		for _, series := range series {
			s.emit(series.Label("namespace"),
				series.Label("cluster", "postgres_cluster", "pod"), "inactive_slot")
			s.p.emitSlotBloat(&s.slotRep, s.rep, series)
		}
	}
	// Volume pressure: the data volume a postgres pod mounts above
	// 60% is the pg_wal runaway we CAN see without exec — the WAL dir
	// lives on that volume and no other signal reaches inside it.
	if series, qerr := s.p.PromQuery(ctx,
		`kubelet_volume_stats_used_bytes / kubelet_volume_stats_capacity_bytes > `+
			fmt.Sprintf("%.2f", pgWALVolumeRatio)); qerr != nil {
		s.log.Info("WARN: volume stats query failed — volume evidence incomplete",
			"error", qerr)
	} else {
		for _, series := range series {
			ns := series.Label("namespace")
			pvc := series.Label("persistentvolumeclaim")
			// The finding's entity is the CLUSTER, not the PVC —
			// the gauge series are per operator cluster, and the
			// claim name is an implementation detail of the
			// operator's volume layout (heal-budget: emitting the PVC name
			// produced series that match no alert label set).
			if cluster := s.pgPVCs[ns+"/"+pvc]; cluster != "" {
				s.emit(ns, cluster, "wal_volume_pressure")
			}
		}
	}
}
