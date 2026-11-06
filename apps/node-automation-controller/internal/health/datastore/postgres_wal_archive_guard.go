// postgres_wal_archive_guard.go — the postgres-wal-archive-guard
// check: the WAL runaway signature across the three Postgres
// operator families (Percona pgv2, CloudNativePG, Percona Everest) —
// a stalled archiver, an inactive replication slot retaining WAL, a
// data volume filling past the threshold, or pg_wal disk-full crash
// evidence in pod logs. Detection-only: nothing here execs, deletes
// or patches — the gauge is the alert contract.
package datastore

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/api/meta"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime/schema"
	logf "sigs.k8s.io/controller-runtime/pkg/log"
	ctrlmetrics "sigs.k8s.io/controller-runtime/pkg/metrics"

	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-automation-controller/internal/health/probefw"
	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-automation-controller/internal/platform/kube"
	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-automation-controller/internal/platform/state"
)

// postgresWALArchiveGuardCheck is the WAL-archive stall watchdog.
type postgresWALArchiveGuardCheck struct {
	*probefw.Deps

	// emitted is the emitted-gauge ledger — a tuple that stops
	// being reported gets DeleteLabelValues'd rather than leaking a
	// stale 1 (zero value usable; the serial sweep needs no lock).
	emitted state.GaugeLedger[string]
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
	pgWALTailLines      = int64(200)
	pgWALLogMaxByte     = 256 * 1024
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
)

func init() {
	ctrlmetrics.Registry.MustRegister(
		postgresWALUnhealthyGauge)
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

// pgWALLogHit fetches the postgres container's log tail and returns
// the first matching WAL signature — bounded like the scylla gossip
// probe; a fetch failure is inconclusive, not healthy. The matched
// reason rides out through the match closure (PodLogTail reports
// only hit/miss).
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
	var reason string
	hit, err := probefw.PodLogTail(ctx, p.CS, pod, container,
		pgWALTailLines, pgWALLogMaxByte, 8*time.Second,
		func(line string) bool {
			if r := pgWALLogReason(line); r != "" {
				reason = r
				return true
			}
			return false
		})
	if err != nil || !hit {
		return "", err
	}
	return reason, nil
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
	findings := map[string]finding{}
	emit := func(ns, cluster, reason string) {
		if cluster == "" {
			cluster = "-"
		}
		findings[ns+"/"+cluster+"/"+reason] = finding{ns, cluster, reason}
	}

	// (a) CR conditions — the operator's own archive/backup verdicts.
	for _, rk := range postgresCRKinds {
		items, err := p.Dyn.Resource(rk.gvr).List(ctx, metav1.ListOptions{})
		switch {
		case apierrors.IsNotFound(err) || meta.IsNoMatchError(err):
			continue
		case err != nil:
			return probefw.Result{Infra: fmt.Errorf("list %s: %w", rk.gvr.Resource, err)}
		}
		for i := range items.Items {
			cr := &items.Items[i]
			for _, c := range kube.Conditions(cr.Object, "status", "conditions") {
				if pgWALConditionUnhealthy(c, now) {
					emit(cr.GetNamespace(), cr.GetName(), "archive_condition")
				}
			}
		}
	}

	// (b) pod logs — crash/stall evidence the CR status cannot see.
	pods, err := p.CS.CoreV1().Pods(metav1.NamespaceAll).
		List(ctx, metav1.ListOptions{})
	if err != nil {
		return probefw.Result{Infra: fmt.Errorf("list pods: %w", err)}
	}
	pgPVCs := map[string]bool{} // "ns/pvc" mounted by a postgres pod
	for i := range pods.Items {
		pod := &pods.Items[i]
		cluster := postgresClusterOf(pod)
		if cluster == "" {
			continue
		}
		for _, v := range pod.Spec.Volumes {
			if v.PersistentVolumeClaim != nil {
				pgPVCs[pod.Namespace+"/"+v.PersistentVolumeClaim.ClaimName] = true
			}
		}
		if pod.DeletionTimestamp != nil || pod.Status.Phase == corev1.PodSucceeded {
			continue
		}
		reason, lerr := p.pgWALLogHit(ctx, pod)
		if lerr != nil {
			log.Info("WARN: postgres log fetch failed — WAL signature inconclusive",
				"pod", pod.Namespace+"/"+pod.Name, "error", lerr)
			continue
		}
		if reason != "" {
			emit(pod.Namespace, cluster, reason)
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
			if pgPVCs[ns+"/"+pvc] {
				emit(ns, pvc, "wal_volume_pressure")
			}
		}
	}

	var rep probefw.SweepReport
	for k, f := range findings {
		rep.Emit(postgresWALUnhealthyGauge, k,
			[]string{f.ns, f.cluster, f.reason}, k)
	}
	return rep.Result(&p.emitted, postgresWALUnhealthyGauge.DeleteLabelValues,
		"postgres wal/archive unhealthy: ", ", ")
}
