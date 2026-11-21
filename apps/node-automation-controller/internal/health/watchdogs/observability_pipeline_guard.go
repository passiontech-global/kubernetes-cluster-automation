// observability_pipeline_guard.go — the observability-pipeline-guard
// check: "monitoring the monitor". A Prometheus/Alertmanager/Fluent
// Bit outage is invisible exactly when it matters — alerts stop
// firing because the pipeline that would page is the thing that is
// down. The check verifies the in-cluster Dead-Man's-Switch — the
// always-firing Watchdog alert must be present (its absence means
// alerting or rule evaluation is wedged) — plus the error counters
// of every pipeline stage: alertmanager_notifications_failed_total,
// prometheus_notifications_dropped_total,
// prometheus_notifications_alertmanagers_discovered == 0,
// prometheus_tsdb_wal_corruptions_total,
// prometheus_target_scrapes_exceeded_sample_limit_total, and
// fluentbit_output_dropped_records_total/_retries_failed_total.
// Each degraded component emits
// node_automation_observability_pipeline_degraded{component} and a
// deduped ObservabilityPipelineDegraded Warning Event.
package watchdogs

import (
	"context"
	"fmt"
	"strings"

	"github.com/go-logr/logr"
	"github.com/prometheus/client_golang/prometheus"
	"golang.org/x/sync/errgroup"
	corev1 "k8s.io/api/core/v1"
	logf "sigs.k8s.io/controller-runtime/pkg/log"
	ctrlmetrics "sigs.k8s.io/controller-runtime/pkg/metrics"

	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-automation-controller/internal/platform/kube"
	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-automation-controller/internal/platform/state"
	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-automation-controller/internal/probefw"
	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-automation-controller/internal/promq"
	"github.com/passiontech-global/kubernetes-cluster-automation/libs/hostkit/envx"
)

// observabilityPipelineCheck is the monitoring-the-monitor watchdog.
type observabilityPipelineCheck struct {
	*probefw.Deps

	// emitted is the emitted-gauge ledger — a component that stops
	// degrading gets its series deleted rather than pinning stale.
	emitted state.GaugeLedger[string]
	// evented dedupes the ObservabilityPipelineDegraded K8s Event —
	// one emission per component episode, re-armed when it clears.
	evented state.SeenSet

	// Cardinality early-breaker config & state (observability_cardinality.go).
	cardCfg        obsCardinalityConfig
	culpritEmitted state.GaugeLedger[culpritKey]
	growthStreak   state.StreakLedger
	cardEvented    state.SeenSet
}

// NewObservabilityPipelineGuardCheck builds the
// observability-pipeline-guard check.
func NewObservabilityPipelineGuardCheck(d *probefw.Deps) probefw.Check {
	return &observabilityPipelineCheck{
		Deps: d,
		cardCfg: obsCardinalityConfig{
			headSeriesWarn:    envx.GetenvFloatPositive("NODE_AUTOMATION_OBS_HEAD_SERIES_WARN", defaultObsHeadSeriesWarn),
			growthPerHourWarn: envx.GetenvFloatPositive("NODE_AUTOMATION_OBS_HEAD_SERIES_GROWTH_PER_HOUR", defaultObsHeadSeriesGrowthPerHour),
		},
	}
}

const (
	CheckNameObservabilityPipelineGuard = "observability-pipeline-guard"

	// obsPipelineEventReason is the Warning Event reason — the
	// byte-stable reason the alert runbook references.
	obsPipelineEventReason = "ObservabilityPipelineDegraded"
	// obsPipelineEventNS/Obj anchor the event where operators look:
	// the prometheus-operator namespace's kube-prometheus-stack
	// deployment reporting on its own pipeline.
	obsPipelineEventNS = "prometheus-operator"
)

// obsWatchdogQuery is the Dead-Man's-Switch: the kube-prometheus-stack
// chart ships an always-firing Watchdog alert precisely so its
// ABSENCE proves the alert pipeline is broken. count() >= 1 keeps
// the pipeline alive; an empty vector is the worst signal here.
const obsWatchdogQuery = `count(ALERTS{alertname="Watchdog",alertstate="firing"})`

// obsPipelineCounters is the per-stage error-counter table: each
// component is the gauge/event label value, the query detects a
// non-zero increase over the trailing 10m (counters only ever go
// up — the rate, not the level, is the live signature).
var obsPipelineCounters = []struct {
	component string
	query     string
	desc      string
}{
	{"alertmanager_notifications",
		`sum(increase(alertmanager_notifications_failed_total[10m])) > 0`,
		"alert notifications failing to deliver"},
	{"prometheus_notifications_dropped",
		`sum(increase(prometheus_notifications_dropped_total[10m])) > 0`,
		"prometheus dropping alert notifications before delivery"},
	{"prometheus_alertmanagers_discovered",
		`max(prometheus_notifications_alertmanagers_discovered) == 0`,
		"prometheus discovered zero alertmanagers — notifications have nowhere to go"},
	{"prometheus_tsdb_wal",
		`sum(increase(prometheus_tsdb_wal_corruptions_total[10m])) > 0`,
		"prometheus WAL corrupting (hard-reset replay damage)"},
	{"prometheus_sample_limit",
		`sum(increase(prometheus_target_scrapes_exceeded_sample_limit_total[10m])) > 0`,
		"scrapes exceeding the sample limit — metrics silently dropped"},
	{"fluentbit_drops",
		`sum(increase(fluentbit_output_dropped_records_total[10m])) > 0`,
		"fluent-bit dropping log records on a backed-up output"},
	{"fluentbit_retries",
		`sum(increase(fluentbit_output_retries_failed_total[10m])) > 0`,
		"fluent-bit output retries exhausted"},
}

var (
	// observability-pipeline-guard — 1 while a monitoring-pipeline
	// stage is degraded, by component.
	obsPipelineDegradedGauge = prometheus.NewGaugeVec(prometheus.GaugeOpts{
		Name: "node_automation_observability_pipeline_degraded",
		Help: "1 while an observability-pipeline component is degraded (watchdog heartbeat, alertmanager delivery, TSDB, sample limit, fluent-bit output), by component.",
	}, []string{"component"})
)

func init() {
	ctrlmetrics.Registry.MustRegister(
		obsPipelineDegradedGauge)
}

// checkObservabilityPipeline verifies the alert/log pipeline's own
// health: a missing Watchdog heartbeat is the strongest degraded
// signature there is, and each error-counter increase is a stage
// silently failing. Prometheus-unreachable is itself inconclusive —
// the check carries last verdicts forward and reports the Infra
// error rather than reading "cannot verify" as "healthy".
func (p *observabilityPipelineCheck) Run(ctx context.Context) probefw.Result {
	log := logf.FromContext(ctx)
	var rep probefw.SweepReport
	last := p.emitted.Last()
	// The components judged degraded this sweep + whether every
	// query answered: the evented set may only be pruned on a
	// conclusive cycle, else a Prometheus flap would re-arm the
	// deduped Warning Event and re-page the same episode.
	degraded := map[string]bool{}
	inconclusive := false

	// Phase 1 — issue all baseline queries concurrently (bounded 8):
	// they are independent instant queries and the serial loop used to
	// pay Prometheus round-trip latency inside one PerCheck budget.
	// Evaluation stays serial below so metric series, log lines and
	// Warning Events keep their declared order regardless of which
	// query answered first.
	type qres struct {
		series []promq.Sample
		err    error
	}
	headIdx := 1 + len(obsPipelineCounters)
	growthIdx := 2 + len(obsPipelineCounters)
	results := make([]qres, 3+len(obsPipelineCounters))
	var g errgroup.Group
	g.SetLimit(8)
	fire := func(i int, query string) {
		g.Go(func() error {
			series, err := p.PromQuery(ctx, query)
			results[i] = qres{series: series, err: err}
			return nil
		})
	}
	fire(0, obsWatchdogQuery)
	for i, q := range obsPipelineCounters {
		fire(1+i, q.query)
	}
	fire(headIdx, obsHeadSeriesQuery)
	fire(growthIdx, obsHeadSeriesGrowthQuery)
	_ = g.Wait()

	// Phase 2 — evaluate in declared order.

	// Dead-Man's-Switch — the always-firing Watchdog alert.
	wd := results[0]
	series, err := wd.series, wd.err
	switch {
	case err != nil:
		inconclusive = true
		log.Info("WARN: watchdog heartbeat query failed — pipeline signal inconclusive",
			"error", err)
		rep.InfraErr(err)
		if lv, held := last["watchdog_heartbeat"]; held {
			rep.Carry("watchdog_heartbeat", lv)
		}
	case len(series) == 0 || series[0].Value < 1:
		degraded["watchdog_heartbeat"] = true
		p.degrade(ctx, log, &rep, "watchdog_heartbeat",
			"always-firing Watchdog alert absent — alert evaluation or routing is wedged")
	}

	for i, q := range obsPipelineCounters {
		series, err := results[1+i].series, results[1+i].err
		if err != nil {
			inconclusive = true
			log.Info("WARN: pipeline counter query failed — stage inconclusive",
				"component", q.component, "error", err)
			rep.InfraErr(err)
			if lv, held := last[q.component]; held {
				rep.Carry(q.component, lv)
			}
			continue
		}
		if len(series) == 0 {
			continue
		}
		degraded[q.component] = true
		p.degrade(ctx, log, &rep, q.component, q.desc)
	}
	p.evalCardinality(ctx, log, &rep, last, degraded, &inconclusive,
		results[headIdx].series, results[headIdx].err,
		results[growthIdx].series, results[growthIdx].err)
	// Recovery prune — a conclusive cycle in which a component is no
	// longer degraded clears its episode marker so a later relapse
	// emits a fresh Warning Event instead of being deduped against
	// the stale one.
	if !inconclusive {
		p.evented.Prune(func(c string) bool { return degraded[c] })
	}
	return rep.Result(&p.emitted, obsPipelineDegradedGauge.DeleteLabelValues,
		"observability pipeline degraded: ", ", ")
}

// degrade flags one pipeline component — the gauge emission plus the
// finding plus the deduped Warning Event.
func (p *observabilityPipelineCheck) degrade(ctx context.Context,
	log logr.Logger, rep *probefw.SweepReport, component, desc string) {

	rep.Emit(obsPipelineDegradedGauge, component,
		[]string{component},
		fmt.Sprintf("%s (%s)", component, desc))
	// Mark evented ONLY after the Event lands — a failed send must
	// retry next sweep, not dedupe against an episode marker that
	// never produced an event.
	if !p.evented.Has(component) &&
		p.emitDegradedEvent(ctx, log, component, desc) == nil {
		p.evented.Add(component)
	}
}

// emitDegradedEvent stamps the ObservabilityPipelineDegraded Warning
// Event — best-effort like every check emitter: a Forbidden is
// logged, never escalated; the gauge stays the signal. The event
// anchors on the monitoring namespace so it surfaces where the
// on-call actually watches.
func (p *observabilityPipelineCheck) emitDegradedEvent(
	ctx context.Context, log logr.Logger, component, desc string) error {

	now := p.Now()
	if err := kube.EmitWarningEvent(ctx, p.CS, kube.WarningEvent{
		// The component rides the name (underscores are not
		// DNS-1123 — map them to dashes): one sweep can degrade
		// several components and every emission shares this
		// sweep's `now` — without the component in the name the
		// second Create hits 409 AlreadyExists.
		Name: fmt.Sprintf("observability-pipeline.%s.%x",
			strings.ReplaceAll(component, "_", "-"), now.UnixNano()),
		Namespace: obsPipelineEventNS,
		Regarding: corev1.ObjectReference{
			APIVersion: "monitoring.coreos.com/v1",
			Kind:       "Prometheus",
			Namespace:  obsPipelineEventNS,
			Name:       "kube-prometheus-stack-prometheus",
		},
		Reason: obsPipelineEventReason,
		Note: fmt.Sprintf("observability pipeline component %s degraded: %s — alerts and logs may be silently lost",
			component, desc),
		ReportingInstance: p.Name,
		Now:               now,
	}); err != nil {
		log.Info("WARN: ObservabilityPipelineDegraded event create failed (RBAC?)",
			"component", component, "error", err)
		return err
	}
	log.Info("EVENT: ObservabilityPipelineDegraded — monitoring pipeline stage failing",
		"component", component)
	return nil
}
