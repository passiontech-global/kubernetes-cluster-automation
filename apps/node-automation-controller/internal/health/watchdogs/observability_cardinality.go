// observability_cardinality.go — Prometheus TSDB cardinality explosion
// early-breaker inside observability-pipeline-guard.
//
// Strictly O(targets) PromQL only (NEVER full-series scans such as
// {__name__=~".+"}): monitors max(prometheus_tsdb_head_series) and
// 2-cycle sustained max(deriv(prometheus_tsdb_head_series[15m])) * 3600,
// and runs topk(5, ...) scrape attribution ONLY when a threshold is
// breached.
package watchdogs

import (
	"context"
	"fmt"
	"strings"

	"github.com/go-logr/logr"
	"github.com/prometheus/client_golang/prometheus"
	corev1 "k8s.io/api/core/v1"
	ctrlmetrics "sigs.k8s.io/controller-runtime/pkg/metrics"

	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-automation-controller/internal/platform/kube"
	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-automation-controller/internal/probefw"
	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-automation-controller/internal/promq"
)

const (
	defaultObsHeadSeriesWarn          = 1500000
	defaultObsHeadSeriesGrowthPerHour = 200000

	obsCardinalityComponent   = "prometheus_cardinality"
	obsCardinalityEventReason = "ObservabilityCardinalityExplosion"
	obsCardinalityEventKey    = "cardinality"
	obsCardinalityGrowthKey   = "head_series_growth"
	obsCardinalityMinCycles   = 2

	obsHeadSeriesQuery                = `max(prometheus_tsdb_head_series)`
	obsHeadSeriesGrowthQuery          = `max(deriv(prometheus_tsdb_head_series[15m])) * 3600`
	obsCardinalitySeriesAddedQuery    = `topk(5, sum by (job, namespace) (scrape_series_added))`
	obsCardinalitySamplesScrapedQuery = `topk(5, sum by (job, namespace) (scrape_samples_scraped))`
)

type obsCardinalityConfig struct {
	headSeriesWarn    float64
	growthPerHourWarn float64
}

type culpritKey struct {
	job, ns string
}

var (
	prometheusHeadSeriesGauge = prometheus.NewGauge(prometheus.GaugeOpts{
		Name: "node_automation_prometheus_head_series",
		Help: "Current maximum prometheus_tsdb_head_series observed across Prometheus targets.",
	})
	prometheusCardinalityCulpritGauge = prometheus.NewGaugeVec(prometheus.GaugeOpts{
		Name: "node_automation_prometheus_cardinality_culprit",
		Help: "Top scrape targets contributing scrape_series_added during a Prometheus TSDB cardinality surge.",
	}, []string{"job", "namespace"})
)

func init() {
	ctrlmetrics.Registry.MustRegister(
		prometheusHeadSeriesGauge,
		prometheusCardinalityCulpritGauge,
	)
}

func (p *observabilityPipelineCheck) evalCardinality(
	ctx context.Context,
	log logr.Logger,
	rep *probefw.SweepReport,
	last map[string][]string,
	degraded map[string]bool,
	inconclusive *bool,
	headSeries []promq.Sample, headErr error,
	growthSeries []promq.Sample, growthErr error,
) {
	p.culpritEmitted.Begin()

	if headErr != nil || growthErr != nil {
		*inconclusive = true
		if headErr != nil {
			log.Info("WARN: prometheus head_series query failed — cardinality signal inconclusive", "error", headErr)
			rep.InfraErr(headErr)
		}
		if growthErr != nil {
			log.Info("WARN: prometheus head_series growth query failed — cardinality signal inconclusive", "error", growthErr)
			rep.InfraErr(growthErr)
		}
		if lv, held := last[obsCardinalityComponent]; held {
			rep.Carry(obsCardinalityComponent, lv)
		}
		for k, lv := range p.culpritEmitted.Last() {
			p.culpritEmitted.Emit(k, lv...)
		}
		p.culpritEmitted.Prune(prometheusCardinalityCulpritGauge.DeleteLabelValues)
		return
	}

	var headMax float64
	if len(headSeries) > 0 {
		headMax = headSeries[0].Value
		prometheusHeadSeriesGauge.Set(headMax)
	}
	headBreached := len(headSeries) > 0 && headMax > p.cardCfg.headSeriesWarn

	var growthMax float64
	var growthBreached bool
	if len(growthSeries) > 0 && growthSeries[0].Value > p.cardCfg.growthPerHourWarn {
		growthMax = growthSeries[0].Value
		growthBreached = p.growthStreak.Hit(obsCardinalityGrowthKey) >= obsCardinalityMinCycles
	} else {
		if len(growthSeries) > 0 {
			growthMax = growthSeries[0].Value
		}
		p.growthStreak.Reset(obsCardinalityGrowthKey)
	}

	if !headBreached && !growthBreached {
		p.cardEvented.Prune(func(string) bool { return false })
		p.culpritEmitted.Prune(prometheusCardinalityCulpritGauge.DeleteLabelValues)
		return
	}

	degraded[obsCardinalityComponent] = true
	var reasons []string
	if headBreached {
		reasons = append(reasons, fmt.Sprintf("head_series=%.0f (>%.0f)", headMax, p.cardCfg.headSeriesWarn))
	}
	if growthBreached {
		reasons = append(reasons, fmt.Sprintf("growth=%.0f/h (>%.0f/h)", growthMax, p.cardCfg.growthPerHourWarn))
	}
	detail := fmt.Sprintf("%s (%s)", obsCardinalityComponent, strings.Join(reasons, ", "))
	rep.Emit(obsPipelineDegradedGauge, obsCardinalityComponent, []string{obsCardinalityComponent}, detail)

	// Run attribution queries ONLY when threshold breached.
	addedSamples, addedErr := p.PromQuery(ctx, obsCardinalitySeriesAddedQuery)
	scrapedSamples, scrapedErr := p.PromQuery(ctx, obsCardinalitySamplesScrapedQuery)
	if addedErr != nil {
		*inconclusive = true
		log.Info("WARN: scrape_series_added attribution query failed", "error", addedErr)
		rep.InfraErr(addedErr)
		for k, lv := range p.culpritEmitted.Last() {
			p.culpritEmitted.Emit(k, lv...)
		}
	} else {
		for _, s := range addedSamples {
			job := s.Label("job")
			if job == "" {
				job = "-"
			}
			ns := s.Label("namespace")
			if ns == "" {
				ns = "-"
			}
			p.culpritEmitted.Set(prometheusCardinalityCulpritGauge, s.Value, culpritKey{job: job, ns: ns}, job, ns)
		}
	}
	if scrapedErr != nil {
		*inconclusive = true
		log.Info("WARN: scrape_samples_scraped attribution query failed", "error", scrapedErr)
		rep.InfraErr(scrapedErr)
	}

	if !p.cardEvented.Has(obsCardinalityEventKey) {
		summary := formatCardinalityCulprits(addedSamples, scrapedSamples)
		note := fmt.Sprintf("Prometheus TSDB cardinality surge (%s); top culprits: %s",
			strings.Join(reasons, ", "), summary)
		if p.emitCardinalityEvent(ctx, log, note) == nil {
			p.cardEvented.Add(obsCardinalityEventKey)
		}
	}

	p.culpritEmitted.Prune(prometheusCardinalityCulpritGauge.DeleteLabelValues)
}

func formatCardinalityCulprits(added, scraped []promq.Sample) string {
	var parts []string
	for _, s := range added {
		job := s.Label("job")
		if job == "" {
			job = "-"
		}
		ns := s.Label("namespace")
		if ns == "" {
			ns = "-"
		}
		parts = append(parts, fmt.Sprintf("%s/%s(series_added=%.0f)", ns, job, s.Value))
	}
	if len(parts) == 0 {
		for _, s := range scraped {
			job := s.Label("job")
			if job == "" {
				job = "-"
			}
			ns := s.Label("namespace")
			if ns == "" {
				ns = "-"
			}
			parts = append(parts, fmt.Sprintf("%s/%s(samples=%.0f)", ns, job, s.Value))
		}
	}
	if len(parts) == 0 {
		return "none reported"
	}
	return strings.Join(parts, ", ")
}

func (p *observabilityPipelineCheck) emitCardinalityEvent(
	ctx context.Context, log logr.Logger, note string,
) error {
	now := p.Now()
	if err := kube.EmitWarningEvent(ctx, p.CS, kube.WarningEvent{
		Name:      fmt.Sprintf("observability-cardinality.%x", now.UnixNano()),
		Namespace: obsPipelineEventNS,
		Regarding: corev1.ObjectReference{
			APIVersion: "monitoring.coreos.com/v1",
			Kind:       "Prometheus",
			Namespace:  obsPipelineEventNS,
			Name:       "kube-prometheus-stack-prometheus",
		},
		Reason:            obsCardinalityEventReason,
		Note:              note,
		ReportingInstance: p.Name,
		Now:               now,
	}); err != nil {
		log.Info("WARN: ObservabilityCardinalityExplosion event create failed (RBAC?)", "error", err)
		return err
	}
	log.Info("EVENT: ObservabilityCardinalityExplosion — TSDB cardinality threshold breached")
	return nil
}
