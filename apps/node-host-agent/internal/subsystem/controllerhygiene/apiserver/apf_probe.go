// apf_probe.go — apiserver APF (API Priority & Fairness)
// queue-starvation probe.
//
// The kube-apiserver's API Priority & Fairness layer sheds requests
// with 429s when a flow schema's queues overflow — the mirror image
// of the KCM workqueue stall (cp_freeze_heal.go): instead of the
// controller's own workqueue stalling, one client GROUP's queue
// saturates and its requests are rejected while the rest of the
// apiserver stays healthy. apiserver_flowcontrol_rejected_requests_total
// and apiserver_flowcontrol_current_inqueue_requests carry
// flow_schema + priority_level labels — the labels that name the
// congesting client group — so the probe mirrors both into
// node-agent-apiserver-apf.prom (node-exporter textfile channel:
// the subsystem registry is owned by controllerhygiene.go's New(),
// outside this file — see textfile_prom.go) and suspect-logs the
// offending pairs whenever the reject counters grow between
// consecutive scrapes. ProbeAPF rides the ungated-cycle slot
// dispatched from FreezeCheck.Run (see cdeps.CheckCPFreeze).

package apiserver

import (
	"context"
	"errors"
	"fmt"
	"io"
	"math"
	"net/http"
	"regexp"
	"sort"
	"strconv"
	"strings"

	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-host-agent/internal/platform/promfile"
)

const (
	// APFRejectedMetric mirrors the apiserver's cumulative reject
	// counter per flow_schema+priority_level — increase() over it
	// names the client group being 429'd.
	APFRejectedMetric = "node_host_agent_apiserver_apf_rejected_total"
	// apfInqueueMetric mirrors the live queue depth per
	// flow_schema+priority_level — the leading edge before rejects.
	apfInqueueMetric = "node_host_agent_apiserver_apf_inqueue_requests"
	APFPromFile      = "node-agent-apiserver-apf.prom"
	// terminatedWatchersMetric mirrors the apiserver's cumulative
	// apiserver_terminated_watchers_total — the relist-storm 410-Gone
	// relist-storm signature (watch clients relisting en masse).
	terminatedWatchersMetric = "node_host_agent_apiserver_terminated_watchers"
	// apiserverRSSMetric mirrors the local apiserver's
	// process_resident_memory_bytes (W19-PI2) — kube-apiserver RSS
	// growth/leak visibility without scraping the static pod.
	apiserverRSSMetric = "node_host_agent_apiserver_rss_bytes"
	// logKeyAPFStarve keys the suspectLog dedupe budget for the
	// reject-growth lines — no dedicated latch, same role as
	// cdeps.LogKeyDeadFallbk.
	logKeyAPFStarve = "apf-starvation"
	// apfOffenderSample caps the flow-schema list in one suspect
	// line — the rest still land in the textfile series.
	apfOffenderSample = 5
)

// APFSeriesKey identifies one APF series — the
// (flow_schema, priority_level) label pair shared by the rejected
// and inqueue families.
type APFSeriesKey struct {
	FlowSchema    string
	PriorityLevel string
}

// apfOffender is one (flow_schema, priority_level) pair whose reject
// counter grew since the previous scrape.
type apfOffender struct {
	key     APFSeriesKey
	delta   float64
	inqueue float64
}

var (
	// apfSeriesRe matches the two apiserver_flowcontrol families the
	// probe needs — same scrape-line grammar as kcmWorkqueueRe.
	apfSeriesRe = regexp.MustCompile(
		`(?m)^apiserver_flowcontrol_(rejected_requests_total|current_inqueue_requests)` +
			`(\{[^}]*\})?\s+([0-9.eE+-]+)`)
	apfFlowSchemaRe = regexp.MustCompile(`flow_schema="([^"]*)"`)
	apfPriorityRe   = regexp.MustCompile(`priority_level="([^"]*)"`)
	// terminatedWatchersRe extracts the apiserver's 410-Gone
	// terminated-watch counter (all label variants summed).
	terminatedWatchersRe = regexp.MustCompile(
		`(?m)^apiserver_terminated_watchers_total(\{[^}]*\})?\s+([0-9.eE+-]+)`)
	// apiserverRSSRe extracts process_resident_memory_bytes — the
	// apiserver's own RSS gauge (W19-PI2).
	apiserverRSSRe = regexp.MustCompile(
		`(?m)^process_resident_memory_bytes(\{[^}]*\})?\s+([0-9.eE+-]+)`)
)

// apfLabel extracts one label value from a `{...}` label set — ""
// when absent, which still groups consistently.
func apfLabel(labels string, re *regexp.Regexp) string {
	if m := re.FindStringSubmatch(labels); m != nil {
		return m[1]
	}
	return ""
}

// ParseAPFMetrics extracts the rejected_requests_total counters and
// current_inqueue_requests gauges, keyed by (flow_schema,
// priority_level). Missing APF families (a scraped endpoint that
// never served flowcontrol) yield empty maps — inconclusive, not a
// failure.
func ParseAPFMetrics(body string) (rejected, inqueue map[APFSeriesKey]float64) {
	rejected = map[APFSeriesKey]float64{}
	inqueue = map[APFSeriesKey]float64{}
	for _, m := range apfSeriesRe.FindAllStringSubmatch(body, -1) {
		v, err := strconv.ParseFloat(m[3], 64)
		if err != nil {
			continue
		}
		k := APFSeriesKey{
			FlowSchema:    apfLabel(m[2], apfFlowSchemaRe),
			PriorityLevel: apfLabel(m[2], apfPriorityRe),
		}
		switch m[1] {
		case "rejected_requests_total":
			rejected[k] += v
		case "current_inqueue_requests":
			inqueue[k] += v
		}
	}
	return rejected, inqueue
}

// ParseTerminatedWatchers sums the apiserver's
// apiserver_terminated_watchers_total counter across its label
// sets — relist-storm relist-storm evidence. seen=false when the family
// is absent (older apiserver / non-flowcontrol endpoint).
func ParseTerminatedWatchers(body string) (total float64, seen bool) {
	for _, m := range terminatedWatchersRe.FindAllStringSubmatch(body, -1) {
		v, err := strconv.ParseFloat(m[2], 64)
		if err != nil {
			continue
		}
		total += v
		seen = true
	}
	return total, seen
}

// ParseApiserverRSS returns the largest
// process_resident_memory_bytes sample in the /metrics body — the
// apiserver exposes one per listener/process label set, so the max
// is the process's real RSS. seen=false when the family is absent.
func ParseApiserverRSS(body string) (rss float64, seen bool) {
	for _, m := range apiserverRSSRe.FindAllStringSubmatch(body, -1) {
		v, err := strconv.ParseFloat(m[2], 64)
		if err != nil {
			continue
		}
		if !seen || v > rss {
			rss = v
		}
		seen = true
	}
	return rss, seen
}

// apfKeysSorted returns the map keys in a stable order — the
// textfile content stays byte-stable between scrapes.
func apfKeysSorted(m map[APFSeriesKey]float64) []APFSeriesKey {
	keys := make([]APFSeriesKey, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Slice(keys, func(i, j int) bool {
		if keys[i].FlowSchema != keys[j].FlowSchema {
			return keys[i].FlowSchema < keys[j].FlowSchema
		}
		return keys[i].PriorityLevel < keys[j].PriorityLevel
	})
	return keys
}

// apfMetrics fetches the local apiserver /metrics body. The default
// path reuses the mTLS client the rv probe already builds from the
// admin credentials (the secure :6443 /metrics endpoint requires
// client auth — the insecure healthz/metrics probe client would get
// a 401). ensureClient()==nil is "not a controller / no creds" —
// inconclusive, same posture as the hub check.
func (c *FreezeCheck) apfMetrics(ctx context.Context) (string, error) {
	if c.APFMetricsFn != nil {
		return c.APFMetricsFn(ctx)
	}
	client := c.d.EnsureClient()
	if client == nil {
		return "", errors.New("no apiserver client credentials")
	}
	qctx, cancel := context.WithTimeout(ctx, c.d.Cfg.QueryTimeout)
	defer cancel()
	req, err := http.NewRequestWithContext(qctx, http.MethodGet,
		"https://"+c.d.Cfg.Hub.SelfEndpoint+"/metrics", nil)
	if err != nil {
		return "", err
	}
	resp, err := client.Do(req)
	if err != nil {
		return "", err
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 64<<10))
		return "", fmt.Errorf("apiserver /metrics status %d", resp.StatusCode)
	}
	// The apiserver /metrics body is a few MiB on a healthy cluster —
	// 16MiB bounds it like the journal capture cap.
	body, err := io.ReadAll(io.LimitReader(resp.Body, 16<<20))
	if err != nil {
		return "", err
	}
	return string(body), nil
}

// ProbeAPF scrapes the local apiserver /metrics, mirrors the APF
// rejected/inqueue series into the textfile, and suspect-logs the
// (flow_schema, priority_level) pairs whose reject counter grew —
// the observable signature of APF queue overflow (requests denied
// with 429). A scrape failure degrades to headers-only emission so
// the series goes absent rather than pinning a stale counter.
func (c *FreezeCheck) ProbeAPF(ctx context.Context) {
	body, err := c.apfMetrics(ctx)
	if err != nil {
		c.apiserverRSSSeen = false // blind scrape drops the series
		c.EmitAPFMetrics(nil, nil, 0, false)
		logger().Debug("controllerhygiene: apf metrics scrape failed",
			"error", err)
		return
	}
	rejected, inqueue := ParseAPFMetrics(body)
	tw, twOK := ParseTerminatedWatchers(body)
	rss, rssOK := ParseApiserverRSS(body)
	c.apiserverRSS, c.apiserverRSSSeen = rss, rssOK
	c.EmitAPFMetrics(rejected, inqueue, tw, twOK)

	// Reject deltas vs the previous scrape — the APF counters are
	// cumulative, so a growth window is what proves CURRENT
	// congestion (same consecutive-scrape posture as
	// KCMQueueStalled). No baseline → inconclusive.
	var offenders []apfOffender
	if c.apfPrevRejected != nil {
		reset := false
		for k, cur := range rejected {
			prev, ok := c.apfPrevRejected[k]
			if !ok {
				continue
			}
			d := cur - prev
			switch {
			case d > 0:
				offenders = append(offenders, apfOffender{
					key: k, delta: d, inqueue: inqueue[k]})
			case d < 0:
				reset = true // counter reset — apiserver restarted
			}
		}
		if reset {
			logger().Debug("controllerhygiene: apf reject counters went backwards — apiserver restarted, re-baselining")
		}
	}
	c.apfPrevRejected = rejected
	if len(offenders) == 0 {
		return
	}
	sort.Slice(offenders, func(i, j int) bool {
		return offenders[i].delta > offenders[j].delta
	})
	if len(offenders) > apfOffenderSample {
		offenders = offenders[:apfOffenderSample]
	}
	parts := make([]string, 0, len(offenders))
	for _, o := range offenders {
		parts = append(parts, fmt.Sprintf(
			"flow_schema=%s priority_level=%s +%.0f rejects (inqueue %.0f)",
			o.key.FlowSchema, o.key.PriorityLevel, o.delta, o.inqueue))
	}
	c.d.State.SuspectLog(logKeyAPFStarve,
		"suspect: apiserver APF queue starvation — flow-schema queues rejecting requests: "+
			strings.Join(parts, "; "), c.d.Cfg.SuspectLogCadence)
}

// EmitAPFMetrics renders node-agent-apiserver-apf.prom — the
// rejected family as a mirrored counter (TYPE counter: the apiserver
// series is cumulative), the inqueue family as a gauge. nil maps
// emit headers only so a blind scrape drops the series instead of
// leaving a stale reading live.
func (c *FreezeCheck) EmitAPFMetrics(rejected, inqueue map[APFSeriesKey]float64,
	terminatedWatchers float64, twSeen bool) {
	var p promfile.Builder
	p.HeaderType(APFRejectedMetric,
		"apiserver_flowcontrol_rejected_requests_total mirrored from the "+
			"local apiserver — APF queue-overflow rejects by flow_schema "+
			"and priority_level.", "counter")
	for _, k := range apfKeysSorted(rejected) {
		p.Line(fmt.Sprintf("%s{flow_schema=\"%s\",priority_level=\"%s\"} %s",
			APFRejectedMetric,
			promfile.EscapeLabelValue(k.FlowSchema),
			promfile.EscapeLabelValue(k.PriorityLevel),
			strconv.FormatFloat(rejected[k], 'f', -1, 64)))
	}
	inqueueHelp := "apiserver_flowcontrol_current_inqueue_requests " +
		"mirrored from the local apiserver — APF queue depth by " +
		"flow_schema and priority_level."
	if len(inqueue) == 0 {
		p.Header(apfInqueueMetric, inqueueHelp)
	}
	for _, k := range apfKeysSorted(inqueue) {
		p.GaugeLabels(apfInqueueMetric, inqueueHelp, fmt.Sprintf(
			"flow_schema=\"%s\",priority_level=\"%s\"",
			promfile.EscapeLabelValue(k.FlowSchema),
			promfile.EscapeLabelValue(k.PriorityLevel)), inqueue[k])
	}
	// relist-storm: the terminated-watchers counter rides the same
	// textfile — headers-only when the family wasn't in the
	// scrape so a blind scrape drops the series rather than
	// pinning a stale reading.
	twHelp := "apiserver_terminated_watchers_total mirrored from the " +
		"local apiserver — watches dropped with 410 Gone (relist-storm signal)."
	if !twSeen {
		p.HeaderType(terminatedWatchersMetric, twHelp, "counter")
	} else {
		p.HeaderType(terminatedWatchersMetric, twHelp, "counter")
		p.Line(fmt.Sprintf("%s %s", terminatedWatchersMetric,
			strconv.FormatFloat(terminatedWatchers, 'f', -1, 64)))
		c.d.TerminatedWatchersVal.Store(math.Float64bits(terminatedWatchers))
	}
	// W19-PI2: apiserver RSS — headers-only when the scrape lacked
	// the family so a blind scrape drops the series.
	rssHelp := "kube-apiserver process_resident_memory_bytes " +
		"mirrored from the local apiserver — RSS growth/leak watch."
	if !c.apiserverRSSSeen {
		p.Header(apiserverRSSMetric, rssHelp)
	} else {
		p.Gauge(apiserverRSSMetric, rssHelp, c.apiserverRSS)
	}
	c.d.WriteTextfileProm(APFPromFile, p.String())
}
