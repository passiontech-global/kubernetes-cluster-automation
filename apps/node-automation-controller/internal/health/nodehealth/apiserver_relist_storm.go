// apiserver_relist_storm.go — the apiserver-relist-storm-breaker
// check (W20-CP1): the 410-Gone relist storm signature — a flood of
// clients whose watches die (apiserver_terminated_watchers_total
// climbing) while cluster-scoped LIST latency blows past 5s
// (apiserver_request_duration_seconds_bucket p99). Left alone the
// storm feeds itself: every LIST client retries, LISTs get slower,
// more watches time out. Once the signature persists past
// relistStormMinAge the check names the top LIST offenders
// (client/resource labels on the gauge + a deduped cluster Event)
// and suspends the CronJobs that opted in via
// kube.AnnoRelistStormSuspend — the background scanners (popeye)
// that are exactly the LIST-heavy clients a storm cannot afford.
// On recovery only the CronJobs carrying the check's own
// kube.AnnoRelistStormSuspendedBy stamp are unsuspended — a
// CronJob an operator suspended by hand is never resurrected.
package nodehealth

import (
	"context"
	"fmt"
	"time"

	"github.com/go-logr/logr"
	"github.com/prometheus/client_golang/prometheus"
	corev1 "k8s.io/api/core/v1"
	eventsv1 "k8s.io/api/events/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	logf "sigs.k8s.io/controller-runtime/pkg/log"
	ctrlmetrics "sigs.k8s.io/controller-runtime/pkg/metrics"

	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-automation-controller/internal/metrics"
	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-automation-controller/internal/platform/kube"
	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-automation-controller/internal/platform/state"
	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-automation-controller/internal/probefw"
	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-automation-controller/internal/promq"
)

// apiserverRelistStormCheck is the relist-storm detector + relief
// valve.
type apiserverRelistStormCheck struct {
	*probefw.Deps

	// seen tracks the storm signature's first-seen sweep — the
	// persistence window; pruned on recovery so a later storm
	// re-arms.
	seen state.FirstSeenLedger
	// emitted is the emitted-gauge ledger — storm pairs that stop
	// breaching get DeleteLabelValues'd rather than leaking a
	// stale 1.
	emitted state.GaugeLedger[string]
	// eventHealed is the in-RAM half of the Event dedupe cooldown —
	// a storm emits ONE cluster event per window, not one per sweep.
	eventHealed state.CooldownSet
	// restoreDue/suspended gate restoreSuspendedCronJobs: without
	// them every non-storm sweep would LIST every CronJob
	// cluster-wide just to discover nothing is stamped. restoreDue
	// starts true so a controller restart still finds CronJobs a
	// previous process suspended; suspended flips on the first
	// successful relief patch and re-arms the restore pass.
	restoreDue bool
	suspended  bool
}

// NewAPIServerRelistStormCheck builds the apiserver-relist-storm-breaker check.
func NewAPIServerRelistStormCheck(d *probefw.Deps) probefw.Check {
	return &apiserverRelistStormCheck{Deps: d, restoreDue: true}
}

const (
	CheckNameAPIServerRelistStorm = "apiserver-relist-storm-breaker"

	// The storm signature needs BOTH halves: watchers dying fast
	// (relist churn) AND cluster-scoped LIST latency past 5s —
	// either alone is routine (a deploy wave kills watches; a big
	// CRD list is slow once).
	relistStormWatcherRate    = 5.0 // terminated watchers/sec over 2m
	relistStormListP99Seconds = 5.0 // LIST p99 latency in seconds
	// The signature must hold this long before relief fires — a
	// scrape flap or a single deploy wave must not suspend CronJobs.
	relistStormMinAge = 10 * time.Minute
	// One cluster Event per window — the storm can last hours.
	relistStormEventCooldown = 30 * time.Minute
	// The CronJob suspend/restore pass re-checks the maintenance
	// mutex at most this often (idempotent patches — the cooldown
	// exists to keep the sweep cheap, not to gate correctness).
	relistStormReliefCooldown = 15 * time.Minute
)

var (
	// apiserver-relist-storm-breaker — 1 per top LIST-offender
	// (client, resource) pair while the storm signature persists.
	apiserverRelistStormGauge = prometheus.NewGaugeVec(prometheus.GaugeOpts{
		Name: "node_automation_apiserver_relist_storm",
		Help: "1 while an apiserver relist storm is active, per top LIST-offender client/resource pair — apiserver-relist-storm-breaker.",
	}, []string{"client", "resource"})
)

func init() {
	ctrlmetrics.Registry.MustRegister(apiserverRelistStormGauge)
}

// relistStormQueries are the three PromQL reads the signature is
// built from: watcher churn, LIST p99 latency, and the top cluster-
// scoped LIST talkers that name the offender.
const (
	relistStormWatchersQuery   = `sum(rate(apiserver_terminated_watchers_total[2m]))`
	relistStormListP99Query    = `histogram_quantile(0.99, sum by (le) (rate(apiserver_request_duration_seconds_bucket{verb="LIST"}[5m])))`
	relistStormTopTalkersQuery = `topk(5, sum by (client, resource) ` +
		`(rate(apiserver_request_total{verb="LIST",scope="cluster"}[5m])))`
)

// Run evaluates the relist-storm signature: watcher churn above
// relistStormWatcherRate AND LIST p99 above
// relistStormListP99Seconds, persisted relistStormMinAge. Past the
// window it emits the offender gauge, fires one deduped Event, and
// runs the CronJob relief pass; on recovery it restores only the
// CronJobs it suspended itself.
func (p *apiserverRelistStormCheck) Run(ctx context.Context) probefw.Result {
	log := logf.FromContext(ctx)
	now := p.Now()
	var rep probefw.SweepReport

	watchers, werr := p.PromQuery(ctx, relistStormWatchersQuery)
	p99, perr := p.PromQuery(ctx, relistStormListP99Query)
	if werr != nil || perr != nil {
		// Inconclusive, not clear — carry held tuples forward so a
		// scrape flap cannot flap a live storm off (the shared
		// emitted-gauge contract).
		for k, lv := range p.emitted.Last() {
			rep.Carry(k, lv)
		}
		if werr != nil {
			rep.InfraErr(fmt.Errorf("relist storm watchers query: %w", werr))
		}
		if perr != nil {
			rep.InfraErr(fmt.Errorf("relist storm LIST p99 query: %w", perr))
		}
		return rep.Result(&p.emitted, apiserverRelistStormGauge.DeleteLabelValues,
			"apiserver relist storm: ", ", ")
	}

	storm := sumSamples(watchers) > relistStormWatcherRate &&
		sumSamples(p99) > relistStormListP99Seconds
	if !storm {
		p.seen.Forget("storm")
		if (p.restoreDue || p.suspended) &&
			p.restoreSuspendedCronJobs(ctx, log, now) {
			p.restoreDue = false
			p.suspended = false
		}
		return rep.Result(&p.emitted, apiserverRelistStormGauge.DeleteLabelValues,
			"apiserver relist storm: ", ", ")
	}
	first, _ := p.seen.Observe("storm", now)
	if now.Sub(first) < relistStormMinAge {
		return rep.Result(&p.emitted, apiserverRelistStormGauge.DeleteLabelValues,
			"apiserver relist storm: ", ", ")
	}

	// Storm proven — name the offenders. The topk query is
	// best-effort: a failure still leaves the storm reported under
	// a "-" pair rather than dropping the signal.
	top, terr := p.PromQuery(ctx, relistStormTopTalkersQuery)
	if terr != nil {
		log.Info("WARN: relist storm top-talker query failed — offenders unnamed",
			"error", terr)
		rep.InfraErr(fmt.Errorf("relist storm top-talker query: %w", terr))
	}
	emitted := false
	for _, s := range top {
		client := s.Label("client")
		resource := s.Label("resource")
		if client == "" {
			client = "-"
		}
		if resource == "" {
			resource = "-"
		}
		key := client + "/" + resource
		rep.Emit(apiserverRelistStormGauge, key, []string{client, resource}, key)
		emitted = true
	}
	if !emitted {
		rep.Emit(apiserverRelistStormGauge, "-/-", []string{"-", "-"}, "-")
	}

	p.emitRelistStormEvent(ctx, log, top, now)
	p.suspendOptedInCronJobs(ctx, log, now)
	return rep.Result(&p.emitted, apiserverRelistStormGauge.DeleteLabelValues,
		"apiserver relist storm: ", ", ")
}

// sumSamples totals a PromQuery result — the scalar queries above
// return at most one sample, but summing keeps a multi-series
// surprise from silently under-reading.
func sumSamples(samples []promq.Sample) float64 {
	total := 0.0
	for _, s := range samples {
		total += s.Value
	}
	return total
}

// emitRelistStormEvent fires ONE deduped Warning event per cooldown
// window naming the top LIST offenders — the on-call breadcrumb a
// metric alone cannot carry (which client is melting the apiserver).
func (p *apiserverRelistStormCheck) emitRelistStormEvent(ctx context.Context,
	log logr.Logger, top []promq.Sample, now time.Time) {

	ck := probefw.SelfHealKey(CheckNameAPIServerRelistStorm, "event")
	if p.eventHealed.CooledDown(ck, relistStormEventCooldown, now) {
		return
	}
	msg := "apiserver relist storm: watcher churn + LIST p99 >5s sustained"
	if len(top) > 0 {
		s := top[0]
		msg = fmt.Sprintf("apiserver relist storm: top LIST offender %s/%s",
			s.Label("client"), s.Label("resource"))
	}
	ev := &eventsv1.Event{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "apiserver-relist-storm-" + now.Format("20060102-150405"),
			Namespace: "kube-system",
		},
		EventTime:           metav1.NewMicroTime(now),
		Reason:              "APIServerRelistStorm",
		Note:                msg,
		Type:                corev1.EventTypeWarning,
		ReportingController: "node-automation-controller",
		ReportingInstance:   p.Name,
		Action:              "APIServerRelistStorm",
		Regarding: corev1.ObjectReference{
			APIVersion: "v1",
			Kind:       "Namespace",
			Name:       "kube-system",
		},
	}
	if _, err := p.CS.EventsV1().Events("kube-system").
		Create(ctx, ev, metav1.CreateOptions{}); err != nil {
		metrics.IncError(CheckNameAPIServerRelistStorm)
		log.Info("WARN: relist storm event create failed (RBAC?)",
			"error", err)
		return
	}
	p.eventHealed.Stamp(ck, now)
	log.Info("EVENT: APIServerRelistStorm", "detail", msg)
}

// suspendOptedInCronJobs flips spec.suspend=true on every CronJob
// carrying kube.AnnoRelistStormSuspend="true" — once per relief
// cooldown window, gated on the shared maintenance mutex (fail
// closed: an unverifiable verdict skips the pass entirely). Only
// CronJobs not already suspended get the check's own
// AnnoRelistStormSuspendedBy stamp, so restore never touches a
// manually-suspended or already-running object.
func (p *apiserverRelistStormCheck) suspendOptedInCronJobs(ctx context.Context,
	log logr.Logger, now time.Time) {

	ck := probefw.SelfHealKey(CheckNameAPIServerRelistStorm, "cronjob-relief")
	proceed, unverifiable := p.HealAllowed(ctx, log, &p.Heals,
		ck, relistStormReliefCooldown, now)
	switch {
	case unverifiable:
		metrics.IncError(CheckNameAPIServerRelistStorm)
		return
	case !proceed:
		return
	}
	cjs, err := kube.ListAll(ctx, metav1.ListOptions{
		Limit: kube.DefaultListPageSize,
	}, kube.CronJobs(p.CS, metav1.NamespaceAll))
	if err != nil {
		metrics.IncError(CheckNameAPIServerRelistStorm)
		log.Info("WARN: relist storm cronjob list failed", "error", err)
		return
	}
	// The pass ran — stamp the relief cooldown so the next storm
	// sweep skips the list+mutex re-check for the window (the
	// comment on relistStormReliefCooldown promises exactly this;
	// an unstamped key would re-run every sweep).
	p.Heals.Stamp(ck, now)
	for i := range cjs {
		cj := &cjs[i]
		// spec.suspend is a *bool — nil means "not suspended" (the
		// API default), so the skip must test the pointed-to value,
		// not nil-ness: `Suspend == nil || *Suspend` skipped EVERY
		// CronJob that never declared suspend explicitly.
		if cj.Annotations[kube.AnnoRelistStormSuspend] != "true" ||
			(cj.Spec.Suspend != nil && *cj.Spec.Suspend) ||
			cj.Annotations[kube.AnnoRelistStormSuspendedBy] != "" {
			continue
		}
		patch := []byte(fmt.Sprintf(
			`{"spec":{"suspend":true},"metadata":{"annotations":{%q:%q}}}`,
			kube.AnnoRelistStormSuspendedBy,
			now.Format(time.RFC3339)))
		if _, err := p.CS.BatchV1().CronJobs(cj.Namespace).Patch(ctx,
			cj.Name, types.MergePatchType, patch, metav1.PatchOptions{}); err != nil {
			metrics.IncError(CheckNameAPIServerRelistStorm)
			log.Error(err, "relist storm cronjob suspend failed",
				"cronjob", cj.Namespace+"/"+cj.Name)
			continue
		}
		log.Info("ACTION: suspended cronjob for relist-storm relief",
			"cronjob", cj.Namespace+"/"+cj.Name)
		p.suspended = true
	}
}

// restoreSuspendedCronJobs unsuspends every CronJob carrying the
// check's own AnnoRelistStormSuspendedBy stamp — the storm cleared,
// so the relief window ends. Objects suspended by anyone else (no
// stamp) are left alone by construction. Returns true only when the
// pass completed cleanly — a failed list or patch keeps the caller's
// restoreDue/suspended flags armed so the next sweep retries instead
// of stranding stamped CronJobs suspended forever.
func (p *apiserverRelistStormCheck) restoreSuspendedCronJobs(ctx context.Context,
	log logr.Logger, now time.Time) bool {

	cjs, err := kube.ListAll(ctx, metav1.ListOptions{
		Limit: kube.DefaultListPageSize,
	}, kube.CronJobs(p.CS, metav1.NamespaceAll))
	if err != nil {
		metrics.IncError(CheckNameAPIServerRelistStorm)
		log.Info("WARN: relist storm cronjob restore list failed", "error", err)
		return false
	}
	ok := true
	for i := range cjs {
		cj := &cjs[i]
		if cj.Annotations[kube.AnnoRelistStormSuspendedBy] == "" {
			continue
		}
		patch := []byte(fmt.Sprintf(
			`{"spec":{"suspend":false},"metadata":{"annotations":{%q:null}}}`,
			kube.AnnoRelistStormSuspendedBy))
		if _, err := p.CS.BatchV1().CronJobs(cj.Namespace).Patch(ctx,
			cj.Name, types.MergePatchType, patch, metav1.PatchOptions{}); err != nil {
			metrics.IncError(CheckNameAPIServerRelistStorm)
			log.Error(err, "relist storm cronjob restore failed",
				"cronjob", cj.Namespace+"/"+cj.Name)
			ok = false
			continue
		}
		log.Info("ACTION: restored cronjob after relist-storm relief",
			"cronjob", cj.Namespace+"/"+cj.Name)
	}
	return ok
}
