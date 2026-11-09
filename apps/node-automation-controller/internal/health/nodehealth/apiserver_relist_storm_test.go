// apiserver_relist_storm_test.go — coverage for the
// apiserver-relist-storm-breaker check: the two-signal storm
// signature (watcher churn AND LIST p99, both above threshold),
// the 10-minute persistence window, the offender gauge + deduped
// cluster Event, the opted-in CronJob suspend/restore pair (only
// check-stamped objects are resurrected), the inconclusive-carry
// posture on query failure, and the "-/-" fallback when the
// top-talker query fails.
package nodehealth

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	batchv1 "k8s.io/api/batch/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes/fake"
	"k8s.io/utils/ptr"

	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-automation-controller/internal/health/probetest"
	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-automation-controller/internal/platform/kube"
	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-automation-controller/internal/promq"
)

// relistStormProber wires the shared prober to a fake Prometheus
// answering the three signature queries: watchers/p99 scalars plus
// the topk offender list (nil top = no offender samples).
func relistStormProber(t *testing.T, cs *fake.Clientset,
	watchers, p99 float64, top []probetest.PromTestSample) *probetest.Prober {

	t.Helper()
	srv, _ := probetest.PromTestServer(t,
		func(query string) []probetest.PromTestSample {
			switch {
			case strings.Contains(query, "terminated_watchers"):
				return []probetest.PromTestSample{{Value: watchers}}
			case strings.Contains(query, "histogram_quantile"):
				return []probetest.PromTestSample{{Value: p99}}
			case strings.Contains(query, "topk"):
				return top
			}
			return nil
		})
	p := testProber(cs)
	p.Cfg.HTTPContent.URL = srv.URL
	p.HTTPClient = srv.Client()
	return p
}

// stormCronJob builds a CronJob in the storm-suspend fixture shapes:
// optIn carries AnnoRelistStormSuspend="true" (suspend must be
// explicitly false — a nil spec.suspend is skipped by design), and
// stampedBy pre-sets AnnoRelistStormSuspendedBy.
func stormCronJob(ns, name string, optIn bool, suspend *bool,
	stampedBy string) *batchv1.CronJob {

	cj := &batchv1.CronJob{
		ObjectMeta: metav1.ObjectMeta{
			Namespace: ns, Name: name,
			Annotations: map[string]string{}},
		Spec: batchv1.CronJobSpec{
			Schedule: "*/5 * * * *", Suspend: suspend},
	}
	if optIn {
		cj.Annotations[kube.AnnoRelistStormSuspend] = "true"
	}
	if stampedBy != "" {
		cj.Annotations[kube.AnnoRelistStormSuspendedBy] = stampedBy
	}
	return cj
}

// relistStormCheck extracts this check's instance from the prober.
func relistStormCheck(t *testing.T, p *probetest.Prober) *apiserverRelistStormCheck {
	t.Helper()
	return probetest.MustCheck[*apiserverRelistStormCheck](t, p)
}

// Quiet metrics — watchers under 5/s or LIST p99 under 5s — never
// arm the signature: the check passes and the seen ledger stays
// empty so a later real storm still gets its full window.
func TestRelistStormQuietPasses(t *testing.T) {
	for _, tc := range []struct {
		name     string
		watchers float64
		p99      float64
	}{
		{"both quiet", 0.5, 0.4},
		{"watchers hot but p99 fine", 42, 1.0},
		{"p99 hot but watchers fine", 1.0, 42},
	} {
		t.Run(tc.name, func(t *testing.T) {
			cs := fake.NewSimpleClientset()
			p := relistStormProber(t, cs, tc.watchers, tc.p99, nil)
			base := time.Now()
			probetest.FreezeNow(p.Deps, base)
			ch := relistStormCheck(t, p)
			if res := ch.Run(ctx); !res.Pass {
				t.Fatalf("quiet signature failed: %+v", res)
			}
			if keys := probetest.LedgerKeys(&ch.seen); len(keys) != 0 {
				t.Fatalf("seen ledger armed on a quiet sweep: %v", keys)
			}
		})
	}
}

// The storm signature alone is not enough — it must persist
// relistStormMinAge before the check fails the sweep. The first
// breaching sweep arms the window and still passes.
func TestRelistStormPersistenceWindow(t *testing.T) {
	cs := fake.NewSimpleClientset()
	top := []probetest.PromTestSample{
		{Labels: map[string]string{"client": "popeye", "resource": "pods"}, Value: 30},
	}
	p := relistStormProber(t, cs, 20, 9, top)
	base := time.Now()
	ch := relistStormCheck(t, p)

	probetest.FreezeNow(p.Deps, base)
	if res := ch.Run(ctx); !res.Pass {
		t.Fatalf("first breaching sweep must pass inside the window: %+v", res)
	}
	probetest.FreezeNow(p.Deps, base.Add(relistStormMinAge-time.Minute))
	if res := ch.Run(ctx); !res.Pass {
		t.Fatalf("sweep inside the persistence window must pass: %+v", res)
	}
	probetest.FreezeNow(p.Deps, base.Add(relistStormMinAge+time.Minute))
	res := ch.Run(ctx)
	if res.Pass {
		t.Fatal("storm persisted past relistStormMinAge must fail the check")
	}
	if !strings.Contains(res.Why, "popeye/pods") {
		t.Fatalf("Why = %q, want the offender pair named", res.Why)
	}
	t.Cleanup(func() {
		apiserverRelistStormGauge.DeleteLabelValues("popeye", "pods")
	})
}

// Once proven, the check emits one gauge series per top LIST
// offender and ONE deduped cluster Event per cooldown window —
// the storm can last hours, the event must not.
func TestRelistStormEmitsGaugeAndDedupedEvent(t *testing.T) {
	cs := fake.NewSimpleClientset()
	top := []probetest.PromTestSample{
		{Labels: map[string]string{"client": "popeye", "resource": "pods"}, Value: 30},
		{Labels: map[string]string{"client": "k9s", "resource": "nodes"}, Value: 12},
	}
	p := relistStormProber(t, cs, 20, 9, top)
	base := time.Now()
	ch := relistStormCheck(t, p)
	// Seed the persistence window already elapsed.
	ch.seen.Seed("storm", base.Add(-relistStormMinAge-time.Minute))
	probetest.FreezeNow(p.Deps, base)
	t.Cleanup(func() {
		apiserverRelistStormGauge.DeleteLabelValues("popeye", "pods")
		apiserverRelistStormGauge.DeleteLabelValues("k9s", "nodes")
	})

	if res := ch.Run(ctx); res.Pass {
		t.Fatal("proven storm must fail the check")
	}
	for _, lv := range [][2]string{{"popeye", "pods"}, {"k9s", "nodes"}} {
		m := probetest.FindMetric(t, "node_automation_apiserver_relist_storm",
			map[string]string{"client": lv[0], "resource": lv[1]})
		if m == nil || m.GetGauge().GetValue() != 1 {
			t.Fatalf("offender gauge %v/%v missing", lv[0], lv[1])
		}
	}
	events, err := cs.EventsV1().Events("kube-system").List(ctx, metav1.ListOptions{})
	if err != nil {
		t.Fatal(err)
	}
	if len(events.Items) != 1 || events.Items[0].Reason != "APIServerRelistStorm" {
		t.Fatalf("storm events = %+v, want one APIServerRelistStorm", events.Items)
	}

	// A second proven sweep inside the event cooldown adds no event.
	probetest.FreezeNow(p.Deps, base.Add(time.Minute))
	if res := ch.Run(ctx); res.Pass {
		t.Fatal("still-storming sweep must fail")
	}
	events, _ = cs.EventsV1().Events("kube-system").List(ctx, metav1.ListOptions{})
	if len(events.Items) != 1 {
		t.Fatalf("event cooldown leaked: %d events", len(events.Items))
	}
}

// A proven storm suspends every opted-in CronJob (explicit
// spec.suspend=false + the opt-in annotation) and stamps them with
// AnnoRelistStormSuspendedBy; a manually-suspended CronJob and an
// opted-in one already suspended are left alone.
func TestRelistStormSuspendsOptedInCronJobs(t *testing.T) {
	running := ptr.To(false)
	cs := fake.NewSimpleClientset(
		stormCronJob("tools", "scanner", true, running, ""),
		stormCronJob("tools", "manual", false, ptr.To(true), ""),
		stormCronJob("tools", "already-suspended", true, ptr.To(true), ""),
	)
	p := relistStormProber(t, cs, 20, 9,
		[]probetest.PromTestSample{
			{Labels: map[string]string{"client": "popeye", "resource": "pods"}, Value: 30}})
	base := time.Now()
	ch := relistStormCheck(t, p)
	ch.seen.Seed("storm", base.Add(-relistStormMinAge-time.Minute))
	probetest.FreezeNow(p.Deps, base)
	t.Cleanup(func() {
		apiserverRelistStormGauge.DeleteLabelValues("popeye", "pods")
	})

	if res := ch.Run(ctx); res.Pass {
		t.Fatal("proven storm must fail")
	}
	get := func(name string) *batchv1.CronJob {
		cj, err := cs.BatchV1().CronJobs("tools").Get(ctx, name, metav1.GetOptions{})
		if err != nil {
			t.Fatal(err)
		}
		return cj
	}
	scanner := get("scanner")
	if scanner.Spec.Suspend == nil || !*scanner.Spec.Suspend {
		t.Fatal("opted-in CronJob not suspended")
	}
	if scanner.Annotations[kube.AnnoRelistStormSuspendedBy] == "" {
		t.Fatal("suspended CronJob missing the check's own stamp")
	}
	manual := get("manual")
	if manual.Annotations[kube.AnnoRelistStormSuspendedBy] != "" {
		t.Fatal("manually-suspended CronJob stamped — restore would resurrect it")
	}
	already := get("already-suspended")
	if already.Annotations[kube.AnnoRelistStormSuspendedBy] != "" {
		t.Fatal("already-suspended CronJob re-stamped")
	}
}

// On recovery only the CronJobs carrying the check's own stamp are
// unsuspended — the stamp is removed with the suspend flip, and a
// CronJob suspended by anyone else stays suspended forever.
func TestRelistStormRestoresOnlySelfSuspendedCronJobs(t *testing.T) {
	cs := fake.NewSimpleClientset(
		stormCronJob("tools", "ours", false, ptr.To(true), "2026-11-09T00:00:00Z"),
		stormCronJob("tools", "theirs", false, ptr.To(true), ""),
		stormCronJob("tools", "opted-running", true, ptr.To(false), ""),
	)
	p := relistStormProber(t, cs, 0.1, 0.2, nil) // quiet — storm cleared
	base := time.Now()
	ch := relistStormCheck(t, p)
	probetest.FreezeNow(p.Deps, base)

	if res := ch.Run(ctx); !res.Pass {
		t.Fatalf("quiet sweep must pass: %+v", res)
	}
	get := func(name string) *batchv1.CronJob {
		cj, err := cs.BatchV1().CronJobs("tools").Get(ctx, name, metav1.GetOptions{})
		if err != nil {
			t.Fatal(err)
		}
		return cj
	}
	ours := get("ours")
	if ours.Spec.Suspend == nil || *ours.Spec.Suspend {
		t.Fatal("self-suspended CronJob not restored")
	}
	if ours.Annotations[kube.AnnoRelistStormSuspendedBy] != "" {
		t.Fatal("restore left the suspended-by stamp behind")
	}
	if s := get("theirs"); s.Spec.Suspend == nil || !*s.Spec.Suspend {
		t.Fatal("manually-suspended CronJob resurrected by the restore")
	}
	if s := get("opted-running"); s.Spec.Suspend == nil || *s.Spec.Suspend {
		t.Fatal("running opted-in CronJob suspended on a quiet sweep")
	}
}

// A failed signature query is inconclusive, not clear: the check
// reports Infra and carries every held offender tuple forward —
// one scrape flap must not read as "storm resolved" and prune the
// live series (which would also re-arm the persistence window).
func TestRelistStormQueryErrorIsInfraAndCarries(t *testing.T) {
	cs := fake.NewSimpleClientset()
	p := relistStormProber(t, cs, 20, 9,
		[]probetest.PromTestSample{
			{Labels: map[string]string{"client": "popeye", "resource": "pods"}, Value: 30}})
	base := time.Now()
	ch := relistStormCheck(t, p)
	ch.seen.Seed("storm", base.Add(-relistStormMinAge-time.Minute))
	probetest.FreezeNow(p.Deps, base)
	t.Cleanup(func() {
		apiserverRelistStormGauge.DeleteLabelValues("popeye", "pods")
	})

	if res := ch.Run(ctx); res.Pass {
		t.Fatal("proven storm must fail")
	}
	m := probetest.FindMetric(t, "node_automation_apiserver_relist_storm",
		map[string]string{"client": "popeye", "resource": "pods"})
	if m == nil || m.GetGauge().GetValue() != 1 {
		t.Fatal("precondition: offender series not emitted")
	}

	// Point the query endpoint at a dead address — both signature
	// reads fail.
	p.Cfg.HTTPContent.URL = "http://127.0.0.1:1/"
	p.HTTPClient = &http.Client{Timeout: time.Second}
	res := ch.Run(ctx)
	if res.Infra == nil {
		t.Fatal("query failure must mark the check infra-failed")
	}
	m = probetest.FindMetric(t, "node_automation_apiserver_relist_storm",
		map[string]string{"client": "popeye", "resource": "pods"})
	if m == nil || m.GetGauge().GetValue() != 1 {
		t.Fatal("held offender series pruned by a scrape flap — must carry")
	}
	// And the persistence clock survives: recovery does not re-arm.
	if _, ok := ch.seen.Seen("storm", base); !ok {
		t.Fatal("inconclusive sweep dropped the storm first-seen")
	}
}

// When the top-talker query fails the storm is still reported —
// under the "-/-" unnamed-offender pair — rather than dropping the
// signal entirely; and empty labels on real samples normalize to
// "-" too.
func TestRelistStormTopTalkerFailureAndEmptyLabels(t *testing.T) {
	newQueryServer := func(t *testing.T, topErr bool,
		top []probetest.PromTestSample) *httptest.Server {

		t.Helper()
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			q := r.URL.Query().Get("query")
			w.Header().Set("Content-Type", "application/json")
			switch {
			case strings.Contains(q, "terminated_watchers"):
				fmt.Fprint(w, `{"status":"success","data":{"resultType":"vector","result":[{"metric":{},"value":[1,"20"]}]}}`)
			case strings.Contains(q, "histogram_quantile"):
				fmt.Fprint(w, `{"status":"success","data":{"resultType":"vector","result":[{"metric":{},"value":[1,"9"]}]}}`)
			case strings.Contains(q, "topk"):
				if topErr {
					fmt.Fprint(w, `{"status":"error","error":"query blew up"}`)
					return
				}
				// Reuse the shared renderer shape for the sample list.
				var b strings.Builder
				b.WriteString(`{"status":"success","data":{"resultType":"vector","result":[`)
				for i, s := range top {
					if i > 0 {
						b.WriteString(",")
					}
					b.WriteString(`{"metric":{`)
					first := true
					for k, v := range s.Labels {
						if !first {
							b.WriteString(",")
						}
						first = false
						fmt.Fprintf(&b, "%q:%q", k, v)
					}
					b.WriteString(`},"value":[1,"30"]}`)
				}
				b.WriteString(`]}}`)
				fmt.Fprint(w, b.String())
			default:
				w.WriteHeader(http.StatusNotFound)
			}
		}))
		t.Cleanup(srv.Close)
		return srv
	}

	t.Run("topk failure still reports storm", func(t *testing.T) {
		cs := fake.NewSimpleClientset()
		srv := newQueryServer(t, true, nil)
		p := testProber(cs)
		p.Cfg.HTTPContent.URL = srv.URL
		p.HTTPClient = srv.Client()
		base := time.Now()
		ch := relistStormCheck(t, p)
		ch.seen.Seed("storm", base.Add(-relistStormMinAge-time.Minute))
		probetest.FreezeNow(p.Deps, base)
		t.Cleanup(func() {
			apiserverRelistStormGauge.DeleteLabelValues("-", "-")
		})

		res := ch.Run(ctx)
		if res.Pass {
			t.Fatal("storm with a failed topk query must still fail")
		}
		if res.Infra == nil {
			t.Fatal("topk failure must surface as Infra")
		}
		m := probetest.FindMetric(t, "node_automation_apiserver_relist_storm",
			map[string]string{"client": "-", "resource": "-"})
		if m == nil || m.GetGauge().GetValue() != 1 {
			t.Fatal("unnamed-offender -/- series missing")
		}
	})

	t.Run("empty labels normalize to dashes", func(t *testing.T) {
		cs := fake.NewSimpleClientset()
		srv := newQueryServer(t, false,
			[]probetest.PromTestSample{{Labels: map[string]string{}, Value: 1}})
		p := testProber(cs)
		p.Cfg.HTTPContent.URL = srv.URL
		p.HTTPClient = srv.Client()
		base := time.Now()
		ch := relistStormCheck(t, p)
		ch.seen.Seed("storm", base.Add(-relistStormMinAge-time.Minute))
		probetest.FreezeNow(p.Deps, base)
		t.Cleanup(func() {
			apiserverRelistStormGauge.DeleteLabelValues("-", "-")
		})

		if res := ch.Run(ctx); res.Pass {
			t.Fatal("proven storm must fail")
		}
		m := probetest.FindMetric(t, "node_automation_apiserver_relist_storm",
			map[string]string{"client": "-", "resource": "-"})
		if m == nil || m.GetGauge().GetValue() != 1 {
			t.Fatal("empty-label sample did not normalize to -/-")
		}
	})
}

// sumSamples totals every sample — a multi-series surprise must not
// silently under-read the scalar signature.
func TestRelistStormSumSamples(t *testing.T) {
	if got := sumSamples(nil); got != 0 {
		t.Fatalf("sumSamples(nil) = %v", got)
	}
	got := sumSamples([]promq.Sample{{Value: 2}, {Value: 3.5}})
	if got != 5.5 {
		t.Fatalf("sumSamples = %v, want 5.5", got)
	}
}
