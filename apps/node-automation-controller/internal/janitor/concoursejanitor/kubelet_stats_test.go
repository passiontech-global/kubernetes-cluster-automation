// kubelet_stats_test.go — coverage for kubeletStatsReader.Summary:
// the apiserver node-proxy stats/summary REST read only exists on a
// real clientset pointed at httptest (the fake clientset's
// CoreV1().RESTClient() is nil), so the JSON decode, the absent-
// counter -1 contract and the error paths all run against Probe-
// Clientset handlers.
package concoursejanitor

import (
	"fmt"
	"net/http"
	"strings"
	"testing"

	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-automation-controller/internal/testutil"
)

// kubeletSummaryJSON renders the stats/summary body the kubelet
// serves — used/capacity/imageFs counters in bytes, any subset
// omittable to exercise the absent-counter -1 contract.
func kubeletSummaryJSON(used, cap, imgUsed *int64) string {
	num := func(p *int64) string {
		if p == nil {
			return "null"
		}
		return fmt.Sprintf("%d", *p)
	}
	return fmt.Sprintf(`{"node":{"fs":{"usedBytes":%s,"capacityBytes":%s},`+
		`"runtime":{"imageFs":{"usedBytes":%s}}}}`,
		num(used), num(cap), num(imgUsed))
}

func i64(v int64) *int64 { return &v }

func TestKubeletStatsReaderSummary(t *testing.T) {
	t.Run("full counters decode", func(t *testing.T) {
		cs := testutil.ProbeClientset(t, func(w http.ResponseWriter, r *http.Request) {
			if !strings.Contains(r.URL.Path, "/api/v1/nodes/node-a/proxy/stats/summary") {
				w.WriteHeader(http.StatusNotFound)
				return
			}
			_, _ = fmt.Fprint(w, kubeletSummaryJSON(i64(30<<30), i64(100<<30), i64(10<<30)))
		})
		used, cap, img, err := (&kubeletStatsReader{cs: cs}).Summary(ctx, "node-a")
		if err != nil {
			t.Fatalf("Summary: %v", err)
		}
		if used != 30<<30 || cap != 100<<30 || img != 10<<30 {
			t.Fatalf("Summary = (%d,%d,%d), want (%d,%d,%d)",
				used, cap, img, 30<<30, 100<<30, 10<<30)
		}
	})

	t.Run("absent counters read -1 not 0", func(t *testing.T) {
		cs := testutil.ProbeClientset(t, func(w http.ResponseWriter, r *http.Request) {
			_, _ = fmt.Fprint(w, `{"node":{"fs":{},"runtime":{}}}`)
		})
		used, cap, img, err := (&kubeletStatsReader{cs: cs}).Summary(ctx, "node-a")
		if err != nil {
			t.Fatalf("Summary: %v", err)
		}
		if used != -1 || cap != -1 || img != -1 {
			t.Fatalf("absent counters = (%d,%d,%d), want all -1", used, cap, img)
		}
	})

	t.Run("malformed JSON errors", func(t *testing.T) {
		cs := testutil.ProbeClientset(t, func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusOK)
			_, _ = fmt.Fprint(w, "<html>not json</html>")
		})
		if _, _, _, err := (&kubeletStatsReader{cs: cs}).Summary(ctx, "node-a"); err == nil {
			t.Fatal("malformed stats/summary must error")
		}
	})

	t.Run("apiserver error propagates", func(t *testing.T) {
		cs := testutil.ProbeClientset(t, func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusInternalServerError)
		})
		if _, _, _, err := (&kubeletStatsReader{cs: cs}).Summary(ctx, "node-a"); err == nil {
			t.Fatal("5xx stats/summary must error")
		}
	})
}
