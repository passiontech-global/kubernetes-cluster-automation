// metrics_probe.go — layer 3 of coredns-stale-watchdog: scrape each
// coredns pod's :9153/metrics and sum coredns_panics_total — a plugin
// panic count > 0 marks the replica stale.
package corednswatchdog

import (
	"bufio"
	"context"
	"io"
	"net"
	"net/http"
	"strconv"
	"strings"
)

// panics sums coredns_panics_total across label variants on the pod's
// :9153/metrics. ok=false = curl -sf equivalent (UNKNOWN).
func (w *coreDNSWatchdog) panics(ctx context.Context, podIP string) (float64, bool) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet,
		"http://"+net.JoinHostPort(podIP, "9153")+"/metrics", nil)
	if err != nil {
		return 0, false
	}
	resp, err := w.http.Do(req)
	if err != nil {
		return 0, false
	}
	defer func() {
		// Drain before Close — an unread body makes the connection
		// unreusable, which silently defeats keep-alive on the
		// shared transport (same pattern as the apiserver endpoint
		// guard). Bounded to the same 4MiB as the scan so a
		// pathological body cannot pin the sweep either.
		_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 4*1024*1024))
		_ = resp.Body.Close()
	}()
	if resp.StatusCode != http.StatusOK {
		return 0, false
	}
	// Stream line-by-line instead of ReadAll+Split: the body can be
	// megabytes and only the panic counter matters, so materializing
	// it (4MiB []byte -> string -> thousands of substrings) every
	// minute per pod was pure heap churn. The 4MiB cap stays via
	// LimitReader.
	sc := bufio.NewScanner(io.LimitReader(resp.Body, 4*1024*1024))
	// Metric lines are short, but one absurdly long line must not
	// silently truncate the scan (ErrTooLong reads as a failed
	// scrape below, which is the honest verdict anyway).
	sc.Buffer(make([]byte, 0, 64*1024), 1024*1024)
	var sum float64
	for sc.Scan() {
		line := sc.Text()
		if !strings.HasPrefix(line, "coredns_panics_total") {
			continue
		}
		f := strings.Fields(line)
		if v, err := strconv.ParseFloat(f[len(f)-1], 64); err == nil {
			sum += v
		}
	}
	if err := sc.Err(); err != nil {
		return 0, false // same UNKNOWN verdict as a failed ReadAll
	}
	return sum, true
}
