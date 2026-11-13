// metrics_probe.go — layer 3 of coredns-stale-watchdog: scrape each
// coredns pod's :9153/metrics and sum coredns_panics_total — a plugin
// panic count > 0 marks the replica stale.
package corednswatchdog

import (
	"bufio"
	"context"
	"io"
	"math"
	"net"
	"net/http"
	"strconv"
	"strings"
)

// metricsScanCap caps the /metrics document the panic-counter scan
// reads — the same bound the connection drain below applies, so a
// pathological body cannot pin the sweep either.
const metricsScanCap = 4 * 1024 * 1024

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
		_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, metricsScanCap))
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
	sc := bufio.NewScanner(io.LimitReader(resp.Body, metricsScanCap))
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
		// Metric-name boundary: the match must end at a space or an
		// opening label block — a naive HasPrefix also let
		// coredns_panics_total_something_else contribute to the sum.
		rest := line[len("coredns_panics_total"):]
		if rest != "" && rest[0] != ' ' && rest[0] != '{' {
			continue
		}
		// Exposition format is name[{labels}] value [timestamp] —
		// the value is ALWAYS the second field. Reading the last
		// field mistook an OpenMetrics scrape timestamp for the
		// count (a zero timestamp looked like zero panics; a real
		// one looked like billions) and flipped eviction decisions.
		f := strings.Fields(line)
		if len(f) < 2 {
			continue
		}
		v, err := strconv.ParseFloat(f[1], 64)
		if err != nil || math.IsNaN(v) || math.IsInf(v, 0) {
			continue // NaN/Inf are not counts — never sum them
		}
		sum += v
	}
	if err := sc.Err(); err != nil {
		return 0, false // same UNKNOWN verdict as a failed ReadAll
	}
	// The scan rode a 4MiB LimitReader: a body AT the cap ends the
	// scan cleanly at the cut (Scanner hits EOF, not an error), so a
	// truncated document would report a partial sum as known —
	// understating coredns_panics_total is the silent-stale
	// direction. Probe one byte past the cap: any remainder proves
	// the document was cut → invalid, same ok=false verdict as a
	// failed read, never a trusted partial sum.
	var past [1]byte
	if n, _ := resp.Body.Read(past[:]); n > 0 {
		return 0, false
	}
	return sum, true
}
