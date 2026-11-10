// apf_probe_test.go — ParseApiserverRSS: the apiserver-rss-gauge RSS gauge
// extraction — max sample wins, absent family reports unseen, and a
// token that is not a float is skipped rather than poisoning the max.
package apiserver_test

import (
	"testing"

	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-host-agent/internal/subsystem/controllerhygiene/apiserver"
)

func TestParseApiserverRSS(t *testing.T) {
	// The apiserver exposes one sample per listener/process label
	// set — the LARGEST is the process RSS.
	body := `# HELP process_resident_memory_bytes Resident memory size in bytes.
# TYPE process_resident_memory_bytes gauge
process_resident_memory_bytes{instance="a:6443"} 1.5e+08
process_resident_memory_bytes{instance="b:8080"} 2e+08
up{job="apiserver"} 1
`
	rss, seen := apiserver.ParseApiserverRSS(body)
	if !seen || rss != 2e8 {
		t.Fatalf("ParseApiserverRSS=%v seen=%v want 2e8/true", rss, seen)
	}

	// No label set at all still parses.
	rss, seen = apiserver.ParseApiserverRSS(
		"process_resident_memory_bytes 42\n")
	if !seen || rss != 42 {
		t.Fatalf("bare sample=%v seen=%v want 42/true", rss, seen)
	}

	// Family absent → seen=false (the caller treats it as
	// inconclusive, not zero RSS).
	if _, seen := apiserver.ParseApiserverRSS("up 1\n"); seen {
		t.Fatal("absent family reported seen")
	}

	// A non-float token matching the regex shape is skipped —
	// ParseFloat fails and the sample never poisons the max.
	if _, seen := apiserver.ParseApiserverRSS(
		"process_resident_memory_bytes 1.2.3\n"); seen {
		t.Fatal("unparseable sample reported seen")
	}
	rss, seen = apiserver.ParseApiserverRSS(
		"process_resident_memory_bytes 1.2.3\n" +
			"process_resident_memory_bytes 7\n")
	if !seen || rss != 7 {
		t.Fatalf("mixed body=%v seen=%v want 7/true", rss, seen)
	}
}
