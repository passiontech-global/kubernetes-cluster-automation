// collect_fail2ban_test.go — fail2ban banned-ips-per-jail series.

package hostmetrics

import (
	"path/filepath"
	"testing"

	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-host-agent/internal/testutil"
)

// --- fail2ban banned counts ---

func TestFail2banBannedMetric(t *testing.T) {
	cfg, dirs := fixture(t)
	testutil.WriteFile(t, filepath.Join(dirs["state"], "fail2ban-banned"), "sshd=7 recidive=1\n")
	c := New(cfg)
	v, ok := metricValue(t, c, "node_fail2ban_banned_ips",
		map[string]string{"jail": "sshd"})
	if !ok || v != 7 {
		t.Fatalf("sshd=%v,%v want 7", v, ok)
	}
	if v, ok := metricValue(t, c, "node_fail2ban_banned_ips",
		map[string]string{"jail": "recidive"}); !ok || v != 1 {
		t.Fatalf("recidive=%v,%v want 1", v, ok)
	}
}

func TestFail2banAbsentWithoutFile(t *testing.T) {
	cfg, _ := fixture(t)
	c := New(cfg)
	if _, ok := metricValue(t, c, "node_fail2ban_banned_ips",
		map[string]string{"jail": "sshd"}); ok {
		t.Fatal("banned metric emitted without the file (fake 0)")
	}
}

// TestFail2banMalformedEntries: the file contract tolerates junk —
// entries without '=', with an empty jail or a non-numeric count are
// skipped, never emitted as junk.
func TestFail2banMalformedEntries(t *testing.T) {
	cfg, dirs := fixture(t)
	testutil.WriteFile(t, filepath.Join(dirs["state"], "fail2ban-banned"),
		"sshd=5 noequals bad==garbage =7 haproxy=7 junk=abc")
	c := New(cfg)
	if v, ok := metricValue(t, c, "node_fail2ban_banned_ips",
		map[string]string{"jail": "sshd"}); !ok || v != 5 {
		t.Fatalf("sshd=%v ok=%v want 5", v, ok)
	}
	if v, ok := metricValue(t, c, "node_fail2ban_banned_ips",
		map[string]string{"jail": "haproxy"}); !ok || v != 7 {
		t.Fatalf("haproxy=%v ok=%v want 7", v, ok)
	}
	for _, jail := range []string{"noequals", "bad", "", "junk"} {
		if _, ok := metricValue(t, c, "node_fail2ban_banned_ips",
			map[string]string{"jail": jail}); ok {
			t.Fatalf("malformed entry emitted jail=%q", jail)
		}
	}
}
