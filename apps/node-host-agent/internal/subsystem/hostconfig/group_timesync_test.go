// group_timesync_test.go — timesyncd converge: the vars-driven
// drop-in, the chrony yield, the unit-state ensure, and the
// RTC-in-UTC policy fix gated on NTP sync.
package hostconfig

import (
	"strings"
	"testing"

	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-host-agent/internal/testutil"
)

func timesyncEnv(t *testing.T, cluster string, res map[string]string) (*cyc, *Reconciler, *testutil.FakeRunner) {
	t.Helper()
	vars := writeVarsDir(t, cluster)
	sr := newScripted(res, nil)
	r, err := New(Config{NodeName: "node-a", HostRoot: t.TempDir(),
		VarsDir: vars, Standalone: true, Runner: sr}, nil)
	if err != nil {
		t.Fatal(err)
	}
	return loadCyc(t, r, vars, "node-a"), r, sr
}

func TestTimesyncServersConvergeDropin(t *testing.T) {
	c, r, sr := timesyncEnv(t, `
ntp_servers: [10.0.0.1, 10.0.0.2]
ntp_fallback_servers: [pool.example.org]
`, nil)
	c.groupTimesync()

	dropin := hostRead(t, r, "/etc/systemd/timesyncd.conf.d/50-node-config-agent.conf")
	for _, want := range []string{
		"[Time]\nNTP=10.0.0.1 10.0.0.2\n",
		"FallbackNTP=pool.example.org\n",
		"PollIntervalMinSec=32\n",
		"PollIntervalMaxSec=256\n",
		"RootDistanceMaxSec=10\n",
	} {
		if !strings.Contains(dropin, want) {
			t.Fatalf("timesyncd drop-in missing %q:\n%s", want, dropin)
		}
	}
	// timesyncd re-reads config only on start — the changed drop-in
	// must bounce the unit exactly once.
	if n := len(sr.CallsMatching("systemctl restart systemd-timesyncd.service")); n != 1 {
		t.Fatalf("timesyncd restarts = %d, want 1: %v", n, sr.CallsMatching("systemctl"))
	}
	// Second cycle with identical vars is idempotent — no extra restart.
	c.groupTimesync()
	if n := len(sr.CallsMatching("systemctl restart systemd-timesyncd.service")); n != 1 {
		t.Fatalf("timesyncd restarts after second cycle = %d, want 1: %v", n, sr.CallsMatching("systemctl"))
	}
}

func TestTimesyncFallbackOnlyIncludesStealTuning(t *testing.T) {
	c, r, sr := timesyncEnv(t, `
ntp_fallback_servers: [time.cloudflare.com]
`, nil)
	c.groupTimesync()

	dropin := hostRead(t, r, "/etc/systemd/timesyncd.conf.d/50-node-config-agent.conf")
	if strings.Contains(dropin, "\nNTP=") {
		t.Fatalf("unexpected empty NTP= line:\n%s", dropin)
	}
	for _, want := range []string{
		"[Time]\nFallbackNTP=time.cloudflare.com\n",
		"PollIntervalMinSec=32\n",
		"PollIntervalMaxSec=256\n",
		"RootDistanceMaxSec=10\n",
	} {
		if !strings.Contains(dropin, want) {
			t.Fatalf("timesyncd drop-in missing %q:\n%s", want, dropin)
		}
	}
	if n := len(sr.CallsMatching("systemctl restart systemd-timesyncd.service")); n != 1 {
		t.Fatalf("timesyncd restarts = %d, want 1: %v", n, sr.CallsMatching("systemctl"))
	}
}

func TestTimesyncNoVarsWritesNoDropin(t *testing.T) {
	c, r, sr := timesyncEnv(t, "", nil)
	c.groupTimesync()

	if hostExists(r, "/etc/systemd/timesyncd.conf.d/50-node-config-agent.conf") {
		t.Fatal("drop-in written without any ntp vars — an empty NTP= would worsen a working node")
	}
	if n := len(sr.CallsMatching("systemctl restart systemd-timesyncd.service")); n != 0 {
		t.Fatalf("restart without a config change: %v", sr.CallsMatching("systemctl"))
	}
}

func TestTimesyncYieldsToChrony(t *testing.T) {
	c, r, sr := timesyncEnv(t, `
ntp_servers: [10.0.0.1]
`, nil)
	hostWrite(t, r, "/etc/chrony/chrony.conf", "pool ntppool.example.org iburst\n")
	c.groupTimesync()

	if hostExists(r, "/etc/systemd/timesyncd.conf.d/50-node-config-agent.conf") {
		t.Fatal("timesyncd drop-in written on a chrony-owned host")
	}
	if n := len(sr.CallsMatching("systemd-timesyncd")); n != 0 {
		t.Fatalf("timesyncd touched on a chrony host: %v", sr.CallsMatching("systemctl"))
	}
	// RTC-UTC still applies on chrony hosts — machine-level contract.
	scriptRTC(t, sr, "yes", "yes")
	c.groupTimesync()
	if n := len(sr.CallsMatching("timedatectl set-local-rtc 0")); n != 1 {
		t.Fatalf("chrony host skipped the RTC-UTC fix: %v", sr.CallsMatching("timedatectl"))
	}
}

func TestTimesyncRTCFixGatedOnSync(t *testing.T) {
	c, _, sr := timesyncEnv(t, "", map[string]string{
		"LocalRTC":        "yes",
		"NTPSynchronized": "no",
	})
	scriptRTC(t, sr, "yes", "no")
	c.groupTimesync()

	// A skewed clock must not bake its skew into the RTC: the policy
	// flip waits for NTP sync (the error path records it, no action).
	if n := len(sr.CallsMatching("timedatectl set-local-rtc 0")); n != 0 {
		t.Fatalf("RTC policy flipped on an unsynced clock: %v", sr.CallsMatching("timedatectl"))
	}
}

func TestTimesyncRTCConverged(t *testing.T) {
	c, _, sr := timesyncEnv(t, "", map[string]string{
		"LocalRTC":        "yes",
		"NTPSynchronized": "yes",
	})
	scriptRTC(t, sr, "yes", "yes")
	c.groupTimesync()

	if n := len(sr.CallsMatching("timedatectl set-local-rtc 0")); n != 1 {
		t.Fatalf("RTC-UTC fix missing: %v", sr.CallsMatching("timedatectl"))
	}
	if n := len(sr.CallsMatching("hwclock --systohc --utc")); n != 1 {
		t.Fatalf("synced time not baked into the RTC: %v", sr.CallsMatching("hwclock"))
	}
	// Second cycle: policy now UTC → no repeat.
	scriptRTC(t, sr, "no", "yes")
	c.groupTimesync()
	if n := len(sr.CallsMatching("timedatectl set-local-rtc 0")); n != 1 {
		t.Fatalf("RTC fix repeated after convergence: %v", sr.CallsMatching("timedatectl"))
	}
}

// scriptRTC pre-loads the timedatectl show answers the RTC branch
// probes; each call re-scripts so second cycles can see convergence.
func scriptRTC(t *testing.T, sr *testutil.FakeRunner, localRTC, synced string) {
	t.Helper()
	sr.Clear("LocalRTC")
	sr.Clear("NTPSynchronized")
	sr.On("LocalRTC", localRTC)
	sr.On("NTPSynchronized", synced)
}
