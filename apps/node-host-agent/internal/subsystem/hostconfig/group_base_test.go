// group_base_test.go — groupBase converge: self-staged agent
// binary, hostname hosts pin, and journald integrity/silent
// restart remediation with its cooldown latches.
package hostconfig

import (
	"crypto/sha256"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-host-agent/internal/platform/pagecache"
	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-host-agent/internal/testutil"
)

// ---------- host-protection-drop-ins: host-level protection files ----------

func TestGroupBaseHostProtectionFilesConverge(t *testing.T) {
	vars := writeVarsDir(t, "")
	sr := newScripted(nil, nil)
	r, err := New(Config{NodeName: "node-b", HostRoot: t.TempDir(),
		VarsDir: vars, NebulaCertsDir: t.TempDir(), WatchdogScriptsDir: t.TempDir(),
		Runner: sr}, nil)
	if err != nil {
		t.Fatal(err)
	}
	hostWrite(t, r, "/etc/hosts", "127.0.0.1 localhost\n")
	c := loadCyc(t, r, vars, "node-b")
	c.groupBase()

	networkd := hostRead(t, r, "/etc/systemd/networkd.conf.d/99-preserve-cni-routes.conf")
	for _, want := range []string{
		"[Network]", "ManageForeignRoutes=no", "ManageForeignRoutingPolicyRules=no",
	} {
		if !strings.Contains(networkd, want) {
			t.Fatalf("networkd drop-in missing %q:\n%s", want, networkd)
		}
	}
	logind := hostRead(t, r, "/etc/systemd/logind.conf.d/99-k8s-shutdown.conf")
	if !strings.Contains(logind, "[Login]") || !strings.Contains(logind, "InhibitDelayMaxSec=65") {
		t.Fatalf("bad logind drop-in:\n%s", logind)
	}
	apt := hostRead(t, r, "/etc/apt/apt.conf.d/99-k8s-unattended-safety")
	for _, want := range []string{
		`"containerd*"`, `"runc"`, `"k0s*"`, `"iptables*"`,
		`"nftables"`, `"kmod"`, `"systemd"`, `"systemd-sysv"`, `"udev"`,
		`Unattended-Upgrade::Automatic-Reboot "false";`,
	} {
		if !strings.Contains(apt, want) {
			t.Fatalf("apt safety file missing %q:\n%s", want, apt)
		}
	}
	if fi, err := os.Stat(filepath.Join(r.cfg.HostRoot,
		"/etc/apt/apt.conf.d/99-k8s-unattended-safety")); err != nil || fi.Mode().Perm() != 0o644 {
		t.Fatalf("apt safety mode = %v want 0644", fi)
	}
}

// TestGroupBaseLogindInhibitTracksGraceVar — InhibitDelayMaxSec must
// derive from the SAME kubelet_shutdown_grace_period var groupPulls
// renders into shutdownGracePeriod (+5s buffer, floor 65): the old
// hardcoded 65 left a 120s kubelet window outside logind's inhibit
// delay, so systemd killed the node mid-drain. The first write must
// also reload systemd-logind — the drop-in is inert until logind
// re-parses logind.conf — and a clean second cycle must not reload
// again.
func TestGroupBaseLogindInhibitTracksGraceVar(t *testing.T) {
	vars := writeVarsDir(t, "kubelet_shutdown_grace_period: \"120s\"\n")
	sr := newScripted(nil, nil)
	r, err := New(Config{NodeName: "node-b", HostRoot: t.TempDir(),
		VarsDir: vars, NebulaCertsDir: t.TempDir(), WatchdogScriptsDir: t.TempDir(),
		Runner: sr}, nil)
	if err != nil {
		t.Fatal(err)
	}
	hostWrite(t, r, "/etc/hosts", "127.0.0.1 localhost\n")
	c := loadCyc(t, r, vars, "node-b")
	c.groupBase()

	logind := hostRead(t, r, "/etc/systemd/logind.conf.d/99-k8s-shutdown.conf")
	if !strings.Contains(logind, "InhibitDelayMaxSec=125") { // 120s + 5s buffer
		t.Fatalf("InhibitDelayMaxSec must track the 120s grace var (+5s):\n%s", logind)
	}
	if n := len(sr.CallsMatching("systemctl reload systemd-logind.service")); n != 1 {
		t.Fatalf("logind reload after drop-in change = %d, want 1", n)
	}
	// Second cycle: byte-identical drop-in → no rewrite, no reload.
	c.groupBase()
	if n := len(sr.CallsMatching("systemctl reload systemd-logind.service")); n != 1 {
		t.Fatalf("logind reload re-run despite identical drop-in (%d reloads)", n)
	}
}

// TestGroupBaseLogindReloadFailureWarnOnly — a failed logind reload
// must NOT count a cycle error: the declared state is already on disk
// and lands at the next reload/reboot (coredump daemon-reload
// warn-only parity; a restart would tear down sessions, so it is
// reload-or-nothing).
func TestGroupBaseLogindReloadFailureWarnOnly(t *testing.T) {
	vars := writeVarsDir(t, "")
	sr := newScripted(nil, map[string]bool{
		"systemctl reload systemd-logind.service": true,
	})
	r, err := New(Config{NodeName: "node-b", HostRoot: t.TempDir(),
		VarsDir: vars, NebulaCertsDir: t.TempDir(), WatchdogScriptsDir: t.TempDir(),
		Runner: sr}, nil)
	if err != nil {
		t.Fatal(err)
	}
	hostWrite(t, r, "/etc/hosts", "127.0.0.1 localhost\n")
	c := loadCyc(t, r, vars, "node-b")
	c.groupBase()

	if c.errs != 0 {
		t.Fatalf("failed logind reload counted %d cycle errors, want warn-only", c.errs)
	}
	if logind := hostRead(t, r, "/etc/systemd/logind.conf.d/99-k8s-shutdown.conf"); logind == "" {
		t.Fatal("logind drop-in missing despite failed reload")
	}
}

// TestGroupBaseLimitNOFILEConverges — the limits drop-in renders the
// vars value verbatim plus one daemon-reload; a second cycle is
// byte-identical (no rewrite, no second reload).
func TestGroupBaseLimitNOFILEConverges(t *testing.T) {
	vars := writeVarsDir(t, "k0sworker_limit_nofile: \"1048576\"\n")
	sr := newScripted(nil, nil)
	r, err := New(Config{NodeName: "node-b", HostRoot: t.TempDir(),
		VarsDir: vars, NebulaCertsDir: t.TempDir(), WatchdogScriptsDir: t.TempDir(),
		Runner: sr}, nil)
	if err != nil {
		t.Fatal(err)
	}
	hostWrite(t, r, "/etc/hosts", "127.0.0.1 localhost\n")
	hostWrite(t, r, "/etc/systemd/system/k0sworker.service",
		"[Service]\nExecStart=/usr/bin/k0s worker --data-dir=/var/lib/k0s\n")
	c := loadCyc(t, r, vars, "node-b")
	c.groupBase()

	lim := hostRead(t, r, "/etc/systemd/system/k0sworker.service.d/10-limits.conf")
	if !strings.Contains(lim, "LimitNOFILE=1048576") {
		t.Fatalf("LimitNOFILE not rendered from var:\n%s", lim)
	}
	n := len(sr.CallsMatching("systemctl daemon-reload"))
	if n == 0 {
		t.Fatal("daemon-reload missing after drop-in change")
	}
	c.groupBase()
	if len(sr.CallsMatching("systemctl daemon-reload")) != n {
		t.Fatal("daemon-reload re-run despite identical drop-ins")
	}
}

// TestGroupBaseRefusesUnsafeLimitNOFILE — the drop-in value is a
// systemd assignment rendered verbatim: a newline-bearing var would
// inject a SECOND directive systemd applies (and an unparsable one is
// dropped at daemon-reload, silently keeping stock fd limits). The
// refused value must count an error and leave the drop-in unwritten.
func TestGroupBaseRefusesUnsafeLimitNOFILE(t *testing.T) {
	vars := writeVarsDir(t, "k0sworker_limit_nofile: \"1048576\nTasksMax=2\"\n")
	sr := newScripted(nil, nil)
	r, err := New(Config{NodeName: "node-b", HostRoot: t.TempDir(),
		VarsDir: vars, NebulaCertsDir: t.TempDir(), WatchdogScriptsDir: t.TempDir(),
		Runner: sr}, nil)
	if err != nil {
		t.Fatal(err)
	}
	hostWrite(t, r, "/etc/hosts", "127.0.0.1 localhost\n")
	hostWrite(t, r, "/etc/systemd/system/k0sworker.service",
		"[Service]\nExecStart=/usr/bin/k0s worker --data-dir=/var/lib/k0s\n")
	c := loadCyc(t, r, vars, "node-b")
	c.groupBase()

	if c.errs == 0 {
		t.Fatal("newline-bearing LimitNOFILE not counted")
	}
	if hostExists(r, "/etc/systemd/system/k0sworker.service.d/10-limits.conf") {
		t.Fatal("limits drop-in written from a refused value")
	}
}

// ---------- Coredump: coredump.conf.d disable drop-in ----------

func TestGroupBaseCoredumpDropInConverges(t *testing.T) {
	vars := writeVarsDir(t, "")
	sr := newScripted(nil, nil)
	r, err := New(Config{NodeName: "node-b", HostRoot: t.TempDir(),
		VarsDir: vars, NebulaCertsDir: t.TempDir(), WatchdogScriptsDir: t.TempDir(),
		Runner: sr}, nil)
	if err != nil {
		t.Fatal(err)
	}
	hostWrite(t, r, "/etc/hosts", "127.0.0.1 localhost\n")

	c := loadCyc(t, r, vars, "node-b")
	c.groupBase()
	jd := hostRead(t, r, "/etc/systemd/coredump.conf.d/99-node-ops.conf")
	if !strings.Contains(jd, "[Coredump]") ||
		!strings.Contains(jd, "Storage=none") ||
		!strings.Contains(jd, "ProcessSizeMax=0") {
		t.Fatalf("bad coredump drop-in:\n%s", jd)
	}
	if len(sr.CallsMatching("systemctl daemon-reload")) != 1 {
		t.Fatalf("daemon-reloads = %d, want 1 (drop-in changed)",
			len(sr.CallsMatching("systemctl daemon-reload")))
	}
	// Second cycle: content identical → no rewrite, no reload.
	c.groupBase()
	if len(sr.CallsMatching("systemctl daemon-reload")) != 1 {
		t.Fatalf("daemon-reload re-run despite identical drop-in")
	}
	if fi, err := os.Stat(filepath.Join(r.cfg.HostRoot,
		"/etc/systemd/coredump.conf.d/99-node-ops.conf")); err != nil ||
		fi.Mode().Perm() != 0o644 {
		t.Fatalf("drop-in mode = %v want 0644", fi.Mode())
	}
}

// ---------- self-stage /usr/local/bin/node-host-agent ----------

func TestSelfStageBinaryCopiesAndIsIdempotent(t *testing.T) {
	vars := writeVarsDir(t, "")
	sr := newScripted(nil, nil)
	r, err := New(Config{NodeName: "node-b", HostRoot: t.TempDir(),
		VarsDir: vars, NebulaCertsDir: t.TempDir(), WatchdogScriptsDir: t.TempDir(),
		Runner: sr}, nil)
	if err != nil {
		t.Fatal(err)
	}
	exe, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	srcb, err := os.ReadFile(exe)
	if err != nil {
		t.Fatal(err)
	}
	srcSum := sha256.Sum256(srcb)
	hostWrite(t, r, "/etc/hosts", "127.0.0.1 localhost\n")
	// stale/different host binary -> must be replaced by the running build
	hostWrite(t, r, "/usr/local/bin/node-host-agent", "stale-binary")

	c := loadCyc(t, r, vars, "node-b")
	c.groupBase()

	dst := filepath.Join(r.cfg.HostRoot, "/usr/local/bin/node-host-agent")
	got, err := os.ReadFile(dst)
	if err != nil {
		t.Fatalf("staged binary missing: %v", err)
	}
	if sha256.Sum256(got) != srcSum {
		t.Fatal("staged binary sha256 != running binary")
	}
	if fi, err := os.Stat(dst); err != nil || fi.Mode().Perm() != 0o755 {
		t.Fatalf("staged binary mode = %v want 0755", fi)
	}
	// second cycle: hash matches -> writeManaged must not rewrite
	// (the staged content survives untouched).
	c.groupBase()
	got2, _ := os.ReadFile(dst)
	if string(got2) != string(got) {
		t.Fatal("staged binary rewritten despite matching sha256")
	}
}

func TestSelfStageSkippedOnStandalone(t *testing.T) {
	vars := writeVarsDir(t, "")
	sr := newScripted(nil, nil)
	r, err := New(Config{NodeName: "node-b", HostRoot: t.TempDir(),
		VarsDir: vars, Standalone: true, Runner: sr}, nil)
	if err != nil {
		t.Fatal(err)
	}
	hostWrite(t, r, "/etc/hosts", "127.0.0.1 localhost\n")
	c := loadCyc(t, r, vars, "node-b")
	c.groupBase()
	if hostExists(r, "/usr/local/bin/node-host-agent") {
		t.Fatal("binary staged on a standalone host — /host/usr/local not mounted there")
	}
}

func TestJournaldCorruptOutputRotates(t *testing.T) {
	c, _, sr := journaldEnv(t, map[string]string{
		"journalctl -n 5": "File corruption detected at /var/log/journal/x/system.journal:0 (of 20971520 bytes, 0%)",
	}, map[string]bool{})
	// groupBase runs the probe; corrupted output must trigger the
	// rotate+vacuum remediation.
	c.groupBase()
	if len(sr.CallsMatching("journalctl --rotate --vacuum-time=3d")) == 0 {
		t.Fatalf("corrupt journal not remediated: %v", sr.CallsMatching("journalctl"))
	}
}

func TestJournaldAbnormallyEmptyRotates(t *testing.T) {
	// journalctl answers but returns nothing while journal files are
	// on disk — post-hard-reboot truncated/misindexed journal.
	c, r, sr := journaldEnv(t, map[string]string{}, map[string]bool{})
	if err := os.MkdirAll(filepath.Join(r.cfg.HostRoot, "/var/log/journal/machine-x"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(r.cfg.HostRoot,
		"/var/log/journal/machine-x/system.journal"), []byte("journal"), 0o644); err != nil {
		t.Fatal(err)
	}
	c.groupBase()
	if len(sr.CallsMatching("journalctl --rotate --vacuum-time=3d")) == 0 {
		t.Fatalf("abnormally empty journal not remediated: %v", sr.CallsMatching("journalctl"))
	}
}

func TestJournaldHealthyNoRotate(t *testing.T) {
	c, _, sr := journaldEnv(t, map[string]string{
		"journalctl -n 5": "Oct 01 10:00:00 node-b systemd[1]: Started node-host-agent.service",
	}, map[string]bool{})
	c.groupBase()
	if len(sr.CallsMatching("journalctl --rotate")) > 0 {
		t.Fatalf("healthy journal rotated: %v", sr.CallsMatching("journalctl"))
	}
}

func TestJournaldMissingBinaryNoRotate(t *testing.T) {
	// journalctl absent → probe errors with empty output; that is not
	// corruption evidence (rotating would fail anyway) — no action.
	c, _, sr := journaldEnv(t, map[string]string{}, map[string]bool{"journalctl": true})
	c.groupBase()
	if len(sr.CallsMatching("--rotate")) > 0 {
		t.Fatalf("rotate attempted without journalctl: %v", sr.CallsMatching("journalctl"))
	}
}

func TestJournaldRotateRateLimited(t *testing.T) {
	// A persistently-corrupt probe must not re-run rotate+vacuum every
	// cycle — the last-journald-rotate latch caps it to once per
	// cooldown window (a false positive would otherwise pin errs and
	// hammer the journal on every converge).
	c, _, sr := journaldEnv(t, map[string]string{
		"journalctl -n 5": "File corruption detected at /var/log/journal/x/system.journal:0 (of 20971520 bytes, 0%)",
	}, map[string]bool{})
	c.groupBase()
	c.groupBase()
	if got := len(sr.CallsMatching("journalctl --rotate --vacuum-time=3d")); got != 1 {
		t.Fatalf("rotate ran %d times, want 1 (cooldown latch)", got)
	}
}

func TestJournaldSilentNoFilesRestarts(t *testing.T) {
	// Incident shape: journalctl answers "No journal files were
	// found." while a journal storage root exists — journald is
	// writing nowhere and must be restarted (rotate cannot create
	// files).
	c, r, sr := journaldEnv(t, map[string]string{
		"journalctl -n 5": "No journal files were found.\n",
	}, map[string]bool{})
	if err := os.MkdirAll(filepath.Join(r.cfg.HostRoot, "/var/log/journal/machine-x"), 0o755); err != nil {
		t.Fatal(err)
	}
	c.groupBase()
	if len(sr.CallsMatching("systemctl restart systemd-journald.service")) == 0 {
		t.Fatalf("silent journald not restarted: %v", sr.CallsMatching("systemctl"))
	}
	if len(sr.CallsMatching("journalctl --rotate")) > 0 {
		t.Fatal("rotate ran for a file-less journal — rotate cannot create files")
	}
}

func TestJournaldSilentEmptyNoFilesRestarts(t *testing.T) {
	// Same verdict without the notice text (suppressed/locale): a
	// literally empty read + a storage root + zero *.journal files.
	c, r, sr := journaldEnv(t, map[string]string{}, map[string]bool{})
	if err := os.MkdirAll(filepath.Join(r.cfg.HostRoot, "/var/log/journal/machine-x"), 0o755); err != nil {
		t.Fatal(err)
	}
	c.groupBase()
	if len(sr.CallsMatching("systemctl restart systemd-journald.service")) == 0 {
		t.Fatalf("empty journal with storage root not restarted: %v", sr.CallsMatching("systemctl"))
	}
}

func TestJournaldSilentNoStorageNoRestart(t *testing.T) {
	// No journal storage at all → journald legitimately absent —
	// silence is configuration, not a fault: no restart, no rotate.
	c, _, sr := journaldEnv(t, map[string]string{
		"journalctl -n 5": "No journal files were found.\n",
	}, map[string]bool{})
	c.groupBase()
	if len(sr.CallsMatching("systemctl restart systemd-journald.service")) > 0 {
		t.Fatal("journald restarted with no storage configured")
	}
	if len(sr.CallsMatching("journalctl --rotate")) > 0 {
		t.Fatal("rotate ran with no storage configured")
	}
}

func TestJournaldSilentRestartRateLimited(t *testing.T) {
	c, r, sr := journaldEnv(t, map[string]string{
		"journalctl -n 5": "No journal files were found.\n",
	}, map[string]bool{})
	if err := os.MkdirAll(filepath.Join(r.cfg.HostRoot, "/var/log/journal/machine-x"), 0o755); err != nil {
		t.Fatal(err)
	}
	c.groupBase()
	c.groupBase()
	if got := len(sr.CallsMatching("systemctl restart systemd-journald.service")); got != 1 {
		t.Fatalf("journald restarts = %d, want 1 (last-journald-restart cooldown)", got)
	}
}

// TestHostnamePinNoGlueOnMissingNewline — a hosts file without a
// trailing newline must not fuse the 127.0.1.1 pin onto the last
// existing line.
func TestHostnamePinNoGlueOnMissingNewline(t *testing.T) {
	c, r, _ := journaldEnv(t, map[string]string{
		"journalctl -n 5": "ok",
	}, map[string]bool{})
	hostWrite(t, r, "/etc/hosts", "127.0.0.1 localhost") // NO trailing \n
	c.groupBase()
	hosts := hostRead(t, r, "/etc/hosts")
	if !strings.Contains(hosts, "127.0.0.1 localhost\n127.0.1.1 node-b\n") {
		t.Fatalf("hostname pin glued onto the last line:\n%q", hosts)
	}
}

// The 127.0.1.1 pin must match the hostname as a whole field —
// "127.0.1.1 worker-10" satisfied the old substring check for
// hn="worker-1" and left the wrong pin live.
func TestHostsPinHostnameFieldExact(t *testing.T) {
	vars := writeVarsDir(t, "")
	sr := newScripted(nil, nil)
	r, err := New(Config{NodeName: "worker-1", HostRoot: t.TempDir(),
		VarsDir: vars, NebulaCertsDir: t.TempDir(), WatchdogScriptsDir: t.TempDir(),
		Runner: sr}, nil)
	if err != nil {
		t.Fatal(err)
	}
	hostWrite(t, r, "/etc/hosts", "127.0.0.1 localhost\n127.0.1.1 worker-10\n")

	c := loadCyc(t, r, vars, "worker-1")
	c.groupBase()

	hosts := hostRead(t, r, "/etc/hosts")
	if !strings.Contains(hosts, "127.0.1.1 worker-1\n") {
		t.Fatalf("correct pin not written:\n%s", hosts)
	}
	if strings.Contains(hosts, "worker-10") {
		t.Fatalf("stale worker-10 pin kept:\n%s", hosts)
	}
	// Idempotent: the exact pin already present is left untouched.
	c.groupBase()
	if got := hostRead(t, r, "/etc/hosts"); got != hosts {
		t.Fatalf("hosts rewritten despite exact pin:\n%s", got)
	}
}

// TestConntrackHashsizeConverge — conntrack_max=524288 must persist
// hashsize=131072 (max(max/4, 65536)) in modprobe.d AND grow the
// live table when the running hashsize is smaller. A live value at
// or above the want is left alone (kernel shrinks are refused).
func TestConntrackHashsizeConverge(t *testing.T) {
	vars := writeVarsDir(t, "conntrack_max: \"524288\"\n")
	sr := newScripted(nil, nil)
	r, err := New(Config{NodeName: "node-b", HostRoot: t.TempDir(),
		VarsDir: vars, NebulaCertsDir: t.TempDir(), WatchdogScriptsDir: t.TempDir(),
		Runner: sr, Standalone: true}, nil)
	if err != nil {
		t.Fatal(err)
	}
	hostWrite(t, r, "/etc/hosts", "127.0.0.1 localhost\n")
	// Live table below the want -> must be grown in place.
	hostWrite(t, r, "/sys/module/nf_conntrack/parameters/hashsize", "16384\n")

	c := loadCyc(t, r, vars, "node-b")
	c.conntrackHashsize()

	conf := hostRead(t, r, "/etc/modprobe.d/nf_conntrack.conf")
	if !strings.Contains(conf, "options nf_conntrack hashsize=131072") {
		t.Fatalf("modprobe.d hashsize not persisted:\n%s", conf)
	}
	if got := hostRead(t, r, "/sys/module/nf_conntrack/parameters/hashsize"); strings.TrimSpace(got) != "131072" {
		t.Fatalf("live hashsize = %q, want 131072", got)
	}

	// A live table already at/above the want is never shrunk.
	hostWrite(t, r, "/sys/module/nf_conntrack/parameters/hashsize", "262144\n")
	c.conntrackHashsize()
	if got := hostRead(t, r, "/sys/module/nf_conntrack/parameters/hashsize"); strings.TrimSpace(got) != "262144" {
		t.Fatalf("live hashsize shrunk to %q, want 262144", got)
	}
}

// TestConntrackHashsizeDefault — no conntrack_max var keeps the
// 262144 table default, giving wantBuckets 65536 (the floor).
func TestConntrackHashsizeDefault(t *testing.T) {
	vars := writeVarsDir(t, "")
	sr := newScripted(nil, nil)
	r, err := New(Config{NodeName: "node-b", HostRoot: t.TempDir(),
		VarsDir: vars, NebulaCertsDir: t.TempDir(), WatchdogScriptsDir: t.TempDir(),
		Runner: sr, Standalone: true}, nil)
	if err != nil {
		t.Fatal(err)
	}
	hostWrite(t, r, "/etc/hosts", "127.0.0.1 localhost\n")
	hostWrite(t, r, "/sys/module/nf_conntrack/parameters/hashsize", "16384\n")
	c := loadCyc(t, r, vars, "node-b")
	c.conntrackHashsize()
	conf := hostRead(t, r, "/etc/modprobe.d/nf_conntrack.conf")
	if !strings.Contains(conf, "hashsize=65536") {
		t.Fatalf("default hashsize want 65536:\n%s", conf)
	}
	if got := hostRead(t, r, "/sys/module/nf_conntrack/parameters/hashsize"); strings.TrimSpace(got) != "65536" {
		t.Fatalf("live hashsize = %q, want 65536", got)
	}
}

// On chrony hosts systemd-timesyncd is installed but INACTIVE —
// the conf drop-in still lands but the service must NOT be
// restarted (a second NTP daemon would fight chrony for adjtimex).
func TestGroupResolvedTimesyncdRestartGatedOnActive(t *testing.T) {
	newCyc := func(t *testing.T, timesyncdState string) (*cyc, *testutil.FakeRunner, *Reconciler) {
		vars := writeVarsDir(t, "")
		sr := newScripted(map[string]string{
			"systemctl show systemd-resolved.service":  "active\n",
			"systemctl show systemd-timesyncd.service": timesyncdState,
		}, nil)
		r, err := New(Config{NodeName: "node-x", HostRoot: t.TempDir(),
			VarsDir: vars, NebulaCertsDir: t.TempDir(), WatchdogScriptsDir: t.TempDir(),
			Runner: sr}, nil)
		if err != nil {
			t.Fatal(err)
		}
		return loadCyc(t, r, vars, "node-x"), sr, r
	}

	c, sr, r := newCyc(t, "inactive\n")
	c.groupResolved()
	if !r.fileExists("/etc/systemd/timesyncd.conf.d/99-fallback.conf") {
		t.Fatal("timesyncd fallback conf not written for an installed unit")
	}
	if len(sr.CallsMatching("systemctl restart systemd-timesyncd.service")) > 0 {
		t.Fatalf("inactive timesyncd restarted: %v",
			sr.CallsMatching("systemctl restart systemd-timesyncd.service"))
	}

	c2, sr2, _ := newCyc(t, "active\n")
	c2.groupResolved()
	if len(sr2.CallsMatching("systemctl restart systemd-timesyncd.service")) == 0 {
		t.Fatal("active timesyncd not restarted after conf change")
	}
}

// baseFixture — a reconciler + runner + cyc with the stock registry;
// seed extra files per test.
func baseFixture(t *testing.T, cluster string) (*Reconciler, *testutil.FakeRunner, *cyc) {
	t.Helper()
	vars := writeVarsDir(t, cluster)
	sr := newScripted(nil, nil)
	r, err := New(Config{NodeName: "node-b", HostRoot: t.TempDir(),
		VarsDir: vars, NebulaCertsDir: t.TempDir(), WatchdogScriptsDir: t.TempDir(),
		Runner: sr}, nil)
	if err != nil {
		t.Fatal(err)
	}
	return r, sr, loadCyc(t, r, vars, "node-b")
}

// TestBaseInotifySysctlGates — a refused (non-printable) value skips
// its pair; a custom value renders verbatim.
func TestBaseInotifySysctlGates(t *testing.T) {
	r, _, c := baseFixture(t, `inotify_max_user_watches: "1\n2"
inotify_max_user_instances: "1024"
`)
	c.groupBase()
	f := hostRead(t, r, "/etc/sysctl.d/99-k8s-inotify.conf")
	if strings.Contains(f, "max_user_watches") {
		t.Fatalf("refused watches value rendered anyway:\n%s", f)
	}
	if !strings.Contains(f, "fs.inotify.max_user_instances = 1024") {
		t.Fatalf("custom instances value missing:\n%s", f)
	}
	if c.errs != 1 {
		t.Fatalf("errs = %d, want exactly the refused value", c.errs)
	}
}

// TestBaseModprobeAndSysctlFailures — the batched BBR/conntrack
// modprobe failure and a failed `sysctl --system` apply each count;
// the files still land for the next boot.
func TestBaseModprobeAndSysctlFailures(t *testing.T) {
	r, sr, c := baseFixture(t, "")
	sr.FailOn("modprobe -a tcp_bbr nf_conntrack", nil)
	sr.FailOn("sysctl --system", nil)
	c.groupBase()
	if c.errs != 2 {
		t.Fatalf("errs = %d, want 1 modprobe + 1 sysctl counted", c.errs)
	}
	if !hostExists(r, "/etc/modules-load.d/interdc-bbr.conf") {
		t.Fatal("bbr module-load file not converged despite the modprobe failure")
	}
}

// TestBaseAbsentLimitVarsNoError — worker/controller nodes whose vars
// lack k0sworker/k0scontroller_limit_nofile converge clean: an absent
// var is skipped like the sysctl pairs, not refused (refusing the
// empty value would count an error every cycle and fail converge-once
// on healthy nodes).
func TestBaseAbsentLimitVarsNoError(t *testing.T) {
	r, _, c := baseFixture(t, "")
	hostWrite(t, r, "/etc/systemd/system/k0sworker.service", "[Service]\n")
	hostWrite(t, r, "/etc/systemd/system/k0scontroller.service", "[Service]\n")
	c.groupBase()
	if c.errs != 0 {
		t.Fatalf("healthy node without limit vars counted %d errors", c.errs)
	}
	if hostExists(r, "/etc/systemd/system/k0sworker.service.d/10-limits.conf") ||
		hostExists(r, "/etc/systemd/system/k0scontroller.service.d/10-limits.conf") {
		t.Fatal("limits drop-in written from an absent var")
	}
}

// TestBaseControllerLimitsDropin — the controller fd-limits drop-in
// converges both ways: rendered on a valid var, refused+skipped on an
// unsafe one, daemon-reload only when it actually landed.
func TestBaseControllerLimitsDropin(t *testing.T) {
	r, sr, c := baseFixture(t, `k0scontroller_limit_nofile: "1048576"
`)
	hostWrite(t, r, "/etc/systemd/system/k0scontroller.service", "[Service]\n")
	c.groupBase()
	f := hostRead(t, r, "/etc/systemd/system/k0scontroller.service.d/10-limits.conf")
	if !strings.Contains(f, "LimitNOFILE=1048576") || !strings.Contains(f, "LimitNPROC=infinity") {
		t.Fatalf("limits drop-in wrong:\n%s", f)
	}
	if len(sr.CallsMatching("systemctl daemon-reload")) == 0 {
		t.Fatal("limits drop-in did not daemon-reload")
	}

	// Refused value: the splice-shaped var must leave no drop-in.
	vars := writeVarsDir(t, `k0scontroller_limit_nofile: "1
2"
`)
	sr2 := newScripted(nil, nil)
	r2, err := New(Config{NodeName: "node-b", HostRoot: t.TempDir(),
		VarsDir: vars, Runner: sr2}, nil)
	if err != nil {
		t.Fatal(err)
	}
	hostWrite(t, r2, "/etc/systemd/system/k0scontroller.service", "[Service]\n")
	c2 := loadCyc(t, r2, vars, "node-b")
	c2.groupBase()
	if hostExists(r2, "/etc/systemd/system/k0scontroller.service.d/10-limits.conf") {
		t.Fatal("unsafe LimitNOFILE value rendered a drop-in")
	}
	if c2.errs == 0 {
		t.Fatal("refused LimitNOFILE did not count a cycle error")
	}
}

// TestBaseMultipathDropin — the multipathd blacklist only converges
// when multipath is actually present on the host.
func TestBaseMultipathDropin(t *testing.T) {
	r, _, c := baseFixture(t, "")
	c.groupBase()
	if hostExists(r, "/etc/multipath/conf.d/99-k8s-node-ops.conf") {
		t.Fatal("multipath drop-in created on a host without multipath")
	}
	hostWrite(t, r, "/etc/multipath.conf", "# defaults\n")
	c.groupBase()
	f := hostRead(t, r, "/etc/multipath/conf.d/99-k8s-node-ops.conf")
	if !strings.Contains(f, `devnode "^(sd[a-z0-9]+`) {
		t.Fatalf("multipath blacklist missing:\n%s", f)
	}
}

// TestLogindInhibitDelaySecsTable — the kubelet graceful-shutdown
// window + 5s buffer, floored at 65s; unparsable/zero falls back to
// the 60s default (+ buffer).
func TestLogindInhibitDelaySecsTable(t *testing.T) {
	for _, tc := range []struct {
		in   string
		want int64
	}{
		{"garbage", 65},
		{"0", 65},
		{"-5s", 65},
		{"45s", 65},
		{"60s", 65},
		{"70s", 75},
		{"10m", 605},
	} {
		if got := logindInhibitDelaySecs(tc.in); got != tc.want {
			t.Errorf("logindInhibitDelaySecs(%q) = %d, want %d", tc.in, got, tc.want)
		}
	}
}

// TestSelfStageBinaryModeRetighten — the host copy already carries
// this build but drifted to 0644: no rewrite, just the chmod back to
// 0755 (the hostPath consumer needs the exec bit).
func TestSelfStageBinaryModeRetighten(t *testing.T) {
	r, _, c := baseFixture(t, "")
	src, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	sum, err := pagecache.Sha256File(src)
	if err != nil {
		t.Fatal(err)
	}
	hostWrite(t, r, "/usr/local/bin/node-host-agent", "")
	// Replace the seeded empty file with the REAL test binary content.
	bin, err := os.ReadFile(src)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(r.cfg.HostRoot, "/usr/local/bin/node-host-agent"), bin, 0o644); err != nil {
		t.Fatal(err)
	}
	c.selfStageBinary()
	fi, err := os.Stat(filepath.Join(r.cfg.HostRoot, "/usr/local/bin/node-host-agent"))
	if err != nil {
		t.Fatal(err)
	}
	if fi.Mode().Perm() != 0o755 {
		t.Fatalf("staged binary mode = %v, want re-tightened 0755", fi.Mode().Perm())
	}
	got, err := pagecache.Sha256File(filepath.Join(r.cfg.HostRoot, "/usr/local/bin/node-host-agent"))
	if err != nil || got != sum {
		t.Fatalf("staged binary content churned (sha %v err %v)", got, err)
	}
	if c.errs != 0 {
		t.Fatalf("mode re-tighten counted errors: %d", c.errs)
	}
}

// TestSelfStageBinaryInstallFailure — the host copy drifts to OTHER
// content while the destination path is a directory: the atomic
// replace fails, the failure is counted once, and the node keeps its
// (stale) target.
func TestSelfStageBinaryInstallFailure(t *testing.T) {
	r, _, c := baseFixture(t, "")
	if err := os.MkdirAll(filepath.Join(r.cfg.HostRoot, "/usr/local/bin/node-host-agent"), 0o755); err != nil {
		t.Fatal(err)
	}
	c.selfStageBinary()
	if c.errs != 1 {
		t.Fatalf("errs = %d, want the failed install counted once", c.errs)
	}
}

// TestConntrackHashsizeArms — want = max(conntrack_max/4, 65536):
// the floor applies under a small pin, the live module parameter is
// bumped when smaller, an unparsable live file is skipped, and a
// refused write counts.
func TestConntrackHashsizeArms(t *testing.T) {
	t.Run("floor_65536", func(t *testing.T) {
		r, _, c := baseFixture(t, "conntrack_max: 100000\n")
		c.groupBase()
		f := hostRead(t, r, "/etc/modprobe.d/nf_conntrack.conf")
		if !strings.Contains(f, "hashsize=65536") {
			t.Fatalf("hashsize floor not applied:\n%s", f)
		}
	})
	t.Run("live_bump", func(t *testing.T) {
		r, _, c := baseFixture(t, "")
		hostWrite(t, r, "/sys/module/nf_conntrack/parameters/hashsize", "1024\n")
		c.groupBase()
		if got := strings.TrimSpace(hostRead(t, r, "/sys/module/nf_conntrack/parameters/hashsize")); got != "65536" {
			t.Fatalf("live hashsize = %q, want grown to 65536", got)
		}
	})
	t.Run("write_refused", func(t *testing.T) {
		r, _, c := baseFixture(t, "")
		p := filepath.Join(r.cfg.HostRoot, "/sys/module/nf_conntrack/parameters/hashsize")
		if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(p, []byte("1024\n"), 0o444); err != nil {
			t.Fatal(err)
		}
		c.groupBase()
		if c.errs == 0 {
			t.Fatal("refused hashsize grow did not count a cycle error")
		}
	})
}

// TestSysctlPtyMaxOverride — pty.max renders (gated on the procfs
// file the sandbox HostRoot seeds) with the vars override winning
// over the 16384 default.
func TestSysctlPtyMaxOverride(t *testing.T) {
	r, _, c := baseFixture(t, "pty_max: 4096\n")
	hostWrite(t, r, "/proc/sys/kernel/pty/max", "16384\n")
	c.groupBase()
	f := hostRead(t, r, "/etc/sysctl.d/99-k8s-network-tuning.conf")
	if !strings.Contains(f, "kernel.pty.max = 4096") {
		t.Fatalf("pty_max override missing:\n%s", f)
	}

	// Default when the var is absent.
	vars := writeVarsDir(t, "")
	sr := newScripted(nil, nil)
	r2, err := New(Config{NodeName: "node-b", HostRoot: t.TempDir(),
		VarsDir: vars, Runner: sr}, nil)
	if err != nil {
		t.Fatal(err)
	}
	hostWrite(t, r2, "/proc/sys/kernel/pty/max", "16384\n")
	c2 := loadCyc(t, r2, vars, "node-b")
	c2.groupBase()
	if f := hostRead(t, r2, "/etc/sysctl.d/99-k8s-network-tuning.conf"); !strings.Contains(f, "kernel.pty.max = 16384") {
		t.Fatalf("pty default missing:\n%s", f)
	}
}
