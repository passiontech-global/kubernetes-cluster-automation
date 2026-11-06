// deps_env_test.go — DepsFromEnv: env resolution + defaults + the
// conf-parse-failure fallback, locked to the semantics
// buildAgentConfig used to resolve inline.

package hostctx

import (
	"path/filepath"
	"testing"

	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-host-agent/internal/platform/systemd"
)

// testParams is the pod-mode shape callers pass: host-root joiner,
// resolved root/name, shared systemd client.
func testParams(root, node string) EnvParams {
	hostPath := func(p string) string {
		if root == "/" {
			return p
		}
		return root + p
	}
	return EnvParams{
		HostPath: hostPath,
		HostRoot: root,
		NodeName: node,
		Systemd:  systemd.New(systemd.Config{HostRoot: root}),
	}
}

// TestDepsFromEnvDefaults pins the compiled defaults: every host path
// is hostPath-prefixed ("/host" in pod mode), journal dirs are the
// two standard locations, and the non-env params pass through.
func TestDepsFromEnvDefaults(t *testing.T) {
	for _, k := range []string{
		"NODE_HOST_AGENT_WATCHDOG_CONF",
		"NODE_HOST_AGENT_WATCHDOG_STATE_DIR",
		"NODE_HOST_AGENT_WATCHDOG_LOG",
		"NODE_HOST_AGENT_JOURNAL_DIRS",
		"NODE_HOST_AGENT_JOURNAL_UNREADABLE_NEEDED",
		"NODE_HOST_AGENT_HOSTCONFIG_VARS_DIR",
		"NODE_HOST_AGENT_TEXTFILE_DIR",
		"NODE_HOST_AGENT_NODE_NAME",
	} {
		t.Setenv(k, "") // envx treats empty as unset — hermetic defaults
	}
	t.Setenv("NODE_HOST_AGENT_WATCHDOG_CONF",
		filepath.Join(t.TempDir(), "absent.conf"))

	d := DepsFromEnv(testParams("/host", "node-a"))

	if d.WatchdogStateDir != "/host/var/lib/node-watchdog" {
		t.Fatalf("WatchdogStateDir=%q", d.WatchdogStateDir)
	}
	if d.WatchdogLogFile != "/host/var/log/node-watchdog.log" {
		t.Fatalf("WatchdogLogFile=%q", d.WatchdogLogFile)
	}
	if d.VarsDir != "/config/vars" {
		t.Fatalf("VarsDir=%q", d.VarsDir)
	}
	if d.TextfileDir != "/host/var/lib/node-exporter/textfile" {
		t.Fatalf("TextfileDir=%q", d.TextfileDir)
	}
	want := []string{"/host/var/log/journal", "/host/run/log/journal"}
	if len(d.JournalDirs) != 2 || d.JournalDirs[0] != want[0] ||
		d.JournalDirs[1] != want[1] {
		t.Fatalf("JournalDirs=%v want %v", d.JournalDirs, want)
	}
	if d.JournalUnreadableNeeded != 5 {
		t.Fatalf("JournalUnreadableNeeded=%d want 5",
			d.JournalUnreadableNeeded)
	}
	if d.NodeName != "node-a" {
		t.Fatalf("NodeName=%q want node-a", d.NodeName)
	}
	if d.HostRoot != "/host" || d.HostPath("/x") != "/host/x" {
		t.Fatalf("HostRoot/HostPath not passed through: %+v", d)
	}
	if d.Systemd == nil {
		t.Fatal("Systemd is nil")
	}
	// A missing conf is not an error — the watchdog contract is an
	// all-defaults Config plus a live reloader pointed at the path.
	if d.Watchdog == nil || d.Watchdog.NebulaNet != "interdc" {
		t.Fatalf("Watchdog=%+v want defaults", d.Watchdog)
	}
	if d.WatchdogSrc == nil {
		t.Fatal("WatchdogSrc is nil")
	}
}

// TestDepsPathJoin pins the nil-safe accessor the consumers call
// instead of re-declaring the fallback: nil HostPath → identity join
// (the documented nil-dep contract), non-nil → the join applied.
func TestDepsPathJoin(t *testing.T) {
	var d Deps
	if got := d.PathJoin("/etc/hosts"); got != "/etc/hosts" {
		t.Fatalf("nil HostPath: PathJoin=%q want identity", got)
	}
	d.HostPath = func(p string) string { return "/host" + p }
	if got := d.PathJoin("/etc/hosts"); got != "/host/etc/hosts" {
		t.Fatalf("PathJoin=%q want /host/etc/hosts", got)
	}
}

// TestDepsFromEnvStandalonePaths: root "/" makes hostPath the
// identity — the same knobs land unprefixed on standalone hosts.
func TestDepsFromEnvStandalonePaths(t *testing.T) {
	for _, k := range []string{
		"NODE_HOST_AGENT_WATCHDOG_CONF",
		"NODE_HOST_AGENT_WATCHDOG_STATE_DIR",
		"NODE_HOST_AGENT_WATCHDOG_LOG",
		"NODE_HOST_AGENT_JOURNAL_DIRS",
		"NODE_HOST_AGENT_JOURNAL_UNREADABLE_NEEDED",
		"NODE_HOST_AGENT_HOSTCONFIG_VARS_DIR",
		"NODE_HOST_AGENT_TEXTFILE_DIR",
		"NODE_HOST_AGENT_NODE_NAME",
	} {
		t.Setenv(k, "")
	}
	t.Setenv("NODE_HOST_AGENT_WATCHDOG_CONF",
		filepath.Join(t.TempDir(), "absent.conf"))

	d := DepsFromEnv(testParams("/", "n"))
	if d.WatchdogStateDir != "/var/lib/node-watchdog" {
		t.Fatalf("WatchdogStateDir=%q want unprefixed", d.WatchdogStateDir)
	}
	if d.JournalDirs[0] != "/var/log/journal" {
		t.Fatalf("JournalDirs=%v want unprefixed", d.JournalDirs)
	}
}

// TestDepsFromEnvOverrides: every shared knob env-overridable, and
// NODE_HOST_AGENT_NODE_NAME still wins over the passed-in name
// (env > flag precedence kept from the old main.go resolution).
func TestDepsFromEnvOverrides(t *testing.T) {
	conf := filepath.Join(t.TempDir(), "wd.conf")
	t.Setenv("NODE_HOST_AGENT_WATCHDOG_CONF", conf)
	t.Setenv("NODE_HOST_AGENT_WATCHDOG_STATE_DIR", "/x/state")
	t.Setenv("NODE_HOST_AGENT_WATCHDOG_LOG", "/x/wd.log")
	t.Setenv("NODE_HOST_AGENT_JOURNAL_DIRS", "/j1, /j2")
	t.Setenv("NODE_HOST_AGENT_JOURNAL_UNREADABLE_NEEDED", "9")
	t.Setenv("NODE_HOST_AGENT_HOSTCONFIG_VARS_DIR", "/x/vars")
	t.Setenv("NODE_HOST_AGENT_TEXTFILE_DIR", "/x/textfile")
	t.Setenv("NODE_HOST_AGENT_NODE_NAME", "env-node")

	d := DepsFromEnv(testParams("/host", "flag-node"))

	if d.WatchdogSrc == nil {
		t.Fatal("WatchdogSrc is nil")
	}
	if d.WatchdogSrc.Path != conf {
		t.Fatalf("WatchdogSrc.Path=%q want %q", d.WatchdogSrc.Path, conf)
	}
	if d.WatchdogStateDir != "/x/state" ||
		d.WatchdogLogFile != "/x/wd.log" ||
		d.VarsDir != "/x/vars" || d.TextfileDir != "/x/textfile" {
		t.Fatalf("env overrides ignored: %+v", d)
	}
	if len(d.JournalDirs) != 2 || d.JournalDirs[0] != "/j1" ||
		d.JournalDirs[1] != "/j2" {
		t.Fatalf("JournalDirs=%v want [/j1 /j2]", d.JournalDirs)
	}
	if d.JournalUnreadableNeeded != 9 {
		t.Fatalf("JournalUnreadableNeeded=%d want 9",
			d.JournalUnreadableNeeded)
	}
	if d.NodeName != "env-node" {
		t.Fatalf("NodeName=%q want env-node (env wins)", d.NodeName)
	}
}
