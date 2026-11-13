// group_hosts_test.go — /etc/hosts managed-block helpers:
// blockInHosts create/replace/read-failure bail and the
// unpinHosts dual-marker sweep.
package hostconfig

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestUnpinRemovesBothMarkerStyles(t *testing.T) {
	vars := lbVars(t)
	sr := lbRunner()
	r := newLBHost(t, vars, sr)
	hostWrite(t, r, "/etc/hosts",
		"127.0.0.1 localhost\n"+
			"# BEGIN api-local-lb managed block\n127.0.0.1 api.test.internal\n# END api-local-lb managed block\n"+
			"# BEGIN ANSIBLE MANAGED BLOCK - api-local-lb\n127.0.0.1 api.test.internal\n# END ANSIBLE MANAGED BLOCK - api-local-lb\n")
	c := loadCyc(t, r, vars, "node-b")
	c.unpinHosts()
	hosts := hostRead(t, r, "/etc/hosts")
	if strings.Contains(hosts, "api.test.internal") || strings.Contains(hosts, "MANAGED BLOCK") {
		t.Fatalf("stale pin survived:\n%s", hosts)
	}
}

// TestBlockInHostsReadFail — a failed /etc/hosts read must bail (and
// count) rather than rewrite the file to only the managed block.
func TestBlockInHostsReadFail(t *testing.T) {
	vars := writeVarsDir(t, "")
	sr := newScripted(nil, nil)
	r, err := New(Config{NodeName: "node-b", HostRoot: t.TempDir(),
		VarsDir: vars, Runner: sr}, nil)
	if err != nil {
		t.Fatal(err)
	}
	// /etc/hosts as a DIRECTORY makes ReadFile fail.
	if err := os.MkdirAll(filepath.Join(r.cfg.HostRoot, "etc/hosts"), 0o755); err != nil {
		t.Fatal(err)
	}
	c := loadCyc(t, r, vars, "node-b")
	before := c.errs
	c.blockInHosts("x-test", "# BEGIN x-test managed block\n1.2.3.4 x\n# END x-test managed block\n")
	if c.errs == before {
		t.Fatal("hosts read failure not counted")
	}
	if fi, _ := os.Stat(filepath.Join(r.cfg.HostRoot, "etc/hosts")); !fi.IsDir() {
		t.Fatal("hosts overwritten on read failure")
	}
}

// ---------- blockInHosts ENOENT ----------

// TestBlockInHostsCreatesWhenMissing — a missing /etc/hosts is not
// the unreadable case: create it containing just the managed block.
func TestBlockInHostsCreatesWhenMissing(t *testing.T) {
	vars := writeVarsDir(t, "")
	sr := newScripted(nil, nil)
	r, err := New(Config{NodeName: "node-b", HostRoot: t.TempDir(),
		VarsDir: vars, Runner: sr}, nil)
	if err != nil {
		t.Fatal(err)
	}
	c := loadCyc(t, r, vars, "node-b")
	c.blockInHosts("x-test", "# BEGIN x-test managed block\n1.2.3.4 x\n# END x-test managed block\n")
	if c.errs != 0 {
		t.Fatalf("ENOENT hosts counted %d errors — must create instead", c.errs)
	}
	if got := hostRead(t, r, "/etc/hosts"); got !=
		"# BEGIN x-test managed block\n1.2.3.4 x\n# END x-test managed block\n" {
		t.Fatalf("hosts = %q, want just the managed block", got)
	}
}

// ---------- hostnamePin alias preservation ----------

// TestHostnamePinPreservesAliases — a re-pin swaps ONLY the hostname
// field of the 127.0.1.1 line; trailing aliases must survive
// (lineinfile parity), and a wrong-hostname line must be rewritten
// (not appended) without dropping its aliases.
func TestHostnamePinPreservesAliases(t *testing.T) {
	vars := writeVarsDir(t, "")
	sr := newScripted(nil, nil)
	r, err := New(Config{NodeName: "node-b", HostRoot: t.TempDir(),
		VarsDir: vars, Runner: sr}, nil)
	if err != nil {
		t.Fatal(err)
	}
	c := loadCyc(t, r, vars, "node-b")

	// Wrong hostname WITH aliases → rewrite the field, keep aliases.
	hostWrite(t, r, "/etc/hosts",
		"127.0.0.1 localhost\n127.0.1.1 old-host alias1 alias2\n")
	c.hostnamePin()
	hosts := hostRead(t, r, "/etc/hosts")
	if !strings.Contains(hosts, "127.0.1.1 node-b alias1 alias2\n") {
		t.Fatalf("aliases lost on re-pin:\n%s", hosts)
	}
	if strings.Contains(hosts, "old-host") {
		t.Fatalf("stale hostname survived:\n%s", hosts)
	}

	// Already correctly pinned → no duplicate pin appended.
	c.hostnamePin()
	hosts = hostRead(t, r, "/etc/hosts")
	if strings.Count(hosts, "127.0.1.1 node-b") != 1 {
		t.Fatalf("pin duplicated on converge:\n%s", hosts)
	}

	// Prefix must be matched whole-field: "node-b2" is NOT this
	// node — the pin replaces its field and keeps "node-b2" alias.
	hostWrite(t, r, "/etc/hosts",
		"127.0.0.1 localhost\n127.0.1.1 node-b2 node-b2.alias\n")
	c.hostnamePin()
	hosts = hostRead(t, r, "/etc/hosts")
	if !strings.Contains(hosts, "127.0.1.1 node-b node-b2.alias\n") {
		t.Fatalf("node-b2 line not re-pinned correctly:\n%s", hosts)
	}

	// No pin line at all → appended exactly as before.
	hostWrite(t, r, "/etc/hosts", "127.0.0.1 localhost\n")
	c.hostnamePin()
	hosts = hostRead(t, r, "/etc/hosts")
	if !strings.Contains(hosts, "127.0.0.1 localhost\n127.0.1.1 node-b\n") {
		t.Fatalf("fresh pin not appended:\n%s", hosts)
	}
}

// TestUnpinHostsReadFailureCounts — /etc/hosts unreadable: the
// managed-block removal must refuse (not rewrite a nil read to an
// empty file) and count.
func TestUnpinHostsReadFailureCounts(t *testing.T) {
	vars := writeVarsDir(t, "")
	sr := newScripted(nil, nil)
	r, err := New(Config{NodeName: "node-b", HostRoot: t.TempDir(),
		VarsDir: vars, Runner: sr}, nil)
	if err != nil {
		t.Fatal(err)
	}
	hostWrite(t, r, "/etc/hosts/keep", "blocker\n") // /etc/hosts as a dir
	c := loadCyc(t, r, vars, "node-b")
	c.unpinHosts()
	if c.errs != 1 {
		t.Fatalf("errs = %d, want the unreadable-hosts refusal counted", c.errs)
	}
	if !hostExists(r, "/etc/hosts/keep") {
		t.Fatal("/etc/hosts content destroyed by a failed read")
	}
}

// TestHostnamePinReadFailureCounts — a failed /etc/hosts read must
// NOT rewrite the file to only the hostname pin (the append path
// would drop every unmanaged entry for good).
func TestHostnamePinReadFailureCounts(t *testing.T) {
	vars := writeVarsDir(t, "")
	sr := newScripted(nil, nil)
	r, err := New(Config{NodeName: "node-b", HostRoot: t.TempDir(),
		VarsDir: vars, Runner: sr}, nil)
	if err != nil {
		t.Fatal(err)
	}
	hostWrite(t, r, "/etc/hosts/keep", "blocker\n")
	c := loadCyc(t, r, vars, "node-b")
	c.hostnamePin()
	if c.errs != 1 {
		t.Fatalf("errs = %d, want the unreadable-hosts bail counted", c.errs)
	}
	if !hostExists(r, "/etc/hosts/keep") {
		t.Fatal("/etc/hosts replaced via a failed read")
	}
}

// TestPinHostsPrependsSeparatorWithoutTrailingNewline — a hosts file
// whose last line lacks \n must not have the managed block glued onto
// it.
func TestPinHostsPrependsSeparatorWithoutTrailingNewline(t *testing.T) {
	vars := writeVarsDir(t, "")
	sr := newScripted(nil, nil)
	r, err := New(Config{NodeName: "node-b", HostRoot: t.TempDir(),
		VarsDir: vars, Runner: sr}, nil)
	if err != nil {
		t.Fatal(err)
	}
	hostWrite(t, r, "/etc/hosts", "127.0.0.1 localhost")
	c := loadCyc(t, r, vars, "node-b")
	c.pinHosts()
	got := hostRead(t, r, "/etc/hosts")
	if !strings.Contains(got, "localhost\n# BEGIN api-local-lb managed block") {
		t.Fatalf("managed block glued onto the prior entry:\n%q", got)
	}
}
