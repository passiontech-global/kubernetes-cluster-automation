// group_hosts_extra_test.go — /etc/hosts management failure arms:
// unpin/hostname-pin against an unreadable file, and the no-trailing-
// newline block-prepend contract.
package hostconfig

import (
	"strings"
	"testing"
)

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
