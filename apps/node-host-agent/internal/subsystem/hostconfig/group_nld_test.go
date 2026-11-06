// group_nld_test.go — nodelocaldns guard converge: the refuse
// path (no resolv.conf source) and the atomic resolv.conf
// symlink repoint.
package hostconfig

import (
	"os"
	"path/filepath"
	"testing"
)

// ---------- #5: groupNLD refuse path ----------

func TestNLDRefusePathSkipsWrite(t *testing.T) {
	vars := writeVarsDir(t, "")
	sr := &scriptedRunner{
		res: map[string]string{
			"systemctl show systemd-resolved.service": "active",
			"ss -lntu": "tcp  LISTEN 0  4096  127.0.0.53:53  0.0.0.0:*",
		},
		errs: map[string]bool{},
	}
	r, err := New(Config{NodeName: "node-b", HostRoot: t.TempDir(),
		VarsDir: vars, Runner: sr}, nil)
	if err != nil {
		t.Fatal(err)
	}
	// no /run/systemd/resolve/resolv.conf in hostroot
	c := loadCyc(t, r, vars, "node-b")
	c.groupNLD()

	if hostExists(r, "/etc/systemd/resolved.conf.d/99-nodelocal-stub.conf") {
		t.Fatal("stub-off drop-in written on the refuse path — DNS blackout risk")
	}
	if len(sr.callsMatching("systemctl restart systemd-resolved.service")) > 0 {
		t.Fatal("systemd-resolved restarted on the refuse path")
	}
	// the nft guard still converges (independent concern)
	if !hostExists(r, "/etc/nodelocaldns-guard.nft") {
		t.Fatal("nodelocaldns guard nft not deployed")
	}
	if len(sr.callsMatching("nft -c -f /etc/nodelocaldns-guard.nft")) == 0 {
		t.Fatal("guard ruleset not validated against the real file")
	}
}

// TestResolvConfAtomicRepoint — the T4 repoint creates the symlink
// at a temp name and renames over; no gap window and no leftover tmp.
func TestResolvConfAtomicRepoint(t *testing.T) {
	vars := writeVarsDir(t, "")
	sr := &scriptedRunner{res: map[string]string{
		"systemctl show systemd-resolved.service": "active",
		"ss -lntu": "tcp  LISTEN 0  4096  127.0.0.53:53  0.0.0.0:*",
	}, errs: map[string]bool{}}
	r, err := New(Config{NodeName: "node-b", HostRoot: t.TempDir(),
		VarsDir: vars, Runner: sr}, nil)
	if err != nil {
		t.Fatal(err)
	}
	hostWrite(t, r, "/run/systemd/resolve/resolv.conf", "nameserver 10.0.0.2\n")
	hostWrite(t, r, "/etc/resolv.conf", "nameserver 8.8.8.8\n")
	c := loadCyc(t, r, vars, "node-b")
	c.groupNLD()
	dst := filepath.Join(r.cfg.HostRoot, "etc/resolv.conf")
	fi, err := os.Lstat(dst)
	if err != nil || fi.Mode()&os.ModeSymlink == 0 {
		t.Fatalf("resolv.conf not a symlink after repoint: %v %v", fi, err)
	}
	if l, _ := os.Readlink(dst); l != "/run/systemd/resolve/resolv.conf" {
		t.Fatalf("resolv.conf -> %q", l)
	}
	if hostExists(r, "/etc/resolv.conf.hostconfig.tmp") {
		t.Fatal("temp symlink lingered after repoint")
	}
}
