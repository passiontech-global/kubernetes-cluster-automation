// group_security_test.go — sshd hardening drop-in and the
// fail2ban ignoreip derivation from mesh node IPs.
package hostconfig

import (
	"strings"
	"testing"
)

// ---------- #4: fail2ban ignoreip derivation ----------

func TestFail2BanIgnoreIPDerived(t *testing.T) {
	vars := writeVarsDir(t, "fail2ban_ignoreip_extra: \"192.168.0.0/16\"\n")
	sr := newScripted(nil, nil)
	r, err := New(Config{NodeName: "node-b", HostRoot: t.TempDir(),
		VarsDir: vars, Runner: sr}, nil)
	if err != nil {
		t.Fatal(err)
	}
	c := loadCyc(t, r, vars, "node-b")
	got := c.fail2banIgnoreIP()
	want := "127.0.0.1/8 ::1 10.0.1.10 10.0.1.30 10.0.2.20 192.168.0.0/16"
	if got != want {
		t.Fatalf("ignoreip=%q want %q", got, want)
	}
}

// ---------- #20/#21: security files ----------

func TestSecurityFileContents(t *testing.T) {
	vars := writeVarsDir(t, "")
	sr := newScripted(map[string]string{
		"dpkg-query -W -f=${db:Status-Status} fail2ban": "installed",
		"sshd -T": "passwordauthentication no",
	}, nil)
	r, err := New(Config{NodeName: "node-b", HostRoot: t.TempDir(),
		VarsDir: vars, Runner: sr}, nil)
	if err != nil {
		t.Fatal(err)
	}
	c := loadCyc(t, r, vars, "node-b")
	c.groupSecurity()

	jail := hostRead(t, r, "/etc/fail2ban/jail.d/90-cluster-sshd.conf")
	if !strings.Contains(jail, "ignoreip = 127.0.0.1/8 ::1 10.0.1.10 10.0.1.30 10.0.2.20") {
		t.Fatalf("jail ignoreip not derived:\n%s", jail)
	}
	sshd := hostRead(t, r, "/etc/ssh/sshd_config.d/00-passiontech-hardening.conf")
	for _, want := range []string{
		"KbdInteractiveAuthentication no", "PubkeyAuthentication yes",
		"MaxAuthTries 3", "LoginGraceTime 30", "X11Forwarding no",
		"ClientAliveInterval 300", "ClientAliveCountMax 2",
	} {
		if !strings.Contains(sshd, want) {
			t.Fatalf("sshd drop-in missing %q:\n%s", want, sshd)
		}
	}
}
