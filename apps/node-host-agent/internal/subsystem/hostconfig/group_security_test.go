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

// TestSecurityFail2BanInstallFailureCounts — a missing fail2ban whose
// apt install fails counts and aborts the group (api-lb parity): no
// jail file at the live path and no service/probe churn against a
// missing daemon (the half-applied state would error every cycle).
func TestSecurityFail2BanInstallFailureCounts(t *testing.T) {
	vars := writeVarsDir(t, "")
	sr := newScripted(map[string]string{
		"sshd -T": "passwordauthentication no",
	}, nil)
	sr.FailOn("apt-get install -y fail2ban", nil)
	r, err := New(Config{NodeName: "node-b", HostRoot: t.TempDir(),
		VarsDir: vars, Runner: sr}, nil)
	if err != nil {
		t.Fatal(err)
	}
	c := loadCyc(t, r, vars, "node-b")
	c.groupSecurity()
	if c.errs != 1 {
		t.Fatalf("errs = %d, want exactly the install failure", c.errs)
	}
	if hostExists(r, "/etc/fail2ban/jail.d/90-cluster-sshd.conf") {
		t.Fatal("jail written although the package never installed")
	}
	if len(sr.CallsMatching("fail2ban.service")) > 0 {
		t.Fatal("fail2ban.service touched although the package never installed")
	}
	if len(sr.CallsMatching("fail2ban-client status sshd")) > 0 {
		t.Fatal("fail2ban-client probed against a missing package")
	}
}

// TestSecurityFail2BanPurgePath — fail2ban_enabled DEFINED as false
// removes the jail + stale names and purges the package; a purge
// failure counts.
func TestSecurityFail2BanPurgePath(t *testing.T) {
	vars := writeVarsDir(t, "fail2ban_enabled: false\n")
	sr := newScripted(map[string]string{
		"sshd -T": "passwordauthentication no",
	}, nil)
	r, err := New(Config{NodeName: "node-b", HostRoot: t.TempDir(),
		VarsDir: vars, Runner: sr}, nil)
	if err != nil {
		t.Fatal(err)
	}
	hostWrite(t, r, "/etc/fail2ban/jail.d/90-cluster-sshd.conf", "[sshd]\n")
	hostWrite(t, r, "/etc/fail2ban/jail.d/cluster.conf", "[sshd]\n")
	c := loadCyc(t, r, vars, "node-b")
	c.groupSecurity()
	if hostExists(r, "/etc/fail2ban/jail.d/90-cluster-sshd.conf") ||
		hostExists(r, "/etc/fail2ban/jail.d/cluster.conf") {
		t.Fatal("jails not removed on the disabled-defined path")
	}
	if len(sr.CallsMatching("apt-get purge -y fail2ban")) == 0 {
		t.Fatal("package not purged on the disabled-defined path")
	}
	if c.errs != 0 {
		t.Fatalf("clean purge counted errors: %d", c.errs)
	}

	// Purge failure counts.
	sr.FailOn("apt-get purge -y fail2ban", nil)
	c.groupSecurity()
	if c.errs != 1 {
		t.Fatalf("errs = %d, want the purge failure counted", c.errs)
	}
}

// TestSecuritySshdValidateGate — a failing `sshd -t` must abort the
// restart of ssh.service (a broken drop-in must never take sshd down
// on a public node) while counting the refusal.
func TestSecuritySshdValidateGate(t *testing.T) {
	vars := writeVarsDir(t, "")
	sr := newScripted(nil, nil)
	sr.FailOn("sshd -t", nil)
	r, err := New(Config{NodeName: "node-b", HostRoot: t.TempDir(),
		VarsDir: vars, Runner: sr}, nil)
	if err != nil {
		t.Fatal(err)
	}
	c := loadCyc(t, r, vars, "node-b")
	c.groupSecurity()
	if c.errs == 0 {
		t.Fatal("failed sshd -t did not count a cycle error")
	}
	if len(sr.CallsMatching("systemctl restart ssh.service")) > 0 {
		t.Fatal("sshd restarted despite the failed validation")
	}
	if !hostExists(r, "/etc/ssh/sshd_config.d/00-passiontech-hardening.conf") {
		t.Fatal("hardening drop-in not converged despite the validation failure")
	}
}

// TestSecuritySshdVerifyArms — the informational `sshd -T` probe: a
// failed probe warns without counting; an effective config still
// enabling passwords counts.
func TestSecuritySshdVerifyArms(t *testing.T) {
	t.Run("probe_failed_warn_only", func(t *testing.T) {
		vars := writeVarsDir(t, "")
		sr := newScripted(nil, nil)
		sr.FailOn("sshd -T", nil)
		r, err := New(Config{NodeName: "node-b", HostRoot: t.TempDir(),
			VarsDir: vars, Runner: sr}, nil)
		if err != nil {
			t.Fatal(err)
		}
		c := loadCyc(t, r, vars, "node-b")
		c.groupSecurity()
		if c.errs != 0 {
			t.Fatalf("errs = %d — the verify probe is best-effort", c.errs)
		}
	})
	t.Run("still_enabled_counts", func(t *testing.T) {
		vars := writeVarsDir(t, "")
		sr := newScripted(map[string]string{
			"sshd -T": "passwordauthentication yes",
		}, nil)
		r, err := New(Config{NodeName: "node-b", HostRoot: t.TempDir(),
			VarsDir: vars, Runner: sr}, nil)
		if err != nil {
			t.Fatal(err)
		}
		c := loadCyc(t, r, vars, "node-b")
		c.groupSecurity()
		if c.errs == 0 {
			t.Fatal("passwordauthentication still enabled did not count")
		}
	})
}

// TestSecurityHardeningDisabledRemoves — ssh_hardening_enabled
// DEFINED as false removes both drop-in spellings and restarts sshd
// through the -t gate; a failed gate counts and skips the restart.
func TestSecurityHardeningDisabledRemoves(t *testing.T) {
	vars := writeVarsDir(t, `fail2ban_enabled: false
ssh_hardening_enabled: false
`)
	sr := newScripted(nil, nil)
	r, err := New(Config{NodeName: "node-b", HostRoot: t.TempDir(),
		VarsDir: vars, Runner: sr}, nil)
	if err != nil {
		t.Fatal(err)
	}
	hostWrite(t, r, "/etc/ssh/sshd_config.d/00-passiontech-hardening.conf", "PasswordAuthentication no\n")
	hostWrite(t, r, "/etc/ssh/sshd_config.d/60-passiontech-hardening.conf", "PasswordAuthentication no\n")
	c := loadCyc(t, r, vars, "node-b")
	c.groupSecurity()
	if hostExists(r, "/etc/ssh/sshd_config.d/00-passiontech-hardening.conf") ||
		hostExists(r, "/etc/ssh/sshd_config.d/60-passiontech-hardening.conf") {
		t.Fatal("hardening drop-ins not removed on the disabled-defined path")
	}
	if len(sr.CallsMatching("systemctl restart ssh.service")) == 0 {
		t.Fatal("sshd not restarted after the removal")
	}
	if !strings.Contains(strings.Join(sr.Calls(), "\n"), "sshd -t") {
		t.Fatal("removal restart not gated on sshd -t")
	}
	if c.errs != 0 {
		t.Fatalf("clean removal counted errors: %d", c.errs)
	}

	// Gate failure on the removal path counts and skips the restart.
	sr.ClearLog()
	sr.FailOn("sshd -t", nil)
	hostWrite(t, r, "/etc/ssh/sshd_config.d/00-passiontech-hardening.conf", "stale\n")
	c.errs = 0
	c.groupSecurity()
	if c.errs != 1 {
		t.Fatalf("errs = %d, want the removal-path gate failure counted", c.errs)
	}
	if len(sr.CallsMatching("systemctl restart ssh.service")) > 0 {
		t.Fatal("sshd restarted after removal despite the failed gate")
	}
}

// TestFail2BanIgnoreIPSkipsScalarNode — a scalar (non-mapping)
// registry entry contributes nothing to the mesh whitelist.
func TestFail2BanIgnoreIPSkipsScalarNode(t *testing.T) {
	vars := writeVarsDir(t, "")
	patchVarsFile(t, vars, "interdc_nodes.yaml", `node-a:
  name: a
  ip: 10.0.1.10
node-b: gateway-vm
`)
	sr := newScripted(nil, nil)
	r, err := New(Config{NodeName: "node-b", HostRoot: t.TempDir(),
		VarsDir: vars, Runner: sr}, nil)
	if err != nil {
		t.Fatal(err)
	}
	c := loadCyc(t, r, vars, "node-b")
	got := c.fail2banIgnoreIP()
	if got != "127.0.0.1/8 ::1 10.0.1.10" {
		t.Fatalf("ignoreip = %q, want localhost + the single mapped node", got)
	}
}
