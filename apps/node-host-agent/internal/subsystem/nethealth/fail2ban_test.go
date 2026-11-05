// fail2ban_test.go — fail2ban unit-down latch, restart, and banned-count capture.

package nethealth

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-host-agent/internal/platform/hostutil"
)

// --- fail2ban (50) ---

func TestFail2banDownAndBans(t *testing.T) {
	e := fixture(t, nil)
	e.sdReply["LoadState --value fail2ban.service"] = "loaded\n"
	e.sdReply["is-active fail2ban.service"] = "inactive\n"
	e.cmdReply["fail2ban-client status"] =
		"Status\n|- Number of jail:\t2\n`- Jail list:\tsshd, recidive\n"
	e.cmdReply["fail2ban-client status sshd"] = "Currently banned:\t7\n"
	e.cmdReply["fail2ban-client status recidive"] = "Currently banned:\t1\n"
	e.n.Cycle(context.Background())
	if !stateExists(e, "fail2ban-down") {
		t.Fatal("fail2ban-down latch missing")
	}
	// A stopped jail protects nothing — the guard restarts the unit.
	if !e.sdRan("restart fail2ban.service") {
		t.Fatalf("fail2ban not restarted, cmds=%v", e.sdcmds)
	}
	if _, err := os.Stat(filepath.Join(e.state, "last-fail2ban-restart")); err != nil {
		t.Fatal("restart budget file missing")
	}
	got := hostutil.ReadTrimmed(filepath.Join(e.state, "fail2ban-banned"))
	if !strings.Contains(got, "sshd=7") || !strings.Contains(got, "recidive=1") {
		t.Fatalf("banned file=%q", got)
	}
}

func TestFail2banNoUnitSkips(t *testing.T) {
	e := fixture(t, nil)
	e.n.Cycle(context.Background())
	if e.sdRan("restart") || stateExists(e, "fail2ban-down") {
		t.Fatal("fail2ban ran without unit")
	}
}
