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
	e.sd.On("LoadState --value fail2ban.service", "loaded\n")
	e.sd.On("is-active fail2ban.service", "inactive\n")
	e.host.On("fail2ban-client status", "Status\n|- Number of jail:\t2\n`- Jail list:\tsshd, recidive\n")
	e.host.On("fail2ban-client status sshd", "Currently banned:\t7\n")
	e.host.On("fail2ban-client status recidive", "Currently banned:\t1\n")
	e.n.Cycle(context.Background())
	if !stateExists(e, "fail2ban-down") {
		t.Fatal("fail2ban-down latch missing")
	}
	// A stopped jail protects nothing — the guard restarts the unit.
	if !e.sd.Ran("restart fail2ban.service") {
		t.Fatalf("fail2ban not restarted, cmds=%v", e.sd.Cmds())
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
	if e.sd.Ran("restart") || stateExists(e, "fail2ban-down") {
		t.Fatal("fail2ban ran without unit")
	}
}
