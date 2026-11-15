package kdeps

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-host-agent/internal/testutil"
	"github.com/passiontech-global/kubernetes-cluster-automation/libs/hostkit/timex"
)

func TestExecCombinedAndContainersRunning(t *testing.T) {
	d, _, _ := fixture(t, []testutil.ExecRule{
		{Substr: "podman inspect -f {{.State.Running}} c1 c2", Out: "true\nfalse\n"},
		{Substr: "podman inspect -f {{.State.Running}} bad", Err: errors.New("no such container")},
	})
	d.Cfg.RunCombined = func(_ context.Context, _ []string, argv []string, _ string) (string, error) {
		return "combined:" + strings.Join(argv, " "), nil
	}

	out, err := d.ExecCombined(context.Background(), []string{"podman", "logs", "pg"})
	if err != nil || out != "combined:podman logs pg" {
		t.Fatalf("ExecCombined = (%q, %v)", out, err)
	}

	if got := d.ContainersRunning(context.Background()); len(got) != 0 {
		t.Fatalf("empty ContainersRunning = %v", got)
	}
	got := d.ContainersRunning(context.Background(), "c1", "c2")
	if len(got) != 2 || !got[0] || got[1] {
		t.Fatalf("ContainersRunning(c1,c2) = %v, want [true false]", got)
	}
	gotErr := d.ContainersRunning(context.Background(), "bad")
	if len(gotErr) != 1 || gotErr[0] {
		t.Fatalf("ContainersRunning(bad) = %v, want [false]", gotErr)
	}
}

func TestLongBudgetExceededAndHoldPGOptions(t *testing.T) {
	now := time.Unix(1700000000, 0)
	d, _, _ := fixture(t, nil)
	d.Cfg.Clock = timex.NewCell(func() time.Time { return now })
	d.Cfg.LongCmdTimeout = 10 * time.Second

	if d.LongBudgetExceeded(now.Add(-10*time.Second), nil) {
		t.Fatal("expected false when err is nil")
	}
	if d.LongBudgetExceeded(now.Add(-5*time.Second), errors.New("fail")) {
		t.Fatal("expected false before budget exceeded")
	}
	if !d.LongBudgetExceeded(now.Add(-9*time.Second), errors.New("fail")) {
		t.Fatal("expected true near/past LongCmdTimeout")
	}
	d.Cfg.LongCmdTimeout = time.Second
	if d.LongBudgetExceeded(now.Add(-5*time.Second), errors.New("fail")) {
		t.Fatal("expected false when LongCmdTimeout < 2s")
	}

	opts := d.holdPGOptions()
	if !strings.Contains(opts, "statement_timeout=") || !strings.Contains(opts, "lock_timeout=") {
		t.Fatalf("unexpected holdPGOptions: %q", opts)
	}
}

func TestHoldAdvisoryLock(t *testing.T) {
	// Case 1: lock acquired, then released.
	d, _, _ := fixture(t, nil)
	d.Cfg.Run = func(ctx context.Context, _ []string, argv []string, stdin string) (string, error) {
		if strings.Contains(stdin, "pg_try_advisory_lock") {
			<-ctx.Done()
			return "", ctx.Err()
		}
		if strings.Contains(strings.Join(argv, " "), "pg_locks") {
			return "1\n", nil
		}
		return "t\n", nil
	}
	rel, held, err := d.HoldAdvisoryLock(context.Background(), "pg", "u", "p", "app", 50*time.Millisecond)
	if err != nil || !held || rel == nil {
		t.Fatalf("HoldAdvisoryLock acquired = (%v, %v, %v)", rel != nil, held, err)
	}
	rel()

	// Case 2: hold session exits immediately without lock -> false, nil.
	d2, _, _ := fixture(t, nil)
	d2.Cfg.Run = func(_ context.Context, _ []string, argv []string, _ string) (string, error) {
		if strings.Contains(strings.Join(argv, " "), "pg_locks") {
			return "0\n", nil
		}
		return "advisory-lock-busy\n", nil
	}
	rel2, held2, err2 := d2.HoldAdvisoryLock(context.Background(), "pg", "u", "p", "app", 50*time.Millisecond)
	if err2 != nil || held2 || rel2 != nil {
		t.Fatalf("HoldAdvisoryLock busy = (%v, %v, %v)", rel2 != nil, held2, err2)
	}

	// Case 3: canceled context.
	cctx, cancel := context.WithCancel(context.Background())
	cancel()
	_, held3, err3 := d2.HoldAdvisoryLock(cctx, "pg", "u", "p", "app", 50*time.Millisecond)
	if held3 || (err3 != nil && !errors.Is(err3, context.Canceled)) {
		t.Fatalf("HoldAdvisoryLock canceled = (%v, %v)", held3, err3)
	}
}

func TestPsqlHelpers(t *testing.T) {
	d, _, _ := fixture(t, []testutil.ExecRule{
		{Substr: "psql", Out: "42000\n"},
	})

	if !d.GuardRateTrySpend("compact", time.Minute) {
		t.Fatal("expected first GuardRateTrySpend to succeed")
	}
	if d.GuardRateTrySpend("compact", time.Minute) {
		t.Fatal("expected second GuardRateTrySpend within interval to fail")
	}
	d.GuardRateSpend("maint")
	if d.GuardRateTrySpend("maint", time.Minute) {
		t.Fatal("expected GuardRateTrySpend after GuardRateSpend to fail")
	}

	script := WrapAdvisoryLockScript(12345, "got_lock", "VACUUM;\n")
	for _, want := range []string{"pg_try_advisory_lock(12345)", "got_lock", "VACUUM;", "pg_advisory_unlock(12345)", LockBusyMarker} {
		if !strings.Contains(script, want) {
			t.Fatalf("WrapAdvisoryLockScript missing %q in:\n%s", want, script)
		}
	}

	age, err := d.QueryXidAge(context.Background(), "pg", "u", "p", "app")
	if err != nil || age != 42000 {
		t.Fatalf("QueryXidAge = (%d, %v), want (42000, nil)", age, err)
	}

	dBad, _, _ := fixture(t, []testutil.ExecRule{
		{Substr: "psql", Out: "not-an-int\n"},
	})
	if _, err := dBad.QueryXidAge(context.Background(), "pg", "u", "p", "app"); err == nil {
		t.Fatal("expected parse error for non-int XID age")
	}

	dErr, _, _ := fixture(t, []testutil.ExecRule{
		{Substr: "psql", Err: errors.New("psql boom")},
	})
	if _, err := dErr.QueryXidAge(context.Background(), "pg", "u", "p", "app"); err == nil {
		t.Fatal("expected error when PsqlQuery fails")
	}
}
