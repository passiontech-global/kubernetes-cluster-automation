package kdeps

import (
	"context"
	"errors"
	"strings"
	"sync"
	"sync/atomic"
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
	if held3 || !errors.Is(err3, context.Canceled) {
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

func TestHoldAdvisoryLockClassObjSplitAndCleanup(t *testing.T) {
	t.Run("64bit_lock_id_classid_objid", func(t *testing.T) {
		for _, tc := range []struct {
			name    string
			id      int64
			wantSQL string
		}{
			{
				name:    "high_word_set",
				id:      (1 << 32) | 42,
				wantSQL: "AND l.classid = 1 AND l.objid = 42 AND l.objsubid = 1",
			},
			{
				name:    "bit31_set_unsigned_oid",
				id:      int64(-2147483647<<32 | 0x80000002),
				wantSQL: "AND l.classid = 2147483649 AND l.objid = 2147483650 AND l.objsubid = 1",
			},
		} {
			t.Run(tc.name, func(t *testing.T) {
				d, _, _ := fixture(t, nil)
				d.Cfg.AdvisoryLockID = tc.id
				var sawSQL string
				d.Cfg.Run = func(ctx context.Context, _ []string, argv []string, stdin string) (string, error) {
					if strings.Contains(stdin, "pg_try_advisory_lock") {
						<-ctx.Done()
						return "", ctx.Err()
					}
					joined := strings.Join(argv, " ")
					if strings.Contains(joined, "pg_locks") {
						sawSQL = joined
						return "1\n", nil
					}
					return "t\n", nil
				}
				rel, held, err := d.HoldAdvisoryLock(context.Background(), "pg", "u", "p", "app", 50*time.Millisecond)
				if err != nil || !held || rel == nil {
					t.Fatalf("HoldAdvisoryLock=(%v,%v,%v)", rel != nil, held, err)
				}
				rel()
				if !strings.Contains(sawSQL, tc.wantSQL) {
					t.Fatalf("pg_locks query=%q missing %q", sawSQL, tc.wantSQL)
				}
			})
		}
	})

	t.Run("terminates_backend_on_ctx_cancel", func(t *testing.T) {
		d, _, _ := fixture(t, nil)
		var termRan atomic.Bool
		var termCtxActive atomic.Bool
		started := make(chan struct{})
		d.Cfg.Run = func(ctx context.Context, _ []string, argv []string, stdin string) (string, error) {
			if strings.Contains(stdin, "pg_try_advisory_lock") {
				close(started)
				<-ctx.Done()
				return "", ctx.Err()
			}
			joined := strings.Join(argv, " ")
			if strings.Contains(joined, "pg_locks") {
				return "0\n", nil
			}
			if strings.Contains(joined, "pg_terminate_backend") {
				termRan.Store(true)
				termCtxActive.Store(ctx.Err() == nil)
				return "t\n", nil
			}
			return "", nil
		}
		ctx, cancel := context.WithCancel(context.Background())
		go func() {
			<-started
			cancel()
		}()
		rel, held, err := d.HoldAdvisoryLock(ctx, "pg", "u", "p", AppNameMaint, 5*time.Second)
		if rel != nil || held || !errors.Is(err, context.Canceled) {
			t.Fatalf("got (%v, %v, %v), want (nil, false, Canceled)", rel != nil, held, err)
		}
		if !termRan.Load() || !termCtxActive.Load() {
			t.Fatalf("terminate on cancel: ran=%v ctxActive=%v", termRan.Load(), termCtxActive.Load())
		}
	})

	t.Run("terminates_backend_on_poll_exhaustion", func(t *testing.T) {
		d, _, _ := fixture(t, nil)
		var termRan atomic.Bool
		d.Cfg.Run = func(ctx context.Context, _ []string, argv []string, stdin string) (string, error) {
			if strings.Contains(stdin, "pg_try_advisory_lock") {
				<-ctx.Done()
				return "", ctx.Err()
			}
			joined := strings.Join(argv, " ")
			if strings.Contains(joined, "pg_locks") {
				return "0\n", nil
			}
			if strings.Contains(joined, "pg_terminate_backend") {
				termRan.Store(true)
				return "t\n", nil
			}
			return "", nil
		}
		rel, held, err := d.HoldAdvisoryLock(context.Background(), "pg", "u", "p", AppNameMaint, 10*time.Millisecond)
		if rel != nil || held || err != nil {
			t.Fatalf("got (%v, %v, %v), want (nil, false, nil)", rel != nil, held, err)
		}
		if !termRan.Load() {
			t.Fatal("expected pg_terminate_backend on poll exhaustion")
		}
	})

	t.Run("busy_skips_pg_terminate_backend", func(t *testing.T) {
		d, _, _ := fixture(t, nil)
		var termRan atomic.Bool
		d.Cfg.Run = func(_ context.Context, _ []string, argv []string, stdin string) (string, error) {
			joined := strings.Join(argv, " ")
			if strings.Contains(joined, "pg_locks") {
				return "0\n", nil
			}
			if strings.Contains(joined, "pg_terminate_backend") {
				termRan.Store(true)
				return "t\n", nil
			}
			if strings.Contains(stdin, "pg_try_advisory_lock") {
				return "advisory-lock-busy\n", nil
			}
			return "", nil
		}
		rel, held, err := d.HoldAdvisoryLock(context.Background(), "pg", "u", "p", AppNameMaint, 50*time.Millisecond)
		if rel != nil || held || err != nil {
			t.Fatalf("got (%v, %v, %v), want (nil, false, nil)", rel != nil, held, err)
		}
		if termRan.Load() {
			t.Fatal("busy exit unexpectedly ran pg_terminate_backend")
		}
	})

	t.Run("done_closed_before_poll_on_ctx_cancel", func(t *testing.T) {
		d, _, _ := fixture(t, nil)
		var termRan atomic.Bool
		var termCtxActive atomic.Bool
		started := make(chan struct{})
		d.Cfg.Run = func(ctx context.Context, _ []string, argv []string, stdin string) (string, error) {
			if strings.Contains(stdin, "pg_try_advisory_lock") {
				close(started)
				<-ctx.Done()
				return "", ctx.Err()
			}
			joined := strings.Join(argv, " ")
			if strings.Contains(joined, "pg_locks") {
				return "0\n", nil
			}
			if strings.Contains(joined, "pg_terminate_backend") {
				termRan.Store(true)
				termCtxActive.Store(ctx.Err() == nil)
				return "t\n", nil
			}
			return "", nil
		}
		ctx, cancel := context.WithCancel(context.Background())
		rel, held, err := d.holdAdvisoryLock(ctx, "pg", "u", "p", AppNameMaint, 5*time.Second,
			func(done <-chan struct{}) {
				<-started
				cancel()
				<-done
			})
		if rel != nil || held || !errors.Is(err, context.Canceled) {
			t.Fatalf("got (%v, %v, %v), want (nil, false, Canceled)", rel != nil, held, err)
		}
		if !termRan.Load() || !termCtxActive.Load() {
			t.Fatalf("terminate on cancel: ran=%v ctxActive=%v", termRan.Load(), termCtxActive.Load())
		}
	})

	t.Run("returns_non_busy_hold_error", func(t *testing.T) {
		d, _, _ := fixture(t, nil)
		wantErr := errors.New("container down")
		polled := make(chan struct{})
		var polledOnce sync.Once
		var termRan atomic.Bool
		d.Cfg.Run = func(_ context.Context, _ []string, argv []string, stdin string) (string, error) {
			if strings.Contains(stdin, "pg_try_advisory_lock") {
				<-polled
				return "", wantErr
			}
			joined := strings.Join(argv, " ")
			if strings.Contains(joined, "pg_locks") {
				polledOnce.Do(func() { close(polled) })
				return "0\n", nil
			}
			if strings.Contains(joined, "pg_terminate_backend") {
				termRan.Store(true)
				return "t\n", nil
			}
			return "", nil
		}
		rel, held, err := d.HoldAdvisoryLock(context.Background(), "pg", "u", "p", AppNameMaint, 50*time.Millisecond)
		if rel != nil || held || !errors.Is(err, wantErr) {
			t.Fatalf("got (%v, %v, %v), want (nil, false, %v)", rel != nil, held, err, wantErr)
		}
		if !termRan.Load() {
			t.Fatal("expected pg_terminate_backend on non-busy hold error")
		}
	})

	t.Run("busy_after_first_poll_skips_terminate", func(t *testing.T) {
		d, _, _ := fixture(t, nil)
		polled := make(chan struct{})
		var polledOnce sync.Once
		var termRan atomic.Bool
		d.Cfg.Run = func(_ context.Context, _ []string, argv []string, stdin string) (string, error) {
			if strings.Contains(stdin, "pg_try_advisory_lock") {
				<-polled
				return "advisory-lock-busy\n", nil
			}
			joined := strings.Join(argv, " ")
			if strings.Contains(joined, "pg_locks") {
				polledOnce.Do(func() { close(polled) })
				return "0\n", nil
			}
			if strings.Contains(joined, "pg_terminate_backend") {
				termRan.Store(true)
				return "t\n", nil
			}
			return "", nil
		}
		start := time.Now()
		rel, held, err := d.HoldAdvisoryLock(context.Background(), "pg", "u", "p", AppNameMaint, 50*time.Millisecond)
		elapsed := time.Since(start)
		if rel != nil || held || err != nil {
			t.Fatalf("got (%v, %v, %v), want (nil, false, nil)", rel != nil, held, err)
		}
		if termRan.Load() {
			t.Fatal("busy exit unexpectedly ran pg_terminate_backend")
		}
		if elapsed >= 250*time.Millisecond {
			t.Fatalf("busy exit took %v, expected <250ms (no 500ms sleep fall-through)", elapsed)
		}
	})
}
