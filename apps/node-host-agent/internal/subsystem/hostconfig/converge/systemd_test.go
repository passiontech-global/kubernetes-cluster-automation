// systemd_test.go — the systemctl verb contract: argv each verb
// produces through the injected Runner, is-active/show parsing, and
// EnsureService's enable-then-start ordering with joined failures.
package converge

import (
	"context"
	"errors"
	"slices"
	"strings"
	"testing"
	"time"
)

func TestSystemdVerbsArgv(t *testing.T) {
	for _, tc := range []struct {
		name string
		call func(Systemd) error
		want []string
	}{
		{"daemon-reload", func(s Systemd) error { return s.DaemonReload(context.Background()) },
			[]string{"systemctl", "daemon-reload"}},
		{"enable", func(s Systemd) error { return s.EnableService(context.Background(), "u.service") },
			[]string{"systemctl", "enable", "u.service"}},
		{"start", func(s Systemd) error { return s.StartService(context.Background(), "u.service") },
			[]string{"systemctl", "start", "u.service"}},
		{"stop", func(s Systemd) error { return s.StopService(context.Background(), "u.service") },
			[]string{"systemctl", "stop", "u.service"}},
		{"restart", func(s Systemd) error { return s.RestartService(context.Background(), "u.service") },
			[]string{"systemctl", "restart", "u.service"}},
		{"reload", func(s Systemd) error { return s.ReloadService(context.Background(), "u.service") },
			[]string{"systemctl", "reload", "u.service"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			r := &stubRunner{}
			if err := tc.call(Systemd{Runner: r, Budget: time.Second}); err != nil {
				t.Fatal(err)
			}
			if !slices.Equal(r.cmds[0], tc.want) {
				t.Fatalf("argv = %v, want %v", r.cmds[0], tc.want)
			}
			if !r.hasDeadline {
				t.Error("the Systemd budget must attach a ctx deadline")
			}
		})
	}
}

func TestSystemdVerbsPropagateError(t *testing.T) {
	r := &stubRunner{err: errors.New("systemctl: connection refused")}
	if err := (Systemd{Runner: r}).DaemonReload(context.Background()); err == nil {
		t.Fatal("runner error must propagate")
	}
}

func TestIsActive(t *testing.T) {
	for _, tc := range []struct {
		name string
		out  string
		err  error
		want bool
	}{
		{"active output", "active\n", nil, true},
		{"active unpadded", "active", nil, true},
		{"inactive output", "inactive\n", nil, false},
		{"failed state", "failed\n", nil, false},
		{"exec error counts inactive", "", errors.New("boom"), false},
		{"state word beats exit code", "inactive\n", errors.New("boom"), false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			r := &stubRunner{out: tc.out, err: tc.err}
			if got := (Systemd{Runner: r}).IsActive(context.Background(), "u.service"); got != tc.want {
				t.Fatalf("IsActive = %v, want %v", got, tc.want)
			}
			want := []string{"systemctl", "is-active", "u.service"}
			if !slices.Equal(r.cmds[0], want) {
				t.Fatalf("argv = %v, want %v", r.cmds[0], want)
			}
		})
	}
}

// TestActive pins the error-aware contract IsActive folds away: a
// recognized ActiveState word answers the question even when
// systemctl exits non-zero (every non-active state exits non-zero),
// while an error with empty/unexpected output is the probe failing,
// not the unit being down.
func TestActive(t *testing.T) {
	for _, tc := range []struct {
		name    string
		out     string
		err     error
		want    bool
		wantErr bool
	}{
		{"active output", "active\n", nil, true, false},
		{"inactive state word", "inactive\n", nil, false, false},
		{"failed state word", "failed\n", nil, false, false},
		{"activating state word", "activating\n", errors.New("boom"), false, false},
		{"unknown state word", "unknown\n", errors.New("boom"), false, false},
		{"probe error empty output", "", errors.New("dbus down"), false, true},
		{"probe error garbage output", "zzz\n", errors.New("dbus down"), false, true},
		{"garbage output no error", "zzz\n", nil, false, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			r := &stubRunner{out: tc.out, err: tc.err}
			got, err := (Systemd{Runner: r}).Active(context.Background(), "u.service")
			if got != tc.want {
				t.Fatalf("Active = %v, want %v", got, tc.want)
			}
			if (err != nil) != tc.wantErr {
				t.Fatalf("Active err = %v, wantErr %v", err, tc.wantErr)
			}
		})
	}
}

func TestServiceState(t *testing.T) {
	r := &stubRunner{out: "  active\n"}
	got := (Systemd{Runner: r}).ServiceState(context.Background(), "u.service")
	if got != "active" {
		t.Fatalf("ServiceState = %q, want trimmed %q", got, "active")
	}
	want := []string{"systemctl", "show", "u.service", "-p", "ActiveState", "--value"}
	if !slices.Equal(r.cmds[0], want) {
		t.Fatalf("argv = %v, want %v", r.cmds[0], want)
	}

	// A unit that cannot be queried reads as unknown ("").
	r = &stubRunner{err: errors.New("no such unit")}
	if got := (Systemd{Runner: r}).ServiceState(context.Background(), "u.service"); got != "" {
		t.Fatalf("ServiceState on error = %q, want \"\"", got)
	}
}

func TestEnsureService(t *testing.T) {
	ctx := context.Background()

	t.Run("enable+start order", func(t *testing.T) {
		r := &stubRunner{}
		if err := (Systemd{Runner: r}).EnsureService(ctx, "u.service", true, true); err != nil {
			t.Fatal(err)
		}
		want := [][]string{
			{"systemctl", "enable", "u.service"},
			{"systemctl", "start", "u.service"},
		}
		if len(r.cmds) != 2 || !slices.Equal(r.cmds[0], want[0]) || !slices.Equal(r.cmds[1], want[1]) {
			t.Fatalf("cmds = %v, want %v", r.cmds, want)
		}
	})

	t.Run("no-enable + stop", func(t *testing.T) {
		r := &stubRunner{}
		if err := (Systemd{Runner: r}).EnsureService(ctx, "u.service", false, false); err != nil {
			t.Fatal(err)
		}
		want := []string{"systemctl", "stop", "u.service"}
		if len(r.cmds) != 1 || !slices.Equal(r.cmds[0], want) {
			t.Fatalf("cmds = %v, want [%v]", r.cmds, want)
		}
	})

	t.Run("failures join and both verbs still run", func(t *testing.T) {
		r := &stubRunner{err: errors.New("verb failed")}
		err := (Systemd{Runner: r}).EnsureService(ctx, "u.service", true, true)
		if err == nil {
			t.Fatal("failing verbs must surface an error")
		}
		// errors.Join renders each wrapped failure on its own line.
		if n := strings.Count(err.Error(), "verb failed"); n != 2 {
			t.Fatalf("joined error carries %d failures, want 2: %v", n, err)
		}
		if len(r.cmds) != 2 {
			t.Fatalf("both verbs must run despite failures, cmds = %v", r.cmds)
		}
	})
}
