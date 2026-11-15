package probe

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-host-agent/internal/subsystem/kinedb/kdeps"
)

func TestIniListValue(t *testing.T) {
	ini := "admin_users_extra = wrong\r\n" +
		"stats_users =  stats_ro , admin_user \r\n" +
		"auth_user = pgb_auth\n"

	cases := []struct {
		key  string
		want string
	}{
		{"stats_users", "stats_ro"},
		{"auth_user", "pgb_auth"},
		{"admin_users", ""},
		{"missing", ""},
	}
	for _, tc := range cases {
		t.Run(tc.key, func(t *testing.T) {
			if got := iniListValue(ini, tc.key); got != tc.want {
				t.Fatalf("iniListValue(%q) = %q, want %q", tc.key, got, tc.want)
			}
		})
	}
}

func TestPgbouncerCreds(t *testing.T) {
	ctx := context.Background()
	newProbe := func(run func(context.Context, []string, []string, string) (string, error)) *Probe {
		return &Probe{d: &kdeps.Deps{
			Cfg: kdeps.Config{
				CmdTimeout: time.Second,
				Runtime:    "ctr",
				Run:        run,
			},
		}}
	}

	t.Run("ini_exec_error", func(t *testing.T) {
		p := newProbe(func(context.Context, []string, []string, string) (string, error) {
			return "", errors.New("exec failed")
		})
		if _, _, ok := p.pgbouncerCreds(ctx, "pgb-0", "stats_users"); ok {
			t.Fatal("expected ok=false on ini exec error")
		}
	})

	t.Run("no_matching_key", func(t *testing.T) {
		p := newProbe(func(context.Context, []string, []string, string) (string, error) {
			return "listen_port = 6432\n", nil
		})
		if _, _, ok := p.pgbouncerCreds(ctx, "pgb-0", "stats_users", "admin_users"); ok {
			t.Fatal("expected ok=false when no key matches")
		}
	})

	t.Run("userlist_error_returns_empty_pass", func(t *testing.T) {
		p := newProbe(func(_ context.Context, _, argv []string, _ string) (string, error) {
			cmd := strings.Join(argv, " ")
			if strings.Contains(cmd, "pgbouncer.ini") {
				return "stats_users = pgb_stats\n", nil
			}
			return "", errors.New("no userlist")
		})
		u, pass, ok := p.pgbouncerCreds(ctx, "pgb-0", "stats_users")
		if !ok || u != "pgb_stats" || pass != "" {
			t.Fatalf("got (%q, %q, %v), want (pgb_stats, '', true)", u, pass, ok)
		}
	})

	t.Run("full_match", func(t *testing.T) {
		p := newProbe(func(_ context.Context, _, argv []string, _ string) (string, error) {
			cmd := strings.Join(argv, " ")
			if strings.Contains(cmd, "pgbouncer.ini") {
				return "stats_users = pgb_stats, other\n", nil
			}
			return "\"pgb_stats\" \"secret123\"\n", nil
		})
		u, pass, ok := p.pgbouncerCreds(ctx, "pgb-0", "stats_users")
		if !ok || u != "pgb_stats" || pass != "secret123" {
			t.Fatalf("got (%q, %q, %v), want (pgb_stats, secret123, true)", u, pass, ok)
		}
	})
}
