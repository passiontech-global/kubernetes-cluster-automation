package main

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"flag"
	"io"
	"log/slog"
	"net"
	"net/http"
	"os"
	"strings"
	"testing"
	"time"
)

func TestParseLocalUsers(t *testing.T) {
	cases := []struct {
		name           string
		in             string
		user, password string
		ok             bool
	}{
		{"basic", "admin:pw", "admin", "pw", true},
		// Only the first colon splits — bcrypt hashes and passwords
		// with colons survive intact.
		{"colon in password", "admin:pw:with:colons", "admin", "pw:with:colons", true},
		{"empty password", "admin:", "", "", false},
		{"empty user", ":pw", "", "", false},
		{"no colon", "admin", "", "", false},
		{"empty", "", "", "", false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			user, password, ok := parseLocalUsers(tc.in)
			if ok != tc.ok {
				t.Fatalf("parseLocalUsers(%q) ok=%v want %v", tc.in, ok, tc.ok)
			}
			if ok && (user != tc.user || password != tc.password) {
				t.Fatalf("parseLocalUsers(%q)=(%q,%q) want (%q,%q)",
					tc.in, user, password, tc.user, tc.password)
			}
		})
	}
}

func TestParseLocalUsersEnv(t *testing.T) {
	cases := []struct {
		name           string
		in             string
		user, password string
		ok             bool
	}{
		{"single", "admin:pw", "admin", "pw", true},
		{"surrounding space", "  admin:pw  ", "admin", "pw", true},
		{"two users first wins", "admin:pw,ops:secret", "admin", "pw", true},
		// A comma is a separator ONLY when the segment after it has
		// the user:pass shape — a comma inside a password survives.
		{"comma in password", "admin:pa,ss", "admin", "pa,ss", true},
		{"comma then user", "admin:pa,ss,ops:pw", "admin", "pa,ss", true},
		// A trailing comma or empty/whitespace segment between entries
		// is a separator and gets dropped rather than corrupting the
		// password.
		{"trailing comma dropped", "admin:pw,", "admin", "pw", true},
		{"trailing comma with space dropped", "admin:pw, , ", "admin", "pw", true},
		{"empty segment between users", "u:p, ,v:q", "u", "p", true},
		{"leading comma dropped", ",admin:pw", "admin", "pw", true},
		{"space-only entries dropped", " , admin:pw", "admin", "pw", true},
		{"first invalid second valid", "broken,ops:pw", "ops", "pw", true},
		{"all invalid", "a,b,c", "", "", false},
		{"empty", "", "", "", false},
		{"whitespace only", "   ", "", "", false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			user, password, ok := parseLocalUsersEnv(tc.in)
			if ok != tc.ok {
				t.Fatalf("parseLocalUsersEnv(%q) ok=%v want %v", tc.in, ok, tc.ok)
			}
			if ok && (user != tc.user || password != tc.password) {
				t.Fatalf("parseLocalUsersEnv(%q)=(%q,%q) want (%q,%q)",
					tc.in, user, password, tc.user, tc.password)
			}
		})
	}
}

func TestMainVersionFlag(t *testing.T) {
	origArgs := os.Args
	origCmd := flag.CommandLine
	t.Cleanup(func() {
		os.Args = origArgs
		flag.CommandLine = origCmd
	})
	os.Args = []string{"webhook-dispatcher", "-version"}
	flag.CommandLine = flag.NewFlagSet("webhook-dispatcher", flag.ContinueOnError)
	main()
}

func saveSlogDefault(t *testing.T) {
	t.Helper()
	orig := slog.Default()
	t.Cleanup(func() { slog.SetDefault(orig) })
}

func setValidRunEnv(t *testing.T) {
	t.Helper()
	t.Setenv("GITHUB_WEBHOOK_SECRET", "test-secret")
	t.Setenv("CI_WEBHOOK_TOKEN", "test-token")
	t.Setenv("LOCAL_USERS", "admin:pw")
	t.Setenv("LISTEN_ADDR", "127.0.0.1:0")
	t.Setenv("METRICS_ADDR", "127.0.0.1:0")
}

func TestRunFlags(t *testing.T) {
	saveSlogDefault(t)
	cases := []struct {
		name      string
		args      []string
		wantErr   bool
		wantIsErr error
	}{
		{name: "single_dash_version", args: []string{"-version"}},
		{name: "double_dash_version", args: []string{"--version"}},
		{name: "help_returns_err_help", args: []string{"-help"}, wantErr: true, wantIsErr: flag.ErrHelp},
		{name: "unknown_flag_errors", args: []string{"-bogus"}, wantErr: true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			err := run(t.Context(), tc.args)
			if !tc.wantErr {
				if err != nil {
					t.Fatalf("run(%v) unexpected err: %v", tc.args, err)
				}
				return
			}
			if err == nil {
				t.Fatalf("run(%v) succeeded, want error", tc.args)
			}
			if tc.wantIsErr != nil && !errors.Is(err, tc.wantIsErr) {
				t.Fatalf("run(%v) err = %v, want %v", tc.args, err, tc.wantIsErr)
			}
		})
	}
}

func TestRunEnvValidation(t *testing.T) {
	saveSlogDefault(t)
	cases := []struct {
		name     string
		env      map[string]string
		wantText string
	}{
		{
			name: "missing_all_required",
			env: map[string]string{
				"GITHUB_WEBHOOK_SECRET": "",
				"CI_WEBHOOK_TOKEN":      "",
				"LOCAL_USERS":           "",
			},
			wantText: "GITHUB_WEBHOOK_SECRET",
		},
		{
			name: "missing_github_secret",
			env: map[string]string{
				"GITHUB_WEBHOOK_SECRET": "",
				"CI_WEBHOOK_TOKEN":      "tok",
				"LOCAL_USERS":           "u:p",
			},
			wantText: "GITHUB_WEBHOOK_SECRET",
		},
		{
			name: "missing_ci_token",
			env: map[string]string{
				"GITHUB_WEBHOOK_SECRET": "sec",
				"CI_WEBHOOK_TOKEN":      "",
				"LOCAL_USERS":           "u:p",
			},
			wantText: "CI_WEBHOOK_TOKEN",
		},
		{
			name: "missing_local_users",
			env: map[string]string{
				"GITHUB_WEBHOOK_SECRET": "sec",
				"CI_WEBHOOK_TOKEN":      "tok",
				"LOCAL_USERS":           "",
			},
			wantText: "LOCAL_USERS",
		},
		{
			name: "malformed_local_users_no_colon",
			env: map[string]string{
				"GITHUB_WEBHOOK_SECRET": "sec",
				"CI_WEBHOOK_TOKEN":      "tok",
				"LOCAL_USERS":           "nocolon",
			},
			wantText: "LOCAL_USERS",
		},
		{
			name: "malformed_local_users_empty_pass",
			env: map[string]string{
				"GITHUB_WEBHOOK_SECRET": "sec",
				"CI_WEBHOOK_TOKEN":      "tok",
				"LOCAL_USERS":           "admin:",
			},
			wantText: "LOCAL_USERS",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			setValidRunEnv(t)
			for k, v := range tc.env {
				t.Setenv(k, v)
			}
			err := run(t.Context(), nil)
			if err == nil {
				t.Fatal("expected env validation error, got nil")
			}
			if !strings.Contains(err.Error(), tc.wantText) {
				t.Fatalf("err = %q, want substring %q", err.Error(), tc.wantText)
			}
		})
	}
}

func TestRunBindErrors(t *testing.T) {
	saveSlogDefault(t)

	occupyPort := func(t *testing.T) string {
		t.Helper()
		ln, err := net.Listen("tcp", "127.0.0.1:0")
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = ln.Close() })
		return ln.Addr().String()
	}

	t.Run("invalid_listen_addr", func(t *testing.T) {
		setValidRunEnv(t)
		t.Setenv("LISTEN_ADDR", "127.0.0.1:999999")
		if err := run(t.Context(), nil); err == nil {
			t.Fatal("expected public bind error")
		}
	})

	t.Run("port_in_use_listen_addr", func(t *testing.T) {
		setValidRunEnv(t)
		t.Setenv("LISTEN_ADDR", occupyPort(t))
		if err := run(t.Context(), nil); err == nil {
			t.Fatal("expected public port-in-use error")
		}
	})

	t.Run("invalid_metrics_addr_closes_public_socket", func(t *testing.T) {
		setValidRunEnv(t)
		// Reserve a free port, close it, let run() bind publicSrv to it,
		// and verify run() releases it when internalSrv fails to bind.
		probe, err := net.Listen("tcp", "127.0.0.1:0")
		if err != nil {
			t.Fatal(err)
		}
		pubAddr := probe.Addr().String()
		_ = probe.Close()

		t.Setenv("LISTEN_ADDR", pubAddr)
		t.Setenv("METRICS_ADDR", "127.0.0.1:999999")
		if err := run(t.Context(), nil); err == nil {
			t.Fatal("expected metrics bind error")
		}
		rebind, err := net.Listen("tcp", pubAddr)
		if err != nil {
			t.Fatalf("public socket leaked after metrics bind failure: %v", err)
		}
		_ = rebind.Close()
	})

	t.Run("port_in_use_metrics_addr", func(t *testing.T) {
		setValidRunEnv(t)
		t.Setenv("METRICS_ADDR", occupyPort(t))
		if err := run(t.Context(), nil); err == nil {
			t.Fatal("expected metrics port-in-use error")
		}
	})
}

func TestRunGracefulShutdown(t *testing.T) {
	saveSlogDefault(t)

	t.Run("already_cancelled_context", func(t *testing.T) {
		setValidRunEnv(t)
		ctx, cancel := context.WithCancel(t.Context())
		cancel()
		if err := run(ctx, nil); err != nil {
			t.Fatalf("run(cancelledCtx) = %v, want nil", err)
		}
	})

	t.Run("serves_routes_isolated_and_shuts_down_on_cancel", func(t *testing.T) {
		setValidRunEnv(t)

		origStdout := os.Stdout
		pr, pw, err := os.Pipe()
		if err != nil {
			t.Fatal(err)
		}
		os.Stdout = pw
		t.Cleanup(func() {
			os.Stdout = origStdout
			_ = pr.Close()
			_ = pw.Close()
		})

		type addrs struct {
			pub string
			met string
		}
		addrCh := make(chan addrs, 1)
		scanDone := make(chan struct{})
		go func() {
			defer close(scanDone)
			sc := bufio.NewScanner(pr)
			sent := false
			for sc.Scan() {
				if sent {
					continue
				}
				var rec struct {
					Msg         string `json:"msg"`
					Addr        string `json:"addr"`
					MetricsAddr string `json:"metrics_addr"`
				}
				if json.Unmarshal(sc.Bytes(), &rec) == nil && rec.Msg == "starting webhook-dispatcher" {
					addrCh <- addrs{pub: rec.Addr, met: rec.MetricsAddr}
					sent = true
				}
			}
		}()

		ctx, cancel := context.WithCancel(t.Context())
		defer cancel()
		runDone := make(chan error, 1)
		go func() {
			runDone <- run(ctx, nil)
		}()

		var bound addrs
		select {
		case bound = <-addrCh:
		case err := <-runDone:
			t.Fatalf("run exited early before serving: %v", err)
		case <-time.After(5 * time.Second):
			t.Fatal("timed out waiting for starting log line")
		}

		client := &http.Client{Timeout: 2 * time.Second}
		getStatus := func(url string) (int, string) {
			t.Helper()
			resp, err := client.Get(url)
			if err != nil {
				t.Fatalf("GET %s: %v", url, err)
			}
			defer func() { _ = resp.Body.Close() }()
			b, _ := io.ReadAll(resp.Body)
			return resp.StatusCode, string(b)
		}

		if code, body := getStatus("http://" + bound.pub + "/healthz"); code != http.StatusOK || body != "ok" {
			t.Fatalf("public /healthz = (%d, %q), want (200, ok)", code, body)
		}
		if code, body := getStatus("http://" + bound.pub + "/readyz"); code != http.StatusOK || body != "ok" {
			t.Fatalf("public /readyz = (%d, %q), want (200, ok)", code, body)
		}
		if code, _ := getStatus("http://" + bound.pub + "/metrics"); code != http.StatusNotFound {
			t.Fatalf("public /metrics = %d, want 404", code)
		}
		if code, _ := getStatus("http://" + bound.pub + "/debug/pprof/"); code != http.StatusNotFound {
			t.Fatalf("public /debug/pprof/ = %d, want 404", code)
		}
		if code, _ := getStatus("http://" + bound.met + "/metrics"); code != http.StatusOK {
			t.Fatalf("internal /metrics = %d, want 200", code)
		}
		if code, _ := getStatus("http://" + bound.met + "/healthz"); code != http.StatusNotFound {
			t.Fatalf("internal /healthz = %d, want 404", code)
		}

		cancel()
		select {
		case err := <-runDone:
			if err != nil {
				t.Fatalf("run shutdown err = %v, want nil", err)
			}
		case <-time.After(5 * time.Second):
			t.Fatal("run did not shut down within 5s after context cancel")
		}
		_ = pw.Close()
		<-scanDone
	})
}
