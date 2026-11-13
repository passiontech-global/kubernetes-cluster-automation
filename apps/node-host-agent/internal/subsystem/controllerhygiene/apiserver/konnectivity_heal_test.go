package apiserver_test

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"

	promtest "github.com/prometheus/client_golang/prometheus/testutil"

	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-host-agent/internal/subsystem/controllerhygiene/apiserver"
	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-host-agent/internal/subsystem/controllerhygiene/cdeps"
)

// --- konnectivity-server probe + heal (G4) ---

type nodesTransport struct{ readyWorkers int }

func (nt nodesTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	if strings.HasSuffix(req.URL.Path, "/api/v1/nodes") {
		var items []string
		for i := 0; i < nt.readyWorkers; i++ {
			items = append(items, fmt.Sprintf(
				`{"metadata":{"labels":{"kubernetes.io/hostname":"w%d"}},`+
					`"status":{"conditions":[{"type":"Ready","status":"True"}]}}`, i))
		}
		// One Ready control-plane node always exists — it must NOT
		// count as a worker.
		items = append(items, `{"metadata":{"labels":{"node-role.kubernetes.io/control-plane":""}},`+
			`"status":{"conditions":[{"type":"Ready","status":"True"}]}}`)
		return &http.Response{
			Status:     "200 OK",
			StatusCode: http.StatusOK,
			Header:     make(http.Header),
			Body: io.NopCloser(strings.NewReader(
				`{"items":[` + strings.Join(items, ",") + `]}`)),
			Request: req,
		}, nil
	}
	return nil, errors.New("nodesTransport: unexpected url " + req.URL.String())
}

func TestKonnectivityServerProbeAndHeal(t *testing.T) {
	e := fixture(t)
	runDir := t.TempDir()
	e.H.Cfg.K0sRunDir = runDir
	// The UDS exists — the zero-backends reading is the bad signal.
	if err := os.MkdirAll(filepath.Join(runDir, "konnectivity-server"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(runDir, "konnectivity-server",
		"konnectivity-server.sock"), []byte{}, 0o600); err != nil {
		t.Fatal(err)
	}
	e.H.Cfg.KCMMetricsFn = func(_ context.Context, url string) (string, error) {
		if url == "http://127.0.0.1:8091/metrics" {
			return "konnectivity_network_proxy_server_ready_backend_connections 0\n", nil
		}
		return "", errors.New("unexpected scrape " + url)
	}
	e.H.Client = &http.Client{Transport: nodesTransport{readyWorkers: 1}}
	// The supervisor child — comm truncates to 15 chars but the
	// argv basename is what the pid sweep matches.
	e.MkProc(t, 4242, "konnectivity-se",
		[]string{"/var/lib/k0s/bin/konnectivity-server", "--uds-name=x"}, 600)

	// Cycles 1+2: streak below the 3-cycle gate — no kill.
	e.H.Cycle(context.Background())
	e.H.Cycle(context.Background())
	if len(e.Kills) != 0 {
		t.Fatalf("kill fired before the 3-cycle streak: %v", e.Kills)
	}
	// Cycle 3: unhealthy >= 3 cycles + Ready worker + enforce → kill.
	e.H.Cycle(context.Background())
	if len(e.Kills) != 1 || e.Kills[0].PID != 4242 {
		t.Fatalf("kills=%v want [{4242 SIGKILL}]", e.Kills)
	}
	if log := e.LogLines(); !strings.Contains(log,
		"ACTION: killed konnectivity-server pid=4242") {
		t.Fatalf("watchdog log missing kill ACTION:\n%s", log)
	}
	if v := promtest.ToFloat64(e.H.KonnReadyBackends); v != 0 {
		t.Fatalf("ready_backends gauge=%v want 0", v)
	}
	// The 30-minute restart budget suppresses a second kill.
	e.H.Cycle(context.Background())
	if len(e.Kills) != 1 {
		t.Fatalf("budget did not suppress repeat kill: %v", e.Kills)
	}
}

func TestKonnectivityNoWorkerSuppressesHeal(t *testing.T) {
	e := fixture(t)
	e.H.Cfg.K0sRunDir = t.TempDir() // UDS missing — bad every cycle
	e.H.Cfg.KCMMetricsFn = func(_ context.Context, url string) (string, error) {
		if url == "http://127.0.0.1:8091/metrics" {
			return "konnectivity_network_proxy_server_ready_backend_connections 0\n", nil
		}
		return "", errors.New("unexpected scrape " + url)
	}
	e.H.Client = &http.Client{Transport: nodesTransport{readyWorkers: 0}}
	e.MkProc(t, 4242, "konnectivity-se",
		[]string{"/var/lib/k0s/bin/konnectivity-server"}, 600)
	for range 4 {
		e.H.Cycle(context.Background())
	}
	if len(e.Kills) != 0 {
		t.Fatalf("heal fired with zero Ready workers: %v", e.Kills)
	}
	if log := e.LogLines(); !strings.Contains(log, "no Ready workers") {
		t.Fatalf("suppression not logged:\n%s", log)
	}
	// Scrape failure exports -1, never a fabricated 0.
	e.H.Cfg.KCMMetricsFn = func(_ context.Context, _ string) (string, error) {
		return "", errors.New("refused")
	}
	e.H.Cycle(context.Background())
	if v := promtest.ToFloat64(e.H.KonnReadyBackends); v != -1 {
		t.Fatalf("scrape-failed gauge=%v want -1", v)
	}
}

// --- konnectivity-server edge branches ---

// A healthy cycle after a bad one must reset the streak and refresh
// the gauge — bad→good→bad never reaches the 3-cycle gate.
func TestKonnectivityHealthyCycleResetsStreak(t *testing.T) {
	e := fixture(t)
	runDir := t.TempDir()
	e.H.Cfg.K0sRunDir = runDir
	sock := filepath.Join(runDir, "konnectivity-server", "konnectivity-server.sock")
	e.H.Cfg.KCMMetricsFn = func(_ context.Context, url string) (string, error) {
		if url == "http://127.0.0.1:8091/metrics" {
			return "konnectivity_network_proxy_server_ready_backend_connections 0\n", nil
		}
		return "", errors.New("unexpected scrape " + url)
	}
	e.H.Client = &http.Client{Transport: nodesTransport{readyWorkers: 1}}
	for range 2 { // bad, bad — below the gate
		e.H.Cycle(context.Background())
	}
	if err := os.MkdirAll(filepath.Dir(sock), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(sock, []byte{}, 0o600); err != nil {
		t.Fatal(err)
	}
	e.H.Cfg.KCMMetricsFn = func(_ context.Context, url string) (string, error) {
		if url == "http://127.0.0.1:8091/metrics" {
			return "konnectivity_network_proxy_server_ready_backend_connections 2\n", nil
		}
		return "", errors.New("unexpected scrape " + url)
	}
	e.H.Cycle(context.Background()) // healthy — streak resets, gauge=2
	if v := promtest.ToFloat64(e.H.KonnReadyBackends); v != 2 {
		t.Fatalf("gauge=%v want 2", v)
	}
	e.H.Cfg.KCMMetricsFn = func(_ context.Context, url string) (string, error) {
		if url == "http://127.0.0.1:8091/metrics" {
			return "konnectivity_network_proxy_server_ready_backend_connections 0\n", nil
		}
		return "", errors.New("unexpected scrape " + url)
	}
	if err := os.Remove(sock); err != nil {
		t.Fatal(err)
	}
	e.H.Cycle(context.Background()) // bad again — only 1 of 3
	e.H.Cycle(context.Background()) // 2 of 3
	if len(e.Kills) != 0 {
		t.Fatalf("kill fired before the streak rebuilt: %v", e.Kills)
	}
}

// Unhealthy past the gate but the supervisor child is gone — the
// heal must log and stand down instead of killing pid 0.
func TestKonnectivityNoProcessToKill(t *testing.T) {
	e := fixture(t)
	e.H.Cfg.K0sRunDir = t.TempDir() // UDS missing — bad every cycle
	e.H.Cfg.KCMMetricsFn = func(_ context.Context, url string) (string, error) {
		if url == "http://127.0.0.1:8091/metrics" {
			return "konnectivity_network_proxy_server_ready_backend_connections 0\n", nil
		}
		return "", errors.New("unexpected scrape " + url)
	}
	e.H.Client = &http.Client{Transport: nodesTransport{readyWorkers: 1}}
	for range 3 {
		e.H.Cycle(context.Background())
	}
	if len(e.Kills) != 0 {
		t.Fatalf("kill without a process: %v", e.Kills)
	}
	if !strings.Contains(e.LogLines(),
		"konnectivity-server process not found") {
		t.Fatalf("missing-process not logged:\n%s", e.LogLines())
	}
}

// A failing kill is a suspect warn — the streak stays spent but no
// success action is recorded.
func TestKonnectivityKillFailureWarns(t *testing.T) {
	e := fixture(t)
	e.H.Cfg.K0sRunDir = t.TempDir()
	e.H.Cfg.KCMMetricsFn = func(_ context.Context, url string) (string, error) {
		if url == "http://127.0.0.1:8091/metrics" {
			return "konnectivity_network_proxy_server_ready_backend_connections 0\n", nil
		}
		return "", errors.New("unexpected scrape " + url)
	}
	e.H.Client = &http.Client{Transport: nodesTransport{readyWorkers: 1}}
	e.MkProc(t, 4242, "konnectivity-se",
		[]string{"/var/lib/k0s/bin/konnectivity-server"}, 600)
	oldKill := e.H.Cfg.KillFn
	e.H.Cfg.KillFn = func(int, syscall.Signal) error {
		return errors.New("no such process")
	}
	defer func() { e.H.Cfg.KillFn = oldKill }()
	for range 3 {
		e.H.Cycle(context.Background())
	}
	if len(e.Kills) != 0 {
		t.Fatalf("failed kill recorded as fired: %v", e.Kills)
	}
	if !strings.Contains(e.LogLines(),
		"konnectivity-server kill pid=4242 failed") {
		t.Fatalf("kill failure not warned:\n%s", e.LogLines())
	}
}

// The pid sweep failing wholesale (procfs unreadable) reads as "no
// process" — heal stands down.
func TestKonnectivityProcRootUnreadable(t *testing.T) {
	if os.Getuid() == 0 {
		t.Skip("root ignores directory mode bits")
	}
	e := fixture(t)
	e.H.Cfg.K0sRunDir = t.TempDir()
	e.H.Cfg.KCMMetricsFn = func(_ context.Context, url string) (string, error) {
		if url == "http://127.0.0.1:8091/metrics" {
			return "konnectivity_network_proxy_server_ready_backend_connections 0\n", nil
		}
		return "", errors.New("unexpected scrape " + url)
	}
	e.H.Client = &http.Client{Transport: nodesTransport{readyWorkers: 1}}
	for range 2 { // build the streak with a readable procfs
		e.H.Cycle(context.Background())
	}
	if err := os.Chmod(e.Proc, 0o000); err != nil {
		t.Fatal(err)
	}
	defer func() { _ = os.Chmod(e.Proc, 0o755) }()
	e.H.Cycle(context.Background())
	if len(e.Kills) != 0 {
		t.Fatalf("kill fired with unreadable procfs: %v", e.Kills)
	}
}

// ParseKonnectivityReadyBackends: a HELP-style continuation line and
// a bare metric name with no value are inconclusive, never 0.
func TestParseKonnectivityReadyBackendsEdges(t *testing.T) {
	if v, ok := apiserver.ParseKonnectivityReadyBackends(
		"konnectivity_network_proxy_server_ready_backend_connections\n" +
			"other_metric 1\n"); ok {
		t.Fatalf("valueless sample parsed: %v", v)
	}
	if v, ok := apiserver.ParseKonnectivityReadyBackends(
		"# konnectivity_network_proxy_server_ready_backend_connections 3\n"); ok {
		t.Fatalf("comment line parsed: %v", v)
	}
}

// The pid sweep skips pids with an empty/missing cmdline — a decoy
// process without argv must not shadow the real konnectivity-server
// child, and the lowest matching pid wins.
func TestKonnectivityPIDSkipsEmptyCmdline(t *testing.T) {
	e := fixture(t)
	e.H.Cfg.K0sRunDir = t.TempDir()
	e.H.Cfg.KCMMetricsFn = func(_ context.Context, url string) (string, error) {
		if url == "http://127.0.0.1:8091/metrics" {
			return "konnectivity_network_proxy_server_ready_backend_connections 0\n", nil
		}
		return "", errors.New("unexpected scrape " + url)
	}
	e.H.Client = &http.Client{Transport: nodesTransport{readyWorkers: 1}}
	e.MkProc(t, 4242, "konnectivity-se",
		[]string{"/var/lib/k0s/bin/konnectivity-server"}, 600)
	// A higher-pid second server must be ignored; the empty-argv decoy
	// must be skipped without stopping the sweep.
	e.MkProc(t, 4343, "konnectivity-se",
		[]string{"/var/lib/k0s/bin/konnectivity-server"}, 600)
	e.MkProc(t, 4300, "decoy", nil, 600)
	for range 3 {
		e.H.Cycle(context.Background())
	}
	if len(e.Kills) != 1 || e.Kills[0].PID != 4242 {
		t.Fatalf("kills=%v want lowest matching pid 4242", e.Kills)
	}
}

// readyWorkers: no client credentials, a master-labeled-only node
// list, and undecodable JSON all read as zero — heal suppressed.
func TestKonnectivityReadyWorkersEdges(t *testing.T) {
	for _, tc := range []struct {
		name string
		mut  func(e *env)
	}{
		{"no_client", func(e *env) {
			e.H.Cfg.HTTPClient = nil
			e.H.Client = nil
		}},
		{"master_only", func(e *env) {
			e.H.Client = &http.Client{Transport: masterTransport{}}
		}},
		{"bad_json", func(e *env) {
			e.H.Client = &http.Client{Transport: rawTransport{body: "{oops"}}
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			e := fixture(t)
			e.H.Cfg.K0sRunDir = t.TempDir()
			e.H.Cfg.KCMMetricsFn = func(_ context.Context, url string) (string, error) {
				if url == "http://127.0.0.1:8091/metrics" {
					return "konnectivity_network_proxy_server_ready_backend_connections 0\n", nil
				}
				return "", errors.New("unexpected scrape " + url)
			}
			e.MkProc(t, 4242, "konnectivity-se",
				[]string{"/var/lib/k0s/bin/konnectivity-server"}, 600)
			tc.mut(e)
			for range 4 {
				e.H.Cycle(context.Background())
			}
			if len(e.Kills) != 0 {
				t.Fatalf("%s: heal fired with zero usable workers: %v",
					tc.name, e.Kills)
			}
		})
	}
}

// masterTransport answers the node list with one Ready node that is
// master-labeled (legacy clusters) — not a worker.
type masterTransport struct{}

func (masterTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	return &http.Response{
		Status: "200 OK", StatusCode: http.StatusOK,
		Header: make(http.Header),
		Body: io.NopCloser(strings.NewReader(
			`{"items":[{"metadata":{"labels":` +
				`{"node-role.kubernetes.io/master":""}},` +
				`"status":{"conditions":[{"type":"Ready","status":"True"}]}}]}`)),
		Request: req,
	}, nil
}

// rawTransport answers every request with a fixed body.
type rawTransport struct{ body string }

func (t rawTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	return &http.Response{
		Status: "200 OK", StatusCode: http.StatusOK,
		Header:  make(http.Header),
		Body:    io.NopCloser(strings.NewReader(t.body)),
		Request: req,
	}, nil
}

// Off and dry-run modes must not burn the 30-minute konn restart
// budget — the spend happens atomically inside the enforce branch.
func TestKonnectivityBudgetNotSpentOffOrDryRun(t *testing.T) {
	for _, tc := range []struct {
		name    string
		mode    string
		wantLog string
	}{
		{"dryrun", cdeps.ModeDryRun, "DRY-RUN: would kill konnectivity-server"},
		{"off", cdeps.ModeOff, ""},
	} {
		t.Run(tc.name, func(t *testing.T) {
			e := fixture(t)
			e.H.Cfg.K0sRunDir = t.TempDir() // UDS missing — bad signal
			e.H.Cfg.Sig13.Mode = tc.mode
			e.H.Cfg.KCMMetricsFn = func(_ context.Context, url string) (string, error) {
				if url == "http://127.0.0.1:8091/metrics" {
					return "konnectivity_network_proxy_server_ready_backend_connections 0\n", nil
				}
				return "", errors.New("unexpected scrape " + url)
			}
			e.H.Client = &http.Client{Transport: nodesTransport{readyWorkers: 1}}
			e.MkProc(t, 4242, "konnectivity-se",
				[]string{"/var/lib/k0s/bin/konnectivity-server"}, 600)
			for range 4 {
				e.H.Cycle(context.Background())
			}
			if len(e.Kills) != 0 {
				t.Fatalf("%s mode killed: %v", tc.name, e.Kills)
			}
			if h := e.H.State.Epoch(filepath.Join(e.State,
				cdeps.FileRateKonnRestart)); h != 0 {
				t.Fatalf("%s mode burned the restart budget (epoch=%d)", tc.name, h)
			}
			log := e.LogLines()
			if tc.wantLog == "" {
				if strings.Contains(log, "DRY-RUN") {
					t.Fatalf("off mode logged a dry-run action:\n%s", log)
				}
			} else if !strings.Contains(log, tc.wantLog) {
				t.Fatalf("dry-run not logged:\n%s", log)
			}
		})
	}
}
