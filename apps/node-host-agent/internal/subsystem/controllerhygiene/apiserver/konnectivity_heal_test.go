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
	"time"

	promtest "github.com/prometheus/client_golang/prometheus/testutil"
	corev1 "k8s.io/api/core/v1"

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

// TestKonnectivityNoWorkerResetsStreak: cycles spent with no Ready
// worker cannot justify a tunnel kill, so they must not accumulate
// toward the 3-cycle gate. Without the reset, the FIRST bad cycle
// after a worker returns would fire the kill on the back of a stale
// streak from the outage; the streak has to rebuild from zero.
func TestKonnectivityNoWorkerResetsStreak(t *testing.T) {
	e := fixture(t)
	e.H.Cfg.K0sRunDir = t.TempDir() // UDS missing — bad every cycle
	e.H.Cfg.KCMMetricsFn = func(_ context.Context, url string) (string, error) {
		if url == "http://127.0.0.1:8091/metrics" {
			return "konnectivity_network_proxy_server_ready_backend_connections 0\n", nil
		}
		return "", errors.New("unexpected scrape " + url)
	}
	e.MkProc(t, 4242, "konnectivity-se",
		[]string{"/var/lib/k0s/bin/konnectivity-server"}, 600)

	// Cluster-wide outage: three bad cycles but nobody to heal for.
	e.H.Client = &http.Client{Transport: nodesTransport{readyWorkers: 0}}
	for range 3 {
		e.H.Cycle(context.Background())
	}
	if len(e.Kills) != 0 {
		t.Fatalf("heal fired with zero Ready workers: %v", e.Kills)
	}

	// A real worker returns — the heal needs three FRESH bad cycles.
	e.H.Client = &http.Client{Transport: nodesTransport{readyWorkers: 1}}
	e.H.Cycle(context.Background())
	e.H.Cycle(context.Background())
	if len(e.Kills) != 0 {
		t.Fatalf("stale no-worker streak fired the kill on worker return: %v", e.Kills)
	}
	e.H.Cycle(context.Background())
	if len(e.Kills) != 1 || e.Kills[0].PID != 4242 {
		t.Fatalf("kills=%v want one kill after the rebuilt 3-cycle streak", e.Kills)
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

// virtualNodesTransport answers the node LIST with Ready nodes that
// are all virtual/shadow capacity (Liqo, virtual-kubelet, external
// instances) — none of them can dial the konnectivity tunnel.
type virtualNodesTransport struct{}

func (virtualNodesTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	if strings.HasSuffix(req.URL.Path, "/api/v1/nodes") {
		ready := `"status":{"conditions":[{"type":"Ready","status":"True"}]}`
		items := []string{
			`{"metadata":{"labels":{"type":"virtual-kubelet"}},` + ready + `}`,
			`{"metadata":{"labels":{"virtual-kubelet.io/provider":"azure"}},` + ready + `}`,
			`{"metadata":{"labels":{"liqo.io/type":"virtual-node"}},` + ready + `}`,
			// The real k8s label is node.kubernetes.io/instance-type;
			// the old bare "instance-type" check let these nodes
			// count as Ready workers.
			`{"metadata":{"labels":{"` + corev1.LabelInstanceTypeStable + `":"external"}},` + ready + `}`,
		}
		return &http.Response{
			Status: "200 OK", StatusCode: http.StatusOK,
			Header: make(http.Header),
			Body: io.NopCloser(strings.NewReader(
				`{"items":[` + strings.Join(items, ",") + `]}`)),
			Request: req,
		}, nil
	}
	return nil, errors.New("virtualNodesTransport: unexpected url " + req.URL.String())
}

// A node list made entirely of virtual/shadow nodes must read as
// zero usable workers — a kill there would sever the tunnel while
// no real worker could use it.
func TestKonnectivityVirtualNodesDoNotCountAsWorkers(t *testing.T) {
	e := fixture(t)
	e.H.Cfg.K0sRunDir = t.TempDir() // UDS missing — bad every cycle
	e.H.Cfg.KCMMetricsFn = func(_ context.Context, url string) (string, error) {
		if url == "http://127.0.0.1:8091/metrics" {
			return "konnectivity_network_proxy_server_ready_backend_connections 0\n", nil
		}
		return "", errors.New("unexpected scrape " + url)
	}
	e.H.Client = &http.Client{Transport: virtualNodesTransport{}}
	e.MkProc(t, 4242, "konnectivity-se",
		[]string{"/var/lib/k0s/bin/konnectivity-server"}, 600)
	for range 4 {
		e.H.Cycle(context.Background())
	}
	if len(e.Kills) != 0 {
		t.Fatalf("virtual nodes counted as Ready workers: %v", e.Kills)
	}
	if log := e.LogLines(); !strings.Contains(log, "no Ready workers") {
		t.Fatalf("virtual-node suppression not logged:\n%s", log)
	}
}

// After a heal action the bad-cycle streak must restart: otherwise
// every subsequent bad cycle re-fires the action (a chained latch).
// Dry-run mode has no rate budget to mask the chain, so count the
// DRY-RUN lines across six continuously-bad cycles.
func TestKonnectivityDryRunHealResetsStreak(t *testing.T) {
	e := fixture(t)
	e.H.Cfg.K0sRunDir = t.TempDir() // UDS missing — bad every cycle
	e.H.Cfg.Sig13.Mode = cdeps.ModeDryRun
	e.H.Cfg.KCMMetricsFn = func(_ context.Context, url string) (string, error) {
		if url == "http://127.0.0.1:8091/metrics" {
			return "konnectivity_network_proxy_server_ready_backend_connections 0\n", nil
		}
		return "", errors.New("unexpected scrape " + url)
	}
	e.H.Client = &http.Client{Transport: nodesTransport{readyWorkers: 1}}
	e.MkProc(t, 4242, "konnectivity-se",
		[]string{"/var/lib/k0s/bin/konnectivity-server"}, 600)
	for range 6 {
		e.H.Cycle(context.Background())
	}
	if n := strings.Count(e.LogLines(), "DRY-RUN: would kill konnectivity-server"); n != 2 {
		t.Fatalf("dry-run action fired %d times across 6 bad cycles, want 2 "+
			"(streak must restart after each action):\n%s", n, e.LogLines())
	}
}

type konnTrackBody struct {
	r         io.Reader
	bytesRead int64
	closed    bool
}

func (b *konnTrackBody) Read(p []byte) (int, error) {
	n, err := b.r.Read(p)
	b.bytesRead += int64(n)
	return n, err
}

func (b *konnTrackBody) Close() error {
	b.closed = true
	return nil
}

type konnRTFunc func(*http.Request) (*http.Response, error)

func (f konnRTFunc) RoundTrip(req *http.Request) (*http.Response, error) {
	return f(req)
}

type konnTrackRT struct {
	status int
	body   *konnTrackBody
}

func (rt *konnTrackRT) RoundTrip(req *http.Request) (*http.Response, error) {
	return &http.Response{
		Status:     fmt.Sprintf("%d", rt.status),
		StatusCode: rt.status,
		Header:     make(http.Header),
		Body:       rt.body,
		Request:    req,
	}, nil
}

func TestKonnectivityReadyWorkersDrainsBody(t *testing.T) {
	validJSON := `{"items":[{"metadata":{"labels":{}},"status":{"conditions":[{"type":"Ready","status":"True"}]}}]}`
	cases := []struct {
		name        string
		status      int
		payload     string
		maxRead     int64
		minRead     int64
		wantCleared bool
	}{
		{
			name:        "200 with trailing whitespace drained to EOF",
			status:      http.StatusOK,
			payload:     validJSON + strings.Repeat(" ", 128),
			minRead:     int64(len(validJSON) + 128),
			maxRead:     int64(len(validJSON) + 128),
			wantCleared: false, // 1 ready worker keeps streak (triggers heal check)
		},
		{
			name:        "200 malformed json with 128KiB tail bounded drain",
			status:      http.StatusOK,
			payload:     "{oops" + strings.Repeat("x", 128<<10),
			minRead:     5,
			maxRead:     (64 << 10) + 4096,
			wantCleared: true,
		},
		{
			name:        "500 with 128KiB error body skips json decode and drains 64KiB",
			status:      http.StatusInternalServerError,
			payload:     strings.Repeat("e", 128<<10),
			minRead:     64 << 10,
			maxRead:     64 << 10,
			wantCleared: true,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			e := fixture(t)
			e.H.Cfg.K0sRunDir = t.TempDir()
			e.H.Cfg.KCMMetricsFn = func(_ context.Context, url string) (string, error) {
				if url == "http://127.0.0.1:8091/metrics" {
					return "konnectivity_network_proxy_server_ready_backend_connections 0\n", nil
				}
				return "", errors.New("unexpected scrape " + url)
			}
			tb := &konnTrackBody{r: strings.NewReader(tc.payload)}
			// Drive 3 bad cycles; on cycle 3 readyWorkers runs on tb.
			calls := 0
			e.H.Client = &http.Client{Transport: konnRTFunc(func(req *http.Request) (*http.Response, error) {
				calls++
				if calls == 1 {
					return (&konnTrackRT{status: tc.status, body: tb}).RoundTrip(req)
				}
				return rawTransport{body: "{}"}.RoundTrip(req)
			})}
			for range 3 {
				e.H.Cycle(context.Background())
			}
			if !tb.closed {
				t.Fatal("response body was not closed")
			}
			if tb.bytesRead < tc.minRead || tb.bytesRead > tc.maxRead {
				t.Fatalf("bytesRead=%d want in [%d, %d]", tb.bytesRead, tc.minRead, tc.maxRead)
			}
			if tc.wantCleared && len(e.Kills) != 0 {
				t.Fatalf("expected 0 kills on 0 ready workers, got %v", e.Kills)
			}
		})
	}
}

// --- konnectivity-server goroutine & RSS leak guard ---

func setupHealthyKonnectivityTunnel(t *testing.T, e *env) {
	t.Helper()
	runDir := t.TempDir()
	e.H.Cfg.K0sRunDir = runDir
	if err := os.MkdirAll(filepath.Join(runDir, "konnectivity-server"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(runDir, "konnectivity-server",
		"konnectivity-server.sock"), []byte{}, 0o600); err != nil {
		t.Fatal(err)
	}
	e.H.Client = &http.Client{Transport: nodesTransport{readyWorkers: 2}}
	e.MkProc(t, 4242, "konnectivity-se",
		[]string{"/var/lib/k0s/bin/konnectivity-server", "--uds-name=x"}, 600)
}

func TestKonnectivityLeakGuardNormalNoop(t *testing.T) {
	e := fixture(t)
	setupHealthyKonnectivityTunnel(t, e)
	e.SetProcRSS(t, 4242, 42<<20) // 42 MiB — normal
	e.H.Cfg.KCMMetricsFn = func(_ context.Context, url string) (string, error) {
		if url == "http://127.0.0.1:8091/metrics" {
			return "konnectivity_network_proxy_server_ready_backend_connections 2\n" +
				"go_goroutines 199\n", nil
		}
		return "", errors.New("unexpected scrape " + url)
	}
	for range 5 {
		e.H.Cycle(context.Background())
	}
	if len(e.Kills) != 0 {
		t.Fatalf("normal konnectivity-server triggered kill: %v", e.Kills)
	}
}

func TestKonnectivityLeakGuardGoroutinesSIGTERM(t *testing.T) {
	e := fixture(t)
	setupHealthyKonnectivityTunnel(t, e)
	e.SetProcRSS(t, 4242, 42<<20) // RSS normal; goroutines leaking
	e.H.Cfg.KCMMetricsFn = func(_ context.Context, url string) (string, error) {
		if url == "http://127.0.0.1:8091/metrics" {
			return "# HELP go_goroutines Number of goroutines.\n" +
				"konnectivity_network_proxy_server_ready_backend_connections 2\n" +
				"go_goroutines 60254\n", nil
		}
		return "", errors.New("unexpected scrape " + url)
	}
	// Cycles 1 & 2: below 3-cycle streak -> no SIGTERM.
	e.H.Cycle(context.Background())
	e.H.Cycle(context.Background())
	if len(e.Kills) != 0 {
		t.Fatalf("kill fired before 3-cycle streak: %v", e.Kills)
	}
	// Cycle 3: 3 consecutive leak cycles -> SIGTERM.
	e.H.Cycle(context.Background())
	if len(e.Kills) != 1 || e.Kills[0].PID != 4242 || e.Kills[0].Sig != syscall.SIGTERM {
		t.Fatalf("kills=%v want [{4242 SIGTERM}]", e.Kills)
	}
	log := e.LogLines()
	if !strings.Contains(log, "ACTION:") || !strings.Contains(log, "goroutines=60254>10000") {
		t.Fatalf("ACTION log missing goroutines reason:\n%s", log)
	}
}

func TestKonnectivityLeakGuardRSSSIGTERM(t *testing.T) {
	e := fixture(t)
	setupHealthyKonnectivityTunnel(t, e)
	e.SetProcRSS(t, 4242, 1844<<20) // 1844 MiB > 512 MiB
	e.H.Cfg.KCMMetricsFn = func(_ context.Context, url string) (string, error) {
		if url == "http://127.0.0.1:8091/metrics" {
			return "konnectivity_network_proxy_server_ready_backend_connections 2\n" +
				"go_goroutines 199\n", nil
		}
		return "", errors.New("unexpected scrape " + url)
	}
	e.H.Cycle(context.Background())
	e.H.Cycle(context.Background())
	if len(e.Kills) != 0 {
		t.Fatalf("RSS kill fired before 3-cycle streak: %v", e.Kills)
	}
	e.H.Cycle(context.Background())
	if len(e.Kills) != 1 || e.Kills[0].PID != 4242 || e.Kills[0].Sig != syscall.SIGTERM {
		t.Fatalf("kills=%v want [{4242 SIGTERM}]", e.Kills)
	}
	log := e.LogLines()
	if !strings.Contains(log, "ACTION:") || !strings.Contains(log, "rss_mib=1844>512") {
		t.Fatalf("ACTION log missing rss_mib reason:\n%s", log)
	}
}

func TestKonnectivityLeakGuardSpikeOneCycleNoKill(t *testing.T) {
	e := fixture(t)
	setupHealthyKonnectivityTunnel(t, e)
	e.SetProcRSS(t, 4242, 42<<20)
	goroutines := 60254
	e.H.Cfg.KCMMetricsFn = func(_ context.Context, url string) (string, error) {
		if url == "http://127.0.0.1:8091/metrics" {
			return fmt.Sprintf("konnectivity_network_proxy_server_ready_backend_connections 2\n"+
				"go_goroutines %d\n", goroutines), nil
		}
		return "", errors.New("unexpected scrape " + url)
	}
	// Spike 1 cycle -> recover -> 2 leak cycles: never reaches 3 consecutive.
	e.H.Cycle(context.Background())
	goroutines = 199
	e.H.Cycle(context.Background())
	goroutines = 60254
	e.H.Cycle(context.Background())
	e.H.Cycle(context.Background())
	if len(e.Kills) != 0 {
		t.Fatalf("transient 1-cycle spike caused kill: %v", e.Kills)
	}
}

func TestKonnectivityLeakGuardCooldownActiveNoDoubleKill(t *testing.T) {
	e := fixture(t)
	setupHealthyKonnectivityTunnel(t, e)
	e.SetProcRSS(t, 4242, 1844<<20)
	e.H.Cfg.KCMMetricsFn = func(_ context.Context, url string) (string, error) {
		if url == "http://127.0.0.1:8091/metrics" {
			return "konnectivity_network_proxy_server_ready_backend_connections 2\n" +
				"go_goroutines 60254\n", nil
		}
		return "", errors.New("unexpected scrape " + url)
	}
	// First 3 cycles -> first SIGTERM.
	for range 3 {
		e.H.Cycle(context.Background())
	}
	if len(e.Kills) != 1 || e.Kills[0].Sig != syscall.SIGTERM {
		t.Fatalf("first kill missing: %v", e.Kills)
	}
	// Still inside 30m cooldown -> 3 more leak cycles must NOT double kill.
	e.Now = e.Now.Add(15 * time.Minute)
	for range 3 {
		e.H.Cycle(context.Background())
	}
	if len(e.Kills) != 1 {
		t.Fatalf("cooldown failed to suppress double kill: %v", e.Kills)
	}
	// Past 30m cooldown -> next leak cycle kills again.
	e.Now = e.Now.Add(20 * time.Minute)
	e.H.Cycle(context.Background())
	if len(e.Kills) != 2 || e.Kills[1].Sig != syscall.SIGTERM {
		t.Fatalf("expected second SIGTERM after cooldown, got %v", e.Kills)
	}
}

func TestKonnectivityLeakGuardDisabledWhenKnobZero(t *testing.T) {
	for _, tc := range []struct {
		name string
		mut  func(e *env)
	}{
		{
			name: "goroutines_disabled",
			mut: func(e *env) {
				e.H.Cfg.CPFreeze.KonnectivityMaxGoroutines = 0
				e.SetProcRSS(t, 4242, 42<<20)
			},
		},
		{
			name: "rss_disabled",
			mut: func(e *env) {
				e.H.Cfg.CPFreeze.KonnectivityMaxRSSMiB = 0
				e.SetProcRSS(t, 4242, 1844<<20)
				e.H.Cfg.KCMMetricsFn = func(_ context.Context, url string) (string, error) {
					if url == "http://127.0.0.1:8091/metrics" {
						return "konnectivity_network_proxy_server_ready_backend_connections 2\n" +
							"go_goroutines 199\n", nil
					}
					return "", errors.New("unexpected scrape " + url)
				}
			},
		},
		{
			name: "both_disabled",
			mut: func(e *env) {
				e.H.Cfg.CPFreeze.KonnectivityMaxGoroutines = 0
				e.H.Cfg.CPFreeze.KonnectivityMaxRSSMiB = 0
				e.SetProcRSS(t, 4242, 1844<<20)
			},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			e := fixture(t)
			setupHealthyKonnectivityTunnel(t, e)
			e.H.Cfg.KCMMetricsFn = func(_ context.Context, url string) (string, error) {
				if url == "http://127.0.0.1:8091/metrics" {
					return "konnectivity_network_proxy_server_ready_backend_connections 2\n" +
						"go_goroutines 60254\n", nil
				}
				return "", errors.New("unexpected scrape " + url)
			}
			tc.mut(e)
			for range 4 {
				e.H.Cycle(context.Background())
			}
			if len(e.Kills) != 0 {
				t.Fatalf("%s: disabled knob still killed: %v", tc.name, e.Kills)
			}
		})
	}
}

func TestParseKonnectivityGoroutines(t *testing.T) {
	if v, ok := apiserver.ParseKonnectivityGoroutines("# go_goroutines 99999\ngo_goroutines_extra 99999\ngo_goroutines 60254\n"); !ok || v != 60254 {
		t.Fatalf("got (%v, %v), want (60254, true)", v, ok)
	}
	if v, ok := apiserver.ParseKonnectivityGoroutines("go_goroutines 6.0254e+04\n"); !ok || v != 60254 {
		t.Fatalf("scientific notation: got (%v, %v), want (60254, true)", v, ok)
	}
	if _, ok := apiserver.ParseKonnectivityGoroutines("go_goroutines\n"); ok {
		t.Fatal("valueless go_goroutines parsed")
	}
	if _, ok := apiserver.ParseKonnectivityGoroutines("other_metric 1\n"); ok {
		t.Fatal("absent go_goroutines parsed")
	}
}
