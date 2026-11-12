// sdnotify.go — sd-watchdog: the sd_notify self-watchdog for the
// standalone systemd mode, split out of agent.go. On the standalone
// hosts hubsync converges (db-vm, api-lb VMs, controllers) there is
// no kubelet livenessProbe to kill a wedged agent — the unit carries
// WatchdogSec=120s instead and expects the process itself to feed
// it. The loop is pure Go (unixgram datagrams to NOTIFY_SOCKET —
// `systemd-notify` parity; the wire format lives in
// internal/platform/sdnotify, shared with controllerhygiene's
// feeder): READY=1 once both listeners are bound and a.ready
// flipped, then WATCHDOG=1 every sdWatchdogInterval while the probe
// mux answers a real HTTP self-probe. A wedged probe server stops
// the feed — the skipped datagrams ARE the failure signal (systemd
// restarts the unit at WatchdogSec), so a deaf agent can never mask
// its own hang. NOTIFY_SOCKET is a systemd contract, not a
// NODE_HOST_AGENT_* knob (controllerhygiene config_feeder.go
// parity) — read it directly.
package agent

import (
	"context"
	"io"
	"net"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-host-agent/internal/platform/sdnotify"
)

var (
	// sdWatchdogInterval is the WATCHDOG=1 cadence — comfortably
	// under the unit's WatchdogSec=120s so a single skipped tick
	// can't trip the watchdog. Package var so tests don't wait.
	sdWatchdogInterval = 30 * time.Second
	// sdProbeTimeout bounds the probe-mux self-probe — a hung mux
	// must show as unhealthy well inside the watchdog window.
	sdProbeTimeout = 10 * time.Second
)

// sdNotifyLoop feeds the unit's watchdog until ctx is cancelled. It
// returns immediately when the process was not launched by systemd
// (no NOTIFY_SOCKET — pod mode, tests) so the goroutine is a no-op
// outside standalone deployments.
func (a *Agent) sdNotifyLoop(ctx context.Context) {
	sock := os.Getenv(sdnotify.SocketEnv)
	if sock == "" || !a.ready.Load() {
		return
	}
	conn, err := sdnotify.Dial(sock)
	if err != nil {
		logger().Warn("sd_notify: NOTIFY_SOCKET dial failed — watchdog feed disabled",
			"socket", sock, "error", err)
		return
	}
	defer func() { _ = conn.Close() }()
	send := func(msg string) {
		if err := sdnotify.Send(conn, msg); err != nil {
			logger().Warn("sd_notify: send failed",
				"msg", strings.TrimSpace(msg), "error", err)
		}
	}
	send("READY=1\n")
	probeURL := a.probeSelfURL()
	client := &http.Client{Timeout: sdProbeTimeout}
	tick := time.NewTicker(sdWatchdogInterval)
	defer tick.Stop()
	for {
		select {
		case <-ctx.Done():
			// STOPPING=1 tells systemd the shutdown is deliberate —
			// without it a clean exit inside WatchdogSec still
			// reads as an unclean stop to Type=notify bookkeeping.
			send("STOPPING=1\n")
			return
		case <-tick.C:
		}
		if !a.probeHealthy(client, probeURL) {
			logger().Warn("sd_notify: probe mux unhealthy — skipping WATCHDOG=1")
			continue
		}
		send("WATCHDOG=1\n")
	}
}

// probeSelfURL is the probe mux's loopback /healthz — "" when
// cfg.ProbeAddr can't be parsed (the health verdict then falls back
// to the ready flag alone).
func (a *Agent) probeSelfURL() string {
	host, port, err := net.SplitHostPort(a.cfg.ProbeAddr)
	if err != nil {
		return ""
	}
	if host == "" || host == "0.0.0.0" || host == "::" {
		// Wildcard binds (":8091", "0.0.0.0:8091", "[::]:8091")
		// can't be self-dialed — probe loopback instead.
		host = "127.0.0.1"
	}
	return "http://" + net.JoinHostPort(host, port) + "/healthz"
}

// probeHealthy gates the watchdog feed: the ready flag must hold AND
// the probe mux must answer /healthz 200 — the HTTP round-trip is
// what proves the mux isn't accept-wedged (a bare flag read can't
// see that).
func (a *Agent) probeHealthy(client *http.Client, probeURL string) bool {
	if !a.ready.Load() {
		return false
	}
	if probeURL == "" {
		return true
	}
	resp, err := client.Get(probeURL)
	if err != nil {
		return false
	}
	defer func() {
		_, _ = io.Copy(io.Discard, resp.Body)
		_ = resp.Body.Close()
	}()
	return resp.StatusCode == http.StatusOK
}
