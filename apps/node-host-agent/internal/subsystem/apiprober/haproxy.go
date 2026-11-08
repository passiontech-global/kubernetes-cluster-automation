package apiprober

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"strings"
	"time"
)

// dial connects to the HAProxy admin socket.
func (p *Prober) dial(ctx context.Context) (net.Conn, error) {
	if p.cfg.DialSocket != nil {
		return p.cfg.DialSocket(ctx, p.eff.socket)
	}
	d := net.Dialer{Timeout: p.cfg.TCPTimeout}
	return d.DialContext(ctx, "unix", p.eff.socket)
}

// haproxyReplyMaxBytes caps one admin-socket reply read — `show
// stat` CSV is the big one but still megabyte-scale, and a wedged
// HAProxy answering garbage forever must not slurp unbounded bytes
// into the agent's heap (hostexec's capped-runner parity).
const haproxyReplyMaxBytes = 4 << 20

// socketCmd sends one admin command and returns the response body.
// HAProxy runtime commands are newline-terminated and the server
// closes the connection after answering.
func (p *Prober) socketCmd(ctx context.Context, cmd string) (string, error) {
	conn, err := p.dial(ctx)
	if err != nil {
		return "", err
	}
	defer func() { _ = conn.Close() }()
	deadline := time.Now().Add(p.cfg.TCPTimeout)
	_ = conn.SetDeadline(deadline)
	if _, err := io.WriteString(conn, cmd+"\n"); err != nil {
		return "", err
	}
	out, err := io.ReadAll(io.LimitReader(conn, haproxyReplyMaxBytes))
	if err != nil {
		return "", err
	}
	return string(out), nil
}

// discover lists servers of the configured HAProxy backend via
// `show stat` (CSV). The first line carries the column names; rows are
// matched on pxname==BackendName with svname != BACKEND/FRONTEND.
func (p *Prober) discover(ctx context.Context) ([]backend, error) {
	out, err := p.socketCmd(ctx, "show stat")
	if err != nil {
		return nil, fmt.Errorf("show stat: %w", err)
	}
	var header map[string]int
	var backends []backend
	for _, line := range strings.Split(out, "\n") {
		line = strings.TrimRight(line, "\r")
		if line == "" {
			continue
		}
		if strings.HasPrefix(line, "#") {
			// CSV header. HAProxy emits "# pxname,..." but the
			// marker can come back glued ("#pxname") — strip the
			// '#' first, then whitespace. TrimPrefix("# ") left a
			// glued header unparsed: pxname never mapped, every row
			// was skipped, and cycles{ok} still counted over a
			// silently empty backend set.
			cols := strings.Split(
				strings.TrimSpace(strings.TrimPrefix(line, "#")), ",")
			header = make(map[string]int, len(cols))
			for i, c := range cols {
				header[strings.TrimSpace(c)] = i
			}
			// A header without the required columns is a schema
			// break — loud-fail instead of matching nothing.
			for _, req := range []string{"pxname", "svname", "status"} {
				if _, ok := header[req]; !ok {
					return nil, fmt.Errorf(
						"show stat: header missing %q column", req)
				}
			}
			continue
		}
		if header == nil {
			return nil, errors.New("show stat: data row before header")
		}
		fields := strings.Split(line, ",")
		get := func(col string) string {
			i, ok := header[col]
			if !ok || i >= len(fields) {
				return ""
			}
			return fields[i]
		}
		if get("pxname") != p.eff.backend {
			continue
		}
		svname := get("svname")
		if svname == "" || svname == "BACKEND" || svname == "FRONTEND" {
			continue
		}
		addr := get("addr")
		if addr == "" {
			// External API LB VMs run `server <name>` lines without an
			// addr — resolve it from StaticBackends (API_BACKENDS) by
			// name, api-backend-guard.sh parity.
			if sa := p.staticAddr(svname); sa != "" {
				addr = sa
			} else {
				// One unresolvable row must not fail the WHOLE
				// cycle — the other servers still probe/drain
				// normally (a stray server line is an ops config
				// bug, not an apiserver outage).
				logger().Warn("show stat: server has no addr column value and no API_BACKENDS match — skipping it",
					"server", svname, "backend", p.eff.backend,
				)
				continue
			}
		}
		// svname is a substring of the whole `show stat` buffer —
		// clone it before it becomes a p.states map key / Prometheus
		// label value, or every unique name pins the multi-KB CSV on
		// the heap forever.
		backends = append(backends, backend{
			Name:       strings.Clone(svname),
			Addr:       addr,
			Status:     get("status"),
			discovered: true,
		})
	}
	if header == nil {
		return nil, errors.New("show stat: no CSV header found")
	}
	return backends, nil
}

// haproxyServer issues "<action> server <backend>/<name>" on the admin
// socket for every backend in [BackendName]+CompanionBackends —
// api-backend-guard.sh's haproxy_srv parity (a wedged controller is
// drained on every lane it serves, and the shell ignored every
// reply). Only the PRIMARY backend's result propagates as an error:
// a companion socket/reply failure is Warn-logged and tolerated — it
// must not veto a drain the primary already applied, or the prober
// would forget it drained and retry-fail every cycle (the incident
// shape). "No such server" replies are no-ops everywhere: on
// companions always (the server may not exist there) and on the
// primary when tolerateMissingPrimary is set — for names the caller
// knows are not svnames of the primary backend (static-only
// API_BACKENDS entries), where the miss is expected, not an error
// worth retrying.
func (p *Prober) haproxyServer(ctx context.Context, action, name string,
	tolerateMissingPrimary bool) error {
	backends := append([]string{p.eff.backend}, p.eff.companions...)
	for i, be := range backends {
		out, err := p.socketCmd(ctx,
			fmt.Sprintf("%s server %s/%s", action, be, name))
		if err != nil {
			if i == 0 {
				return err
			}
			logger().Warn("haproxy companion backend command failed — tolerated",
				"command", action, "backend", be, "server", name,
				"error", err)
			continue
		}
		// "No such server" or permission errors come back as text —
		// an empty reply means success on HAProxy >= 2.x. Companions
		// may legitimately not carry this server (no-op in the shell).
		s := strings.TrimSpace(out)
		switch {
		case s == "":
			// Command accepted.
		case i > 0:
			if !strings.Contains(s, "No such server") {
				logger().Warn("haproxy companion backend rejected command — tolerated",
					"command", action, "backend", be, "server", name,
					"reply", s)
			}
		case strings.Contains(s, "No such server") && tolerateMissingPrimary:
			// Tolerated primary miss — see func doc.
		default:
			return fmt.Errorf("%s server %s/%s: %s", action, be, name, s)
		}
		// W5.2: `disable server` stops NEW traffic but every
		// long-lived session already pinned to the server survives —
		// the kubelet/cilium HTTP/2 watch streams ride the 24h
		// client timeout, so a wedged apiserver keeps feeding stale
		// data through the drain. Kill those sessions on the same
		// backend(s) the disable just landed on.
		if action == "disable" {
			p.shutdownSessions(ctx, be, name)
		}
	}
	return nil
}

// shutdownSessions issues `shutdown sessions server <be>/<name>` on
// the admin socket — the W5.2 complement of a disable: closes every
// session still stuck to the drained backend. Best-effort like the
// companion replies above (the shell ignored every socket reply): a
// failed shutdown must not veto a drain that already landed, and a
// "No such server" answer is the same expected no-op it is on
// disable.
func (p *Prober) shutdownSessions(ctx context.Context, be, name string) {
	out, err := p.socketCmd(ctx,
		fmt.Sprintf("shutdown sessions server %s/%s", be, name))
	if err != nil {
		logger().Warn("haproxy shutdown sessions failed — tolerated",
			"backend", be, "server", name, "error", err)
		return
	}
	if s := strings.TrimSpace(out); s != "" &&
		!strings.Contains(s, "No such server") {
		logger().Warn("haproxy shutdown sessions rejected — tolerated",
			"backend", be, "server", name, "reply", s)
	}
}
