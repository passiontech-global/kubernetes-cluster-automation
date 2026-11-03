// Package watchdogconf parses the host's /etc/node-watchdog.conf —
// the shell-style KEY=VALUE file ansible writes per node (node_tuning
// / hub_converge plays) and that every watchdog module sources
// through lib.sh. The Go agent reads the same file so per-node
// overlays, egress relays, DNS fallback maps and API backend lists
// stay identical between the shell runner and the agent.
//
// Tolerances (1:1 with `source file` in bash):
//   - `#` comments (whole-line and inline), blank lines, `export `
//     prefixes.
//   - single/double-quoted values; unquoted values keep inner spaces
//     (a list is just words).
//   - a missing file is NOT an error — Load returns an empty Config
//     (nodes without the file run on defaults exactly like the shell
//     modules did).
//   - OVERLAY_* keys fall back to their TINC_* predecessors, same as
//     lib.sh's rename migration (conf files written before the
//     2026-10 overlay-agnostic rewrite still apply).
//   - WD_SIG_<NAME>=off|0|false|disabled marks a watchdog signal
//     module disabled — same kill switch the runner reads.
package watchdogconf

import (
	"fmt"
	"log/slog"
	"net"
	"os"
	"strconv"
	"strings"
	"sync"
)

// DNSEntry is one DNS_FALLBACK_MAP element "name[:port]=ip1,ip2,..." —
// port defaults 443 when omitted.
type DNSEntry struct {
	Name       string
	Port       string
	Candidates []string
}

// APIBackend is one API_BACKENDS/API_LB_SERVERS element
// "name=ip:port" (or bare "ip:port" — Name falls back to Addr).
type APIBackend struct {
	Name string
	Addr string
}

// Config is the parsed node-watchdog.conf. Empty slices/maps are nil
// — consumers check len() so "unset" and "explicitly empty" behave
// the same, matching the shell's `${VAR:-}` defaults.
type Config struct {
	OverlayProbeTargets    []string          // OVERLAY_PROBE_TARGETS (dataplane ping targets)
	OverlayProbeMarkers    []string          // OVERLAY_PROBE_MARKERS (lighthouse/marker set)
	OverlaySlowpathMarkers []string          // OVERLAY_SLOWPATH_MARKERS (subset of markers, RTT thresholded)
	OverlaySiteMarkers     []string          // OVERLAY_SITE_MARKERS (site-mesh edges)
	OverlaySlowpathRTTms   float64           // OVERLAY_SLOWPATH_RTT_MS (default 100)
	OverlaySiteedgeRTTms   float64           // OVERLAY_SITEEDGE_RTT_MS (default 50)
	OverlayProbeCount      int               // OVERLAY_PROBE_COUNT (default 3)
	OverlayProbeWait       int               // OVERLAY_PROBE_WAIT seconds (default 4)
	OverlayEgressTCP       map[string]string // OVERLAY_EGRESS_TCP entries ip:port → ip→port
	OverlayEgressRelays    []string          // OVERLAY_EGRESS_RELAYS (egress fallback IPs)
	OverlayEgressTable     int               // OVERLAY_EGRESS_TABLE (default 100)
	OverlayActive          string            // OVERLAY_ACTIVE (nebula|tinc; default tinc)
	DNSFallback            []DNSEntry        // DNS_FALLBACK_MAP
	APIBackends            []APIBackend      // API_BACKENDS (per-controller ip:port, never via VIP)
	NebulaNet              string            // NEBULA_NET (default interdc)
	NebulaDev              string            // NEBULA_DEV (default neb1)
	NebulaPort             int               // NEBULA_PORT (default 45670)
	NebulaStatsURL         string            // NEBULA_STATS_URL (empty = stats probe disabled)
	NebulaDegradedConsec   int               // NEBULA_DEGRADED_CONSEC (default 2)
	TincNet                string            // TINC_NET (default interdc)

	// --- controller-plane block (written only on hub/lighthouse
	// nodes — hostconfig's SIG13 section). Raw values are kept
	// verbatim ("off"/"dry-run"/"enforce", counts in seconds) —
	// consumers apply their own defaults on empty/0, exactly like
	// the shell's ${VAR:-def} expansions.
	APISelf             string // API_SELF "ip:port" — first-hub ordering identity
	APIPeer             string // API_PEER "ip:port" — empty = single-hub
	KineDBProbe         string // KINE_DB_PROBE "host:port" — pg-wire probe
	Sig13Autofix        string // SIG13_AUTOFIX (off|dry-run|enforce)
	Sig13MinRestartS    int    // SIG13_MIN_RESTART_S
	Sig13StaleMinErrs   int    // APISERVER_STALE_MIN_ERRS
	Sig13SoloCycles     int    // APISERVER_SOLO_CYCLES
	Sig13GapMin         int64  // APISERVER_GAP_MIN
	Sig13GapCycles      int    // APISERVER_GAP_CYCLES
	Sig13FrozenCycles   int    // APISERVER_FROZEN_CYCLES
	KineTTLAutofix      string // KINE_TTL_AUTOFIX
	KineTTLMinRestartS  int    // KINE_TTL_MIN_RESTART_S
	KineTTLRewedgeCycle int    // KINE_TTL_REWEDGE_CYCLES
	KineTTLCtlRestartS  int    // KINE_TTL_CTL_RESTART_S
	KinePoolAutofix     string // KINE_POOL_AUTOFIX
	KinePoolMaxConns    int    // KINE_POOL_MAX_CONNS
	KinePoolCycles      int    // KINE_POOL_CYCLES
	KinePoolMinRestartS int    // KINE_POOL_MIN_RESTART_S
	OOMLoopAutofix      string // K0S_OOMLOOP_AUTOFIX
	OOMLoopMinKills     int    // K0S_OOMLOOP_MIN_KILLS
	OOMLoopWindowS      int    // K0S_OOMLOOP_WINDOW_S

	// Disabled holds normalized signal names turned off via
	// WD_SIG_<NAME> — lowercase with '-' separators ("overlay-egress").
	Disabled map[string]bool
}

// parseScalar strips surrounding single/double quotes.
func parseScalar(v string) string {
	if len(v) >= 2 {
		if (v[0] == '"' && v[len(v)-1] == '"') ||
			(v[0] == '\'' && v[len(v)-1] == '\'') {
			return v[1 : len(v)-1]
		}
	}
	return v
}

// parseValue cuts a raw VALUE at the first '#' that opens a bash
// comment — outside quotes and at a word boundary (value start or
// after whitespace). A '#' inside quotes or glued to the previous
// word is literal (KEY="a # b" → `a # b`, KEY=a#b → `a#b`), and a
// comment after a quoted value is stripped too (KEY="a b" # note →
// `a b`) — bash `source` parity.
func parseValue(val string) string {
	var out strings.Builder
	out.Grow(len(val))
	var quote byte
	wordStart := true // the value itself begins a word
	for i := 0; i < len(val); i++ {
		ch := val[i]
		if quote != 0 {
			out.WriteByte(ch)
			if ch == quote {
				quote = 0
			}
			continue
		}
		switch ch {
		case '"', '\'':
			quote = ch
			wordStart = false
			out.WriteByte(ch)
		case ' ', '\t':
			wordStart = true
			out.WriteByte(ch)
		case '#':
			if wordStart {
				return strings.TrimSpace(out.String())
			}
			out.WriteByte(ch)
		default:
			wordStart = false
			out.WriteByte(ch)
		}
	}
	return strings.TrimSpace(out.String())
}

// parseKV parses shell-style KEY=VALUE lines into a map. An inline
// `#` comment ends an unquoted value (bash parity); a `#` inside
// quotes is literal.
func parseKV(data string) map[string]string {
	vars := map[string]string{}
	for _, line := range strings.Split(data, "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		if v, ok := strings.CutPrefix(line, "export "); ok {
			line = strings.TrimSpace(v)
		}
		key, val, ok := strings.Cut(line, "=")
		if !ok {
			continue
		}
		key = strings.TrimSpace(key)
		if key == "" {
			continue
		}
		vars[key] = parseScalar(parseValue(strings.TrimSpace(val)))
	}
	return vars
}

func wordList(v string) []string {
	var out []string
	for _, w := range strings.Fields(v) {
		out = append(out, w)
	}
	return out
}

// pick returns vars[primary] if set (even empty-string set? bash's
// ${A:-${B:-}} only falls back on UNSET-or-empty — mirror that: an
// explicitly empty primary wins over a non-empty fallback).
func pick(vars map[string]string, primary, fallback string) string {
	if v, ok := vars[primary]; ok && v != "" {
		return v
	}
	return vars[fallback]
}

func parseAPIBackend(entry string) (APIBackend, bool) {
	name, addr, hasEq := strings.Cut(entry, "=")
	if !hasEq {
		// Bare "ip:port" — the addr is the name too (API_BACKENDS on
		// workers is sometimes written without haproxy names).
		entry = strings.TrimSpace(entry)
		if entry == "" {
			return APIBackend{}, false
		}
		return APIBackend{Name: entry, Addr: entry}, true
	}
	name, addr = strings.TrimSpace(name), strings.TrimSpace(addr)
	if name == "" || addr == "" {
		return APIBackend{}, false
	}
	return APIBackend{Name: name, Addr: addr}, true
}

func parseDNSEntry(entry string) (DNSEntry, bool) {
	nameport, cands, ok := strings.Cut(entry, "=")
	if !ok || nameport == "" || cands == "" {
		return DNSEntry{}, false
	}
	name, port, hasPort := strings.Cut(nameport, ":")
	if !hasPort || port == "" {
		port = "443"
	}
	var ips []string
	for _, c := range strings.Split(cands, ",") {
		if c = strings.TrimSpace(c); c != "" {
			ips = append(ips, c)
		}
	}
	if name == "" || len(ips) == 0 {
		return DNSEntry{}, false
	}
	return DNSEntry{Name: name, Port: port, Candidates: ips}, true
}

func num(v string, def float64) float64 {
	if f, err := strconv.ParseFloat(strings.TrimSpace(v), 64); err == nil {
		return f
	}
	return def
}

// Load parses the conf at path. A missing file returns an empty
// Config and nil error — the watchdog's documented behaviour
// ("node has no conf file -> every module self-skips to defaults").
func Load(path string) (*Config, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			// Missing file = all-defaults config (shell parity:
			// modules ran on defaults without a conf).
			return Parse(nil)
		}
		return nil, fmt.Errorf("read %s: %w", path, err)
	}
	return Parse(data)
}

// Parse parses conf content — separated from Load so tests and the
// runner-feeder can parse embedded text.
func Parse(data []byte) (*Config, error) {
	vars := parseKV(string(data))
	c := &Config{Disabled: map[string]bool{}}

	c.OverlayProbeTargets = wordList(pick(vars, "OVERLAY_PROBE_TARGETS", "TINC_PROBE_TARGETS"))
	c.OverlayProbeMarkers = wordList(pick(vars, "OVERLAY_PROBE_MARKERS", "TINC_PROBE_MARKERS"))
	c.OverlaySlowpathMarkers = wordList(pick(vars, "OVERLAY_SLOWPATH_MARKERS", "TINC_SLOWPATH_MARKERS"))
	c.OverlaySiteMarkers = wordList(pick(vars, "OVERLAY_SITE_MARKERS", "TINC_SITE_MARKERS"))
	c.OverlaySlowpathRTTms = num(pick(vars, "OVERLAY_SLOWPATH_RTT_MS", "TINC_SLOWPATH_RTT_MS"), 100)
	c.OverlaySiteedgeRTTms = num(pick(vars, "OVERLAY_SITEEDGE_RTT_MS", "TINC_SITEEDGE_RTT_MS"), 50)
	c.OverlayProbeCount = int(num(vars["OVERLAY_PROBE_COUNT"], 3))
	c.OverlayProbeWait = int(num(vars["OVERLAY_PROBE_WAIT"], 4))
	c.OverlayEgressRelays = wordList(pick(vars, "OVERLAY_EGRESS_RELAYS", "TINC_EGRESS_RELAYS"))
	c.OverlayEgressTable = int(num(vars["OVERLAY_EGRESS_TABLE"], 100))
	c.OverlayActive = vars["OVERLAY_ACTIVE"]
	if c.OverlayActive == "" {
		c.OverlayActive = "tinc"
	}
	for _, e := range wordList(pick(vars, "OVERLAY_EGRESS_TCP", "TINC_EGRESS_TCP")) {
		ip, port, ok := strings.Cut(e, ":")
		if !ok || ip == "" || port == "" {
			continue
		}
		if c.OverlayEgressTCP == nil {
			c.OverlayEgressTCP = map[string]string{}
		}
		c.OverlayEgressTCP[ip] = port
	}
	for _, e := range wordList(vars["DNS_FALLBACK_MAP"]) {
		if d, ok := parseDNSEntry(e); ok {
			c.DNSFallback = append(c.DNSFallback, d)
		}
	}
	for _, e := range wordList(vars["API_BACKENDS"]) {
		if b, ok := parseAPIBackend(e); ok {
			c.APIBackends = append(c.APIBackends, b)
		}
	}
	c.NebulaNet = vars["NEBULA_NET"]
	if c.NebulaNet == "" {
		c.NebulaNet = "interdc"
	}
	c.NebulaDev = vars["NEBULA_DEV"]
	if c.NebulaDev == "" {
		c.NebulaDev = "neb1"
	}
	c.NebulaPort = int(num(vars["NEBULA_PORT"], 45670))
	c.NebulaStatsURL = vars["NEBULA_STATS_URL"]
	c.NebulaDegradedConsec = int(num(vars["NEBULA_DEGRADED_CONSEC"], 2))
	c.TincNet = vars["TINC_NET"]
	if c.TincNet == "" {
		c.TincNet = "interdc"
	}
	// Controller-plane block — raw values; consumers apply their
	// own defaults (shell ${VAR:-def} parity).
	c.APISelf = vars["API_SELF"]
	c.APIPeer = vars["API_PEER"]
	c.KineDBProbe = vars["KINE_DB_PROBE"]
	c.Sig13Autofix = vars["SIG13_AUTOFIX"]
	c.Sig13MinRestartS = int(num(vars["SIG13_MIN_RESTART_S"], 0))
	c.Sig13StaleMinErrs = int(num(vars["APISERVER_STALE_MIN_ERRS"], 0))
	c.Sig13SoloCycles = int(num(vars["APISERVER_SOLO_CYCLES"], 0))
	c.Sig13GapMin = int64(num(vars["APISERVER_GAP_MIN"], 0))
	c.Sig13GapCycles = int(num(vars["APISERVER_GAP_CYCLES"], 0))
	c.Sig13FrozenCycles = int(num(vars["APISERVER_FROZEN_CYCLES"], 0))
	c.KineTTLAutofix = vars["KINE_TTL_AUTOFIX"]
	c.KineTTLMinRestartS = int(num(vars["KINE_TTL_MIN_RESTART_S"], 0))
	c.KineTTLRewedgeCycle = int(num(vars["KINE_TTL_REWEDGE_CYCLES"], 0))
	c.KineTTLCtlRestartS = int(num(vars["KINE_TTL_CTL_RESTART_S"], 0))
	c.KinePoolAutofix = vars["KINE_POOL_AUTOFIX"]
	c.KinePoolMaxConns = int(num(vars["KINE_POOL_MAX_CONNS"], 0))
	c.KinePoolCycles = int(num(vars["KINE_POOL_CYCLES"], 0))
	c.KinePoolMinRestartS = int(num(vars["KINE_POOL_MIN_RESTART_S"], 0))
	c.OOMLoopAutofix = vars["K0S_OOMLOOP_AUTOFIX"]
	c.OOMLoopMinKills = int(num(vars["K0S_OOMLOOP_MIN_KILLS"], 0))
	c.OOMLoopWindowS = int(num(vars["K0S_OOMLOOP_WINDOW_S"], 0))
	for k, v := range vars {
		name, ok := strings.CutPrefix(k, "WD_SIG_")
		if !ok {
			continue
		}
		switch strings.ToLower(strings.TrimSpace(v)) {
		case "off", "0", "false", "disabled":
			norm := strings.ToLower(strings.ReplaceAll(name, "_", "-"))
			c.Disabled[norm] = true
		}
	}
	c.Normalize()
	return c, nil
}

// Normalize applies the shell defaults to unset fields — callers that
// construct a Config literally (wiring, tests) get the same baseline
// as a parsed file.
func (c *Config) Normalize() {
	if c.OverlaySlowpathRTTms <= 0 {
		c.OverlaySlowpathRTTms = 100
	}
	if c.OverlaySiteedgeRTTms <= 0 {
		c.OverlaySiteedgeRTTms = 50
	}
	if c.OverlayProbeCount <= 0 {
		c.OverlayProbeCount = 3
	}
	if c.OverlayProbeWait <= 0 {
		c.OverlayProbeWait = 4
	}
	if c.OverlayEgressTable <= 0 {
		c.OverlayEgressTable = 100
	}
	if c.OverlayActive == "" {
		c.OverlayActive = "tinc"
	}
	if c.NebulaNet == "" {
		c.NebulaNet = "interdc"
	}
	if c.NebulaDev == "" {
		c.NebulaDev = "neb1"
	}
	if c.NebulaPort <= 0 {
		c.NebulaPort = 45670
	}
	if c.NebulaDegradedConsec <= 0 {
		c.NebulaDegradedConsec = 2
	}
	if c.TincNet == "" {
		c.TincNet = "interdc"
	}
}

// SignalEnabled reports whether the named watchdog signal is enabled —
// WD_SIG_<NAME> with '-' → '_' and uppercased; "off"/"0"/"false"/
// "disabled" values disable, everything else (including unset) is on.
func (c *Config) SignalEnabled(name string) bool {
	norm := strings.ToLower(strings.ReplaceAll(name, "_", "-"))
	return !c.Disabled[norm]
}

// APIBackendIPs returns the host part of every configured API backend
// — module 06's upstream gate checks state-apiserver-backend-stale-
// <ip-dashed>, which keys on the bare IP.
func (c *Config) APIBackendIPs() []string {
	var out []string
	for _, b := range c.APIBackends {
		host := b.Addr
		if h, _, err := net.SplitHostPort(host); err == nil {
			host = h
		} else if i := strings.LastIndexByte(host, ':'); i >= 0 {
			host = host[:i] // "ip:port" that SplitHostPort still rejected
		}
		out = append(out, host)
	}
	return out
}

// Reloader hands out the current conf, re-reading Path on every Get —
// hostconfig rewrites /etc/node-watchdog.conf mid-run (API_BACKENDS,
// OVERLAY_*, WD_SIG_* flips land next cycle), so consumers must not
// pin the startup parse. The file is a few KB; a plain re-read per
// cycle is the simplest correct semantics — no mtime/size window
// where a same-second rewrite is missed.
//
// A missing file yields the all-defaults config and an unparseable
// (hard-error) file keeps the last good one — the shell `source`
// semantics were "read fresh each run, defaults on absent". Get is
// safe for concurrent use.
type Reloader struct {
	Path string

	mu  sync.Mutex
	cfg *Config
}

// NewReloader seeds the reloader with initial (nil → empty baseline)
// and points it at path.
func NewReloader(path string, initial *Config) *Reloader {
	if initial == nil {
		initial, _ = Parse(nil)
	}
	return &Reloader{Path: path, cfg: initial}
}

// Get returns the freshest parse of Path, falling back to the last
// good config on read/parse errors.
func (r *Reloader) Get() *Config {
	r.mu.Lock()
	defer r.mu.Unlock()
	if c, err := Load(r.Path); err != nil {
		slog.Warn("watchdogconf: reload failed — keeping last good config",
			"subsystem", "watchdogconf", "path", r.Path, "error", err)
	} else if c != nil {
		r.cfg = c
	}
	return r.cfg
}
