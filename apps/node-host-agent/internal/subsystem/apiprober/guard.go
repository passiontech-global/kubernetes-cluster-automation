package apiprober

import (
	"strconv"
	"strings"

	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-host-agent/internal/platform/fileconf"
)

// --- /etc/api-backend-guard.conf (standalone api-lb-vm defaults) ---
//
// hostconfig renders a KEY=VALUE shell-env conf on api-lb VMs (the
// file the retired api-backend-guard.sh sourced). The standalone
// agent feeds it as the fallback layer below the env knobs — env →
// guard.conf → compiled defaults — and (via Config.GuardSrc) as a
// per-cycle live overlay so conf writes/edits take effect without
// an agent restart. Keys:
//
//	HAPROXY_SOCKET   admin unix socket → SocketPath
//	HAPROXY_BACKEND  primary backend   → BackendName
//	HAPROXY_BACKENDS full action set   → CompanionBackends (minus the primary)
//	API_BACKENDS     "name=ip:port" list → StaticBackends
//	MODE             dry-run|enforce   → Mode
//	API_TOKEN_FILE/API_CA_FILE         → TokenFile/CAFile
//	TOKEN_FILE/CA_FILE                 → short-spelling fallback for the same
//	GAP_MIN/FAIL_CYCLES/FROZEN_CYCLES/RECOVER_CYCLES → thresholds
//
// (STATE_DIR is intentionally unmapped — the Go port keeps per-
// backend counters in memory; the watchdog compat files live in
// WatchdogStateDir, a different dir with different contents.)

// GuardDefaults is the parsed api-backend-guard.conf — every field
// zero means "fall through to the compiled default".
type GuardDefaults struct {
	SocketPath        string
	BackendName       string
	CompanionBackends []string
	StaticBackends    []StaticBackend
	Mode              string
	TokenFile         string
	CAFile            string
	GapMin            int64 // GAP_MIN
	FailCycles        int   // FAIL_CYCLES
	FrozenCycles      int   // FROZEN_CYCLES
	RecoverCycles     int   // RECOVER_CYCLES
}

// GuardReloader re-reads the conf on every Get — the mtime-check-
// free equivalent of watchdogconf.Reloader (the file is a few
// hundred bytes; a plain re-read is the simplest correct semantics).
// A missing file yields the zero GuardDefaults (no overlay), an
// unreadable one keeps the last good parse — the shell `source`
// semantics were "read fresh each run". Get is safe for concurrent
// use.
//
// The reload skeleton (mutex, keep-last-good, edge-latched warn +
// recovery info) is the shared platform/fileconf.Reloader —
// embedded so Path stays the exported, Get-time-read field. The
// guard flavour keeps its empty-Path early return (BlankPathHolds).
type GuardReloader struct {
	*fileconf.Reloader[GuardDefaults]
}

// NewGuardReloader seeds the reloader with an initial parse (the
// zero value is fine — the first Get re-reads anyway).
func NewGuardReloader(path string, initial GuardDefaults) *GuardReloader {
	return &GuardReloader{fileconf.New(path, parseGuardConf, initial,
		fileconf.Options{
			Log:            logger(),
			WarnMsg:        "apiprober: guard conf unreadable — keeping last good parse",
			RecoveredMsg:   "apiprober: guard conf readable again",
			BlankPathHolds: true,
		})}
}

// Get returns the freshest parse of Path, falling back to the last
// good one on read/parse errors. A persistent read failure warns
// once per episode (and logs recovery once) rather than every cycle —
// Get runs each probe cycle.
func (r *GuardReloader) Get() GuardDefaults { return r.Reloader.Get() }

// LoadGuardConf parses the conf at path. A missing file is NOT an
// error (pods and non-api-lb hosts never carry it) — it returns the
// zero GuardDefaults and nil so callers can chain env → conf →
// default unconditionally. The file contract is the shared
// fileconf.Load — identical to the reloader's per-Get read.
//
// Credential keys accept BOTH spellings: API_TOKEN_FILE/API_CA_FILE
// is the original contract (the ansible api-backend-guard.conf.j2
// template — deployed api-lb VMs still carry it and the retired
// shell guard sourced exactly these), TOKEN_FILE/CA_FILE the short
// spelling the Go port's first conf renders used. The API_-
// prefixed (original) spelling wins when both are present — it is
// the documented contract and the one converge manages.
func LoadGuardConf(path string) (GuardDefaults, error) {
	return fileconf.Load(path, parseGuardConf)
}

// parseGuardConf parses conf content — split from LoadGuardConf so
// the one-shot Load and the fileconf reloader share one parser;
// empty content (absent file) yields the zero GuardDefaults.
func parseGuardConf(data []byte) (GuardDefaults, error) {
	var g GuardDefaults
	vars := parseShellKV(string(data))
	g.SocketPath = vars["HAPROXY_SOCKET"]
	g.BackendName = vars["HAPROXY_BACKEND"]
	g.Mode = vars["MODE"]
	g.TokenFile = firstNonEmpty(vars["API_TOKEN_FILE"], vars["TOKEN_FILE"])
	g.CAFile = firstNonEmpty(vars["API_CA_FILE"], vars["CA_FILE"])
	g.GapMin, _ = strconv.ParseInt(vars["GAP_MIN"], 10, 64)
	g.FailCycles = atoiOr(vars["FAIL_CYCLES"])
	g.FrozenCycles = atoiOr(vars["FROZEN_CYCLES"])
	g.RecoverCycles = atoiOr(vars["RECOVER_CYCLES"])
	// HAPROXY_BACKENDS names the whole action set INCLUDING the
	// primary backend (shell parity: `for b in $HAPROXY_BACKENDS`) —
	// the primary already acts via BackendName, so only the rest are
	// companions (double-applying an enable/disable is a no-op but
	// logs and metrics would double-count it).
	for _, b := range strings.Fields(vars["HAPROXY_BACKENDS"]) {
		if b == "" || b == g.BackendName {
			continue
		}
		g.CompanionBackends = append(g.CompanionBackends, b)
	}
	for _, e := range strings.Fields(vars["API_BACKENDS"]) {
		if sb, ok := parseStaticBackend(e); ok {
			g.StaticBackends = append(g.StaticBackends, sb)
		}
	}
	return g, nil
}

// atoiOr parses a small integer conf value; empty/garbage → 0
// (fall through to the caller's default).
func atoiOr(v string) int {
	n, _ := strconv.Atoi(strings.TrimSpace(v))
	return n
}

// parseStaticBackend parses one API_BACKENDS element "name=ip:port"
// (or bare "ip:port" — Name falls back to Addr), 1:1 with
// watchdogconf's APIBackends entries.
func parseStaticBackend(entry string) (StaticBackend, bool) {
	name, addr, hasEq := strings.Cut(entry, "=")
	if !hasEq {
		entry = strings.TrimSpace(entry)
		if entry == "" {
			return StaticBackend{}, false
		}
		return StaticBackend{Name: entry, Addr: entry}, true
	}
	name, addr = strings.TrimSpace(name), strings.TrimSpace(addr)
	if name == "" || addr == "" {
		return StaticBackend{}, false
	}
	return StaticBackend{Name: name, Addr: addr}, true
}

// parseShellKV parses shell-style KEY=VALUE lines (the same grammar
// watchdogconf uses — quotes honoured, `#` comments, `export `
// prefixes tolerated). Duplicated here because watchdogconf's parser
// is package-private and the guard conf is an apiprober input.
func parseShellKV(data string) map[string]string {
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
		vars[key] = guardScalar(guardValue(strings.TrimSpace(val)))
	}
	return vars
}

// guardScalar strips surrounding single/double quotes.
func guardScalar(v string) string {
	if len(v) >= 2 {
		if (v[0] == '"' && v[len(v)-1] == '"') ||
			(v[0] == '\'' && v[len(v)-1] == '\'') {
			return v[1 : len(v)-1]
		}
	}
	return v
}

// guardValue cuts a raw VALUE at the first `#` that opens a bash
// comment — outside quotes and at a word boundary. A `#` inside
// quotes or glued to the previous word is literal (bash `source`
// parity — same semantics as watchdogconf's parser).
func guardValue(val string) string {
	var out strings.Builder
	out.Grow(len(val))
	var quote byte
	wordStart := true
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
