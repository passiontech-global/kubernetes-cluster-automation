// util.go — the small parse/quote/state-file helpers shared by two
// or more domain packages: psql -tA row parsers, .env value
// extraction, SQL identifier/literal quoting, the last-*/counter
// int-file IO and the NA/dash formatters the cycle logs share.
package kdeps

import (
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"

	"github.com/passiontech-global/kubernetes-cluster-automation/libs/hostkit/fsx"
)

// FirstLine returns the first non-blank trimmed line of psql -tA
// output ("" when there is none).
func FirstLine(out string) string {
	for l := range strings.SplitSeq(out, "\n") {
		if strings.TrimSpace(l) != "" {
			return strings.TrimSpace(l)
		}
	}
	return ""
}

// ParsePair parses a `a|b` psql -tA row into two int64s.
func ParsePair(out string) (a, b int64, err error) {
	f := strings.Split(FirstLine(out), "|")
	if len(f) < 2 {
		return 0, 0, fmt.Errorf("expected 2 fields, got %q", FirstLine(out))
	}
	if a, err = strconv.ParseInt(strings.TrimSpace(f[0]), 10, 64); err != nil {
		return 0, 0, err
	}
	if b, err = strconv.ParseInt(strings.TrimSpace(f[1]), 10, 64); err != nil {
		return 0, 0, err
	}
	return a, b, nil
}

// ParseTriple parses a `a|b|c` psql -tA row into three int64s.
func ParseTriple(out string) (a, b, c int64, err error) {
	f := strings.Split(FirstLine(out), "|")
	if len(f) < 3 {
		return 0, 0, 0, fmt.Errorf("expected 3 fields, got %q", FirstLine(out))
	}
	if a, err = strconv.ParseInt(strings.TrimSpace(f[0]), 10, 64); err != nil {
		return 0, 0, 0, err
	}
	if b, err = strconv.ParseInt(strings.TrimSpace(f[1]), 10, 64); err != nil {
		return 0, 0, 0, err
	}
	if c, err = strconv.ParseInt(strings.TrimSpace(f[2]), 10, 64); err != nil {
		return 0, 0, 0, err
	}
	return a, b, c, nil
}

// ParseQuad parses a `a|b|c|d` psql -tA row into four int64s.
func ParseQuad(out string) (a, b, c, d int64, err error) {
	f := strings.Split(FirstLine(out), "|")
	if len(f) < 4 {
		return 0, 0, 0, 0, fmt.Errorf("expected 4 fields, got %q", FirstLine(out))
	}
	vals := []*int64{&a, &b, &c, &d}
	for i := range vals {
		if *vals[i], err = strconv.ParseInt(strings.TrimSpace(f[i]), 10, 64); err != nil {
			return 0, 0, 0, 0, err
		}
	}
	return a, b, c, d, nil
}

// EnvValue extracts KEY=value from .env content the way dotenv does:
// an optional `export ` prefix, a value that may be wrapped in one
// quote pair (only the wrapping pair is stripped — inner quotes,
// spaces and '#' stay literal), and a trailing ` # comment` on bare
// values. The bash `tr -d "\"' "` deleted every quote and space
// INSIDE the value too, silently corrupting credentials that
// legitimately contain them.
func EnvValue(data, key string) string {
	prefix := key + "="
	for l := range strings.SplitSeq(data, "\n") {
		l = strings.TrimSpace(l)
		l = strings.TrimPrefix(l, "export ")
		if !strings.HasPrefix(l, prefix) {
			continue
		}
		v := strings.TrimSpace(strings.TrimPrefix(l, prefix))
		if v == "" {
			return ""
		}
		if v[0] == '"' || v[0] == '\'' {
			// Quoted value: content runs to the matching closer;
			// anything after it (a trailing comment) is dropped.
			if end := strings.LastIndexByte(v[1:], v[0]); end >= 0 {
				return v[1 : 1+end]
			}
			// Unmatched opener: the bash `tr -d "\"' "` stripped
			// the leading quote too — drop it for parity rather
			// than smuggling it into the credential.
			return v[1:]
		}
		// Bare value: ` #` opens a comment.
		if i := strings.Index(v, " #"); i >= 0 {
			v = v[:i]
		}
		return strings.TrimSpace(v)
	}
	return ""
}

// SQLQuote wraps s as a single-quoted SQL literal — slot names come
// back from the server rather than user input, but a stray quote in
// the name must still not break the DROP statement.
func SQLQuote(s string) string {
	return "'" + strings.ReplaceAll(s, "'", "''") + "'"
}

// SQLIdent wraps s as a double-quoted SQL identifier — cfg.Table is
// validated as a plain identifier by ApplyDefaults, but it lands in
// DDL positions (VACUUM/REINDEX/FROM/UPDATE) where SQLQuote's string
// literal would be wrong; quoting keeps the interpolation safe even
// if a name ever bypasses the config check.
func SQLIdent(s string) string {
	return `"` + strings.ReplaceAll(s, `"`, `""`) + `"`
}

// IntOrNA renders an int64 gauge value or "NA" when its read did
// not land this cycle — the cycle-summary formatter.
func IntOrNA(ok bool, v int64) string {
	if !ok {
		return "NA"
	}
	return strconv.FormatInt(v, 10)
}

// ReasonOrDash renders an unset trigger/state string as "-" — the
// cycle-summary formatter.
func ReasonOrDash(s string) string {
	if s == "" {
		return "-"
	}
	return s
}

// ParseGIDs splits a one-identifier-per-line -tA result — the
// prepared-xacts gid list and the invalid-index regclass list share
// it; empty/blank lines are skipped.
func ParseGIDs(out string) []string {
	var gids []string
	for l := range strings.SplitSeq(out, "\n") {
		l = strings.TrimSpace(l)
		if l == "" {
			continue
		}
		gids = append(gids, l)
	}
	return gids
}

// ReadIntFile reads a file holding a single integer — the
// GuardStateDir last-*/streak-file contract.
func ReadIntFile(path string) (int64, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return 0, err
	}
	return strconv.ParseInt(strings.TrimSpace(string(data)), 10, 64)
}

// WriteIntFile writes v + "\n" to path atomically, creating the
// parent dir first.
func WriteIntFile(path string, v int64) {
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		logger().Warn("kinedb state file write failed", "file", path, "error", err)
		return
	}
	// hostutil's random-suffix tmp + fsync + rename — probe and
	// guard loops can reach the same file from different goroutines,
	// so a fixed .tmp-<name> staging path could clobber mid-write.
	if err := fsx.WriteFileAtomicBytes(path,
		[]byte(strconv.FormatInt(v, 10)+"\n")); err != nil {
		logger().Warn("kinedb state file write failed", "file", path, "error", err)
	}
}
