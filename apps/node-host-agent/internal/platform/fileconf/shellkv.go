// shellkv.go — the shared shell-style KEY=VALUE line parser behind
// watchdogconf (/etc/node-watchdog.conf) and apiprober's guard conf
// (/etc/api-backend-guard.conf). Both files are bash-`source`d
// configs, so the grammar is bash parity, not INI:
//
//   - `#` comments (whole-line and inline), blank lines, `export `
//     prefixes.
//   - single/double-quoted values; unquoted values keep inner spaces
//     (a list is just words).
//   - a `#` ends an unquoted value only at a word boundary — inside
//     quotes or glued to the previous word it is literal.
//
// Quote characters are consumed as they open/close — bash quote
// removal happens per word, so KEY="a"#tail yields `a#tail` (the
// mid-word '#' stays literal) rather than the raw `"a"#tail` a
// whole-value quote-strip could never see.
package fileconf

import "strings"

// ParseShellKV parses shell-style KEY=VALUE lines into a map. An
// inline `#` comment ends an unquoted value (bash parity); a `#`
// inside quotes is literal.
func ParseShellKV(data string) map[string]string {
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
			if ch == quote {
				quote = 0
				continue // closing quote consumed
			}
			out.WriteByte(ch)
			continue
		}
		switch ch {
		case '"', '\'':
			quote = ch
			wordStart = false
			// opening quote consumed — content follows
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
