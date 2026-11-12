package jinja

import (
	"fmt"
	"strings"
)

// --- tokenizer ---

// tokKind is the token class — a uint8 (not a string) so the parser's
// per-token kind checks stay a single byte compare instead of a
// string header compare on every production.
type tokKind uint8

const (
	tokEOF tokKind = iota
	tokNum
	tokStr
	tokName
	tokOp
)

// String keeps tokKind printable in parse-error messages ("(%s)").
func (k tokKind) String() string {
	switch k {
	case tokNum:
		return "num"
	case tokStr:
		return "str"
	case tokName:
		return "name"
	case tokOp:
		return "op"
	}
	return "eof"
}

type tok struct {
	kind tokKind
	val  string
}

func lex(src string) ([]tok, error) {
	var out []tok
	i := 0
	for i < len(src) {
		c := src[i]
		switch {
		case c == ' ' || c == '\t' || c == '\n' || c == '\r':
			i++
		case c == '\'' || c == '"':
			j := i + 1
			hasEsc := false
			for j < len(src) && src[j] != c {
				if src[j] == '\\' && j+1 < len(src) {
					hasEsc = true
					j += 2
					continue
				}
				j++
			}
			if j >= len(src) {
				return nil, fmt.Errorf("unterminated string in %q", src)
			}
			var val string
			if !hasEsc {
				// No backslash inside the literal — the token can
				// point straight into src instead of paying a
				// Builder alloc + copy for the common case.
				val = src[i+1 : j]
			} else {
				var sb strings.Builder
				sb.Grow(j - i - 1)
				for k := i + 1; k < j; {
					if src[k] == '\\' && k+1 < j {
						switch src[k+1] {
						case 'n':
							sb.WriteByte('\n')
						case 'r':
							sb.WriteByte('\r')
						case 't':
							sb.WriteByte('\t')
						default:
							sb.WriteByte(src[k+1])
						}
						k += 2
						continue
					}
					sb.WriteByte(src[k])
					k++
				}
				val = sb.String()
			}
			out = append(out, tok{tokStr, val})
			i = j + 1
		case c >= '0' && c <= '9':
			j := i
			// x/X/o/O/b/B cover the 0x/0X/0o/0O/0b/0B literal
			// prefixes (the hex digits a-f/A-F and b/B itself are
			// already in range); '.' and e-notation digits ride
			// along for floats. A '+'/'-' rides along ONLY
			// directly after e/E — the exponent sign in
			// 1e-5/1e+5 — so "1e-5" stays one number while
			// "1+2" still lexes as num,op,num. The e/E check must
			// not fire inside a based literal: in 0x1e the 'e' is
			// a hex DIGIT, so "0x1e+1" is num,op,num — absorbing
			// the sign would mint the invalid literal "0x1e+1".
			based := i+1 < len(src) && src[i] == '0' &&
				(src[i+1] == 'x' || src[i+1] == 'X' ||
					src[i+1] == 'o' || src[i+1] == 'O' ||
					src[i+1] == 'b' || src[i+1] == 'B')
			for j < len(src) {
				cj := src[j]
				if cj == '+' || cj == '-' {
					if !based && j > i &&
						(src[j-1] == 'e' || src[j-1] == 'E') {
						j++
						continue
					}
					break
				}
				if cj >= '0' && cj <= '9' || cj == '.' ||
					cj == 'x' || cj == 'X' || cj == 'o' || cj == 'O' ||
					cj >= 'a' && cj <= 'f' || cj >= 'A' && cj <= 'F' {
					j++
					continue
				}
				break
			}
			out = append(out, tok{tokNum, src[i:j]})
			i = j
		case isNameChar(c):
			j := i
			for j < len(src) && isNameChar(src[j]) {
				j++
			}
			out = append(out, tok{tokName, src[i:j]})
			i = j
		default:
			matched := false
			for _, op := range []string{"==", "!=", "<=", ">=", "//", "**", "~"} {
				if strings.HasPrefix(src[i:], op) {
					out = append(out, tok{tokOp, op})
					i += len(op)
					matched = true
					break
				}
			}
			if !matched {
				if strings.ContainsRune("()[]{},.:+-*/%|<>=!", rune(c)) {
					out = append(out, tok{tokOp, string(c)})
					i++
				} else {
					return nil, fmt.Errorf("lex: unexpected %q in %q", string(c), src)
				}
			}
		}
	}
	out = append(out, tok{tokEOF, ""})
	return out, nil
}
