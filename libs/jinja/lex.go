package jinja

import (
	"fmt"
	"strings"
)

// --- tokenizer ---

type tok struct {
	kind string // num str name op eof
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
			var sb strings.Builder
			for j < len(src) && src[j] != c {
				if src[j] == '\\' && j+1 < len(src) {
					switch src[j+1] {
					case 'n':
						sb.WriteByte('\n')
					case 'r':
						sb.WriteByte('\r')
					case 't':
						sb.WriteByte('\t')
					default:
						sb.WriteByte(src[j+1])
					}
					j += 2
					continue
				}
				sb.WriteByte(src[j])
				j++
			}
			if j >= len(src) {
				return nil, fmt.Errorf("unterminated string in %q", src)
			}
			out = append(out, tok{"str", sb.String()})
			i = j + 1
		case c >= '0' && c <= '9':
			j := i
			// x/X/o/O cover the 0x/0X/0o/0O literal prefixes (b/B and
			// the hex digits a-f/A-F are already in range); '.' and
			// e-notation digits ride along for floats. A '+'/'-'
			// rides along ONLY directly after e/E — the exponent
			// sign in 1e-5/1e+5 — so "1e-5" stays one number while
			// "1+2" still lexes as num,op,num. The e/E check must
			// not fire inside a based literal: in 0x1e the 'e' is a
			// hex DIGIT, so "0x1e+1" is num,op,num — absorbing the
			// sign would mint the invalid literal "0x1e+1".
			based := i+1 < len(src) && src[i] == '0' &&
				(src[i+1] == 'x' || src[i+1] == 'X' ||
					src[i+1] == 'o' || src[i+1] == 'O')
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
			out = append(out, tok{"num", src[i:j]})
			i = j
		case isNameChar(c):
			j := i
			for j < len(src) && isNameChar(src[j]) {
				j++
			}
			out = append(out, tok{"name", src[i:j]})
			i = j
		default:
			matched := false
			for _, op := range []string{"==", "!=", "<=", ">=", "//", "**", "~"} {
				if strings.HasPrefix(src[i:], op) {
					out = append(out, tok{"op", op})
					i += len(op)
					matched = true
					break
				}
			}
			if !matched {
				if strings.ContainsRune("()[]{},.:+-*/%|<>=!", rune(c)) {
					out = append(out, tok{"op", string(c)})
					i++
				} else {
					return nil, fmt.Errorf("lex: unexpected %q in %q", string(c), src)
				}
			}
		}
	}
	out = append(out, tok{"eof", ""})
	return out, nil
}
