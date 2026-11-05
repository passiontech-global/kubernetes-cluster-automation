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
			for j < len(src) && (src[j] >= '0' && src[j] <= '9' || src[j] == '.' || src[j] == 'x' || src[j] >= 'a' && src[j] <= 'f' || src[j] >= 'A' && src[j] <= 'F') {
				j++
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
