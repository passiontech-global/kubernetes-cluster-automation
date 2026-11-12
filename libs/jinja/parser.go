package jinja

import (
	"errors"
	"fmt"
	"strings"
)

// ---------------- template parsing ----------------

type frame struct {
	kind string // "for" | "if"
	n    tnode
}

// parseTemplate tokenises {{ }} {% %} {# #} and builds the node tree.
func parseTemplate(text string) ([]tnode, error) {
	var containers []*[]tnode
	var frames []frame
	nodes := []tnode{}
	containers = append(containers, &nodes)
	cur := func() *[]tnode { return containers[len(containers)-1] }
	pushFrame := func(f frame, c *[]tnode) {
		frames = append(frames, f)
		containers = append(containers, c)
	}
	pop := func(kind string) error {
		if len(frames) == 0 || frames[len(frames)-1].kind != kind {
			return fmt.Errorf("end%s without open %s block", kind, kind)
		}
		frames = frames[:len(frames)-1]
		containers = containers[:len(containers)-1]
		return nil
	}

	i := 0
	for i < len(text) {
		j := len(text)
		tag := ""
		for _, t := range []string{"{{", "{%", "{#"} {
			if k := strings.Index(text[i:], t); k >= 0 && i+k < j {
				j = i + k
				tag = t
			}
		}
		end := ""
		switch tag {
		case "{{":
			end = "}}"
		case "{%":
			end = "%}"
		case "{#":
			end = "#}"
		}
		if j == len(text) {
			*cur() = append(*cur(), textNode(text[i:]))
			break
		}
		// text[j:j+3] would panic on a bare 2-char opener at EOF
		// ("...{{") — HasPrefix on the remainder is bounds-safe.
		stripL := strings.HasPrefix(text[j:], tag+"-")
		chunk := text[i:j]
		if stripL {
			chunk = strings.TrimRight(chunk, " \t\n\r")
		}
		if chunk != "" {
			*cur() = append(*cur(), textNode(chunk))
		}
		openLen := 2
		if stripL {
			openLen = 3
		}
		rest := text[j+openLen:]
		var closeIdx int
		if tag == "{#" {
			// Comments are opaque text — no string literals to honor.
			closeIdx = strings.Index(rest, end)
		} else {
			// A "}}"/"%}" inside a 'quoted' literal is text, not the
			// tag close ({{ 'a}}b' }}) — naive Index would cut early.
			closeIdx = tagEnd(rest, end)
		}
		if closeIdx < 0 {
			return nil, fmt.Errorf("unclosed %s tag", tag)
		}
		body := rest[:closeIdx]
		i = j + openLen + closeIdx + len(end)
		if strings.HasSuffix(body, "-") {
			body = body[:len(body)-1]
			// skip following whitespace
			for i < len(text) && (text[i] == ' ' || text[i] == '\t' || text[i] == '\n' || text[i] == '\r') {
				i++
			}
		}
		if tag == "{#" {
			continue
		}
		if tag == "{{" {
			e, err := parseExpr(body)
			if err != nil {
				return nil, err
			}
			*cur() = append(*cur(), exprNode{e})
			continue
		}
		stmt := strings.TrimSpace(body)
		fields := strings.Fields(stmt)
		kw := ""
		if len(fields) > 0 {
			kw = fields[0]
		}
		switch kw {
		case "set":
			restStmt := strings.TrimSpace(strings.TrimPrefix(stmt, "set"))
			eq := setAssignIndex(restStmt)
			if eq < 0 {
				return nil, fmt.Errorf("set: missing = in %q", stmt)
			}
			name := strings.TrimSpace(restStmt[:eq])
			// A {% set %} target must be a plain identifier — a
			// mangled name ("x !" off a `x != y` typo) or a dotted
			// path (namespace() is unsupported) must error now,
			// not bind garbage at render time.
			if !isIdentifier(name) {
				return nil, fmt.Errorf("set: invalid variable name %q", name)
			}
			e, err := parseExpr(restStmt[eq+1:])
			if err != nil {
				return nil, err
			}
			*cur() = append(*cur(), setNode{name: name, e: e})
		case "for":
			fn, err := parseFor(stmt)
			if err != nil {
				return nil, err
			}
			*cur() = append(*cur(), fn)
			pushFrame(frame{"for", fn}, &fn.body)
		case "endfor":
			if err := pop("for"); err != nil {
				return nil, err
			}
		case "if":
			e, err := parseExpr(strings.TrimSpace(strings.TrimPrefix(stmt, "if")))
			if err != nil {
				return nil, err
			}
			in := &ifNode{arms: []ifArm{{cond: e}}}
			*cur() = append(*cur(), in)
			pushFrame(frame{"if", in}, &in.arms[0].body)
		case "elif", "else":
			if len(frames) == 0 || frames[len(frames)-1].kind != "if" {
				return nil, fmt.Errorf("%s without if", kw)
			}
			in, ok := frames[len(frames)-1].n.(*ifNode)
			if !ok {
				return nil, fmt.Errorf("%s: frame is %T, not *ifNode", kw, frames[len(frames)-1].n)
			}
			// {% else %} is a bare keyword — "{% else if x %}" is
			// an {% elif %} missing its first two letters, and
			// silently treating it as else would DROP the
			// condition.
			if kw == "else" {
				if restArgs := strings.TrimSpace(strings.TrimPrefix(stmt, "else")); restArgs != "" {
					return nil, fmt.Errorf("{%% else %%} takes no arguments, got %q", restArgs)
				}
			}
			// The else arm is the nil-cond arm; anything after it
			// ({% else %} again, {% elif %}) is unreachable and
			// almost never what the template meant.
			if last := in.arms[len(in.arms)-1]; last.cond == nil {
				return nil, fmt.Errorf("{%% %s %%} after {%% else %%}", kw)
			}
			containers = containers[:len(containers)-1] // pop previous arm body
			if kw == "elif" {
				e, err := parseExpr(strings.TrimSpace(strings.TrimPrefix(stmt, "elif")))
				if err != nil {
					return nil, err
				}
				in.arms = append(in.arms, ifArm{cond: e})
			} else {
				in.arms = append(in.arms, ifArm{})
			}
			containers = append(containers, &in.arms[len(in.arms)-1].body)
		case "endif":
			if len(frames) == 0 || frames[len(frames)-1].kind != "if" {
				return nil, errors.New("endif without if")
			}
			frames = frames[:len(frames)-1]
			containers = containers[:len(containers)-1]
		default:
			return nil, fmt.Errorf("unsupported tag %q", stmt)
		}
	}
	// Any frame left open means a block was never closed — the
	// render would silently truncate at the missing {% endif %}/
	// {% endfor %} (or silently drop the rest of the template).
	// Report the INNERMOST open block: that's where the tag is
	// missing.
	if len(frames) > 0 {
		f := frames[len(frames)-1]
		return nil, fmt.Errorf("missing {%% end%s %%} for {%% %s %%} block", f.kind, f.kind)
	}
	return nodes, nil
}

// tagEnd finds the offset of the closing delimiter in rest, skipping
// over 'single' and "double" quoted literals (with backslash escapes)
// so a "}}"/"%}" inside a string isn't misread as the tag close.
func tagEnd(rest, end string) int {
	for i := 0; i+len(end) <= len(rest); i++ {
		if c := rest[i]; c == '\'' || c == '"' {
			i++
			for i < len(rest) && rest[i] != c {
				if rest[i] == '\\' {
					i++
				}
				i++
			}
			// i now sits on the close quote (or len — loop ends).
			continue
		}
		if strings.HasPrefix(rest[i:], end) {
			return i
		}
	}
	return -1
}

// parseFor parses `{% for a[,b] in seq [if cond [if cond2 ...]] %}`.
// The `in` separator and the `if` filter markers are only honoured at
// bracket-depth 0 outside string literals — a naive lastIndexOf("in")
// splits inside the filter's own `x in y` test and yields a garbage
// loop variable (silent misparse, haproxy.cfg incident class).
func parseFor(stmt string) (*forNode, error) {
	restStmt := strings.TrimSpace(strings.TrimPrefix(stmt, "for"))
	inIdxs := topLevelWords(restStmt, "in")
	if len(inIdxs) == 0 {
		return nil, fmt.Errorf("for: missing 'in' in %q", stmt)
	}
	inIdx := inIdxs[0]
	var names []string
	for _, nm := range strings.Split(restStmt[:inIdx], ",") {
		nm = strings.TrimSpace(nm)
		// A garbage loop name (`x y` from a missing comma) binds at
		// render time and reads back as Undefined — body `{{ x }}`
		// then renders empty into a converged config file. The
		// {% set %} target carries the same isIdentifier gate; the
		// for targets must not be looser than set.
		if !isIdentifier(nm) {
			return nil, fmt.Errorf("for: invalid loop variable %q", nm)
		}
		names = append(names, nm)
	}
	rest := restStmt[inIdx+2:]
	// Sequence expr runs up to the first top-level `if`; every further
	// top-level `if` starts another filter condition.
	ifIdxs := topLevelWords(rest, "if")
	iterSrc := rest
	var condSrcs []string
	if len(ifIdxs) > 0 {
		iterSrc = rest[:ifIdxs[0]]
		for i, ix := range ifIdxs {
			end := len(rest)
			if i+1 < len(ifIdxs) {
				end = ifIdxs[i+1]
			}
			condSrcs = append(condSrcs, rest[ix+2:end])
		}
	}
	e, err := parseExpr(iterSrc)
	if err != nil {
		return nil, fmt.Errorf("for: %w", err)
	}
	fn := &forNode{names: names, list: e}
	for _, cs := range condSrcs {
		ce, err := parseExpr(cs)
		if err != nil {
			return nil, fmt.Errorf("for: filter %q: %w", strings.TrimSpace(cs), err)
		}
		fn.conds = append(fn.conds, ce)
	}
	return fn, nil
}

// topLevelWords returns offsets of word w in s where it appears at
// bracket-depth 0, outside 'single'/"double" quotes, bounded by
// non-name characters. A '.' immediately before the word disqualifies
// it too: `box.in` / `x.if` are ATTRIBUTE reads, not the loop's `in`
// separator or `if` filter marker — treating the attribute name as a
// keyword split the head into garbage ("box." + "" conds) instead of
// leaving the postfix chain to the expression parser.
func topLevelWords(s, w string) []int {
	var idxs []int
	depth := 0
	for off := 0; off < len(s); off++ {
		c := s[off]
		switch c {
		case '\'', '"':
			j := off + 1
			for j < len(s) && s[j] != c {
				if s[j] == '\\' {
					j++
				}
				j++
			}
			off = j
		case '(', '[', '{':
			depth++
		case ')', ']', '}':
			depth--
		default:
			if depth == 0 && off+len(w) <= len(s) && s[off:off+len(w)] == w {
				before := off == 0 || (s[off-1] != '.' && !isNameChar(s[off-1]))
				after := off+len(w) == len(s) || !isNameChar(s[off+len(w)])
				if before && after {
					idxs = append(idxs, off)
					off += len(w) - 1
				}
			}
		}
	}
	return idxs
}

func isNameChar(c byte) bool {
	return c == '_' || c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9'
}

// setAssignIndex finds the '=' separating a {% set %} variable from
// its value — and ONLY that '=': the sign inside !=/<=/>=/== must
// not split ("set ok = a != b" cut at the comparison's '=' turned
// the target into "ok " but left "= a ! b" garbage on both sides
// of a `set x != y` typo).
func setAssignIndex(s string) int {
	for i := range len(s) {
		if s[i] != '=' {
			continue
		}
		if i > 0 && (s[i-1] == '!' || s[i-1] == '<' || s[i-1] == '>' || s[i-1] == '=') {
			continue // tail of != <= >= or second half of ==
		}
		if i+1 < len(s) && s[i+1] == '=' {
			continue // head of ==
		}
		return i
	}
	return -1
}

// isIdentifier reports whether s is a plain [A-Za-z_][A-Za-z0-9_]*
// name — the only {% set %} target shape (dotted namespace names
// are unsupported).
func isIdentifier(s string) bool {
	if s == "" {
		return false
	}
	if c := s[0]; !isNameChar(c) || c >= '0' && c <= '9' {
		return false
	}
	for i := 1; i < len(s); i++ {
		if !isNameChar(s[i]) {
			return false
		}
	}
	return true
}
