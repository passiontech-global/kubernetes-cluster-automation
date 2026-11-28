// filters_regex.go — regex_escape, regex_replace, regex_findall,
// regex_search, and their bounded/fast-path match machinery.
package jinja

import (
	"fmt"
	"regexp"
	"regexp/syntax"
	"strings"
	"unicode/utf8"
)

func filterRegexEscape(v any) (any, error) {
	s := Stringify(v)
	if err := outputSizeCap(len(s), "regex_escape"); err != nil {
		return nil, err
	}
	if len(s) > maxStringBytes/2 {
		extra := 0
		for i := 0; i < len(s); i++ {
			switch s[i] {
			case '\\', '.', '+', '*', '?', '(', ')', '|', '[', ']', '{', '}', '^', '$':
				extra++
			}
		}
		if err := outputSizeCap(len(s)+extra, "regex_escape"); err != nil {
			return nil, err
		}
	}
	out := regexp.QuoteMeta(s)
	if err := outputSizeCap(len(out), "regex_escape"); err != nil {
		return nil, err
	}
	return out, nil
}

func filterRegexReplace(v any, args []any) (any, error) {
	if len(args) < 2 {
		return v, nil
	}
	entry, err := cachedRegexpEntry(Stringify(args[0]))
	if err != nil {
		return nil, err
	}
	s := Stringify(v)
	repl := Stringify(args[1])
	if len(s) > maxStringBytes {
		return nil, fmt.Errorf("regex_replace: input exceeds %d bytes", maxStringBytes)
	}
	return regexReplaceBounded(entry, s, repl)
}

func filterRegexFindall(v any, args []any) (any, error) {
	if len(args) == 0 {
		return &List{}, nil
	}
	entry, err := cachedRegexpEntry(Stringify(args[0]))
	if err != nil {
		return nil, err
	}
	return regexFindallBounded(entry, Stringify(v))
}

func filterRegexSearch(v any, args []any) (any, error) {
	if len(args) == 0 {
		return Undefined{"regex_search"}, nil
	}
	re, err := cachedRegexp(Stringify(args[0]))
	if err != nil {
		return nil, err
	}
	m := re.FindStringSubmatch(Stringify(v))
	if len(m) > 1 {
		out := make([]any, 0, len(m)-1)
		for _, g := range m[1:] {
			out = append(out, g)
		}
		return &List{out}, nil
	}
	if m != nil {
		return m[0], nil
	}
	return Undefined{"regex_search"}, nil
}

const (
	regexLeftFree  = 0 // no ^ / \A / (?m)^ / \b / \B anywhere: safe for incremental s[pos:]
	regexLeftBegin = 1 // must start at text begin (pos == 0): at most one match via FindStringSubmatchIndex(s)
	regexLeftFull  = 2 // general left-context assertion ((?m)^, \b, \B, a|^b): bounded FindAll
)

func hasLeftAnchor(r *syntax.Regexp) bool {
	switch r.Op {
	case syntax.OpBeginText, syntax.OpBeginLine, syntax.OpWordBoundary, syntax.OpNoWordBoundary:
		return true
	}
	for _, sub := range r.Sub {
		if hasLeftAnchor(sub) {
			return true
		}
	}
	return false
}

func mustStartAtTextBegin(r *syntax.Regexp) bool {
	switch r.Op {
	case syntax.OpBeginText:
		return true
	case syntax.OpCapture, syntax.OpPlus:
		return len(r.Sub) > 0 && mustStartAtTextBegin(r.Sub[0])
	case syntax.OpRepeat:
		return r.Min >= 1 && len(r.Sub) > 0 && mustStartAtTextBegin(r.Sub[0])
	case syntax.OpConcat:
		return len(r.Sub) > 0 && mustStartAtTextBegin(r.Sub[0])
	case syntax.OpAlternate:
		if len(r.Sub) == 0 {
			return false
		}
		for _, sub := range r.Sub {
			if !mustStartAtTextBegin(sub) {
				return false
			}
		}
		return true
	}
	return false
}

func classifyRegexReplace(pat string, hasExpand bool) (mode int, lit string, isLit, isEmpty, isLinePrefix bool) {
	if !hasExpand && !strings.ContainsAny(pat, `^$\.*+?()[]{}|`) {
		if !strings.ContainsRune(pat, utf8.RuneError) && pat != "" {
			return regexLeftFree, pat, true, false, false
		}
	}
	ast, err := syntax.Parse(pat, syntax.Perl)
	if err != nil {
		return regexLeftFull, "", false, false, false
	}
	if ast.Op == syntax.OpEmptyMatch {
		return regexLeftFree, "", false, true, false
	}
	if !hasExpand {
		litNode := ast
		if litNode.Op == syntax.OpCapture && len(litNode.Sub) == 1 {
			litNode = litNode.Sub[0]
		}
		if litNode.Op == syntax.OpLiteral && (litNode.Flags&syntax.FoldCase) == 0 && len(litNode.Rune) > 0 {
			s := string(litNode.Rune)
			if !strings.ContainsRune(s, utf8.RuneError) {
				return regexLeftFree, s, true, false, false
			}
		}
		if ast.Op == syntax.OpConcat && len(ast.Sub) == 2 && ast.Sub[0].Op == syntax.OpBeginLine {
			sub := ast.Sub[1]
			if sub.Op == syntax.OpCapture && len(sub.Sub) == 1 {
				sub = sub.Sub[0]
			}
			if sub.Op == syntax.OpLiteral && (sub.Flags&syntax.FoldCase) == 0 && len(sub.Rune) > 0 {
				s := string(sub.Rune)
				if !strings.ContainsRune(s, utf8.RuneError) && !strings.ContainsRune(s, '\n') {
					return regexLeftFull, s, false, false, true
				}
			}
		}
	}
	if !hasLeftAnchor(ast) {
		return regexLeftFree, "", false, false, false
	}
	if mustStartAtTextBegin(ast) {
		return regexLeftBegin, "", false, false, false
	}
	return regexLeftFull, "", false, false, false
}

func singleLiteralCapture(pat string) (string, bool) {
	ast, err := syntax.Parse(pat, syntax.Perl)
	if err != nil || ast.Op != syntax.OpCapture || len(ast.Sub) != 1 {
		return "", false
	}
	sub := ast.Sub[0]
	if sub.Op != syntax.OpLiteral || (sub.Flags&syntax.FoldCase) != 0 || len(sub.Rune) == 0 {
		return "", false
	}
	s := string(sub.Rune)
	if strings.ContainsRune(s, utf8.RuneError) {
		return "", false
	}
	return s, true
}

func replaceLiteralBounded(s, lit, repl string) (string, error) {
	n := strings.Count(s, lit)
	if n == 0 {
		return s, nil
	}
	diff := len(repl) - len(lit)
	if diff > 0 {
		if n > (maxStringBytes-len(s))/diff {
			return "", fmt.Errorf("regex_replace: output exceeds %d bytes", maxStringBytes)
		}
	} else if len(s)+n*diff > maxStringBytes {
		return "", fmt.Errorf("regex_replace: output exceeds %d bytes", maxStringBytes)
	}
	return strings.ReplaceAll(s, lit, repl), nil
}

func replaceEmptyBounded(s, repl string) (string, error) {
	nMatches := utf8.RuneCountInString(s) + 1
	if nMatches > maxSeqElems {
		return "", fmt.Errorf("regex_replace: match count exceeds %d", maxSeqElems)
	}
	if len(repl) > 0 && nMatches > (maxStringBytes-len(s))/len(repl) {
		return "", fmt.Errorf("regex_replace: output exceeds %d bytes", maxStringBytes)
	}
	var b strings.Builder
	b.Grow(len(s) + nMatches*len(repl))
	for i := 0; i < len(s); {
		b.WriteString(repl)
		_, w := utf8.DecodeRuneInString(s[i:])
		if w <= 0 {
			w = 1
		}
		b.WriteString(s[i : i+w])
		i += w
	}
	b.WriteString(repl)
	return b.String(), nil
}

func replaceLinePrefixLiteralBounded(s, lit, repl string) (string, error) {
	var b strings.Builder
	last := 0
	pos := 0
	matches := 0
	for pos <= len(s) {
		if strings.HasPrefix(s[pos:], lit) {
			matches++
			if matches > maxSeqElems {
				return "", fmt.Errorf("regex_replace: match count exceeds %d", maxSeqElems)
			}
			if b.Len()+(pos-last)+len(repl) > maxStringBytes {
				return "", fmt.Errorf("regex_replace: output exceeds %d bytes", maxStringBytes)
			}
			if matches == 1 {
				b.Grow(min(len(s)+64, maxStringBytes))
			}
			b.WriteString(s[last:pos])
			b.WriteString(repl)
			last = pos + len(lit)
			pos = last
		}
		nl := strings.IndexByte(s[pos:], '\n')
		if nl < 0 {
			break
		}
		pos += nl + 1
	}
	if matches == 0 {
		return s, nil
	}
	if b.Len()+(len(s)-last) > maxStringBytes {
		return "", fmt.Errorf("regex_replace: output exceeds %d bytes", maxStringBytes)
	}
	b.WriteString(s[last:])
	return b.String(), nil
}

// regexReplaceBounded replaces matches incrementally without materializing an
// unbounded [][]int match slice, enforcing maxStringBytes before writes.
func regexReplaceBounded(entry *regexEntry, s, repl string) (string, error) {
	re := entry.re
	hasExpand := strings.ContainsRune(repl, '$')
	cls := entry.noExpand
	if hasExpand {
		cls = entry.withExpand
	}
	mode, lit, isLit, isEmpty, isLinePrefix := cls.mode, cls.lit, cls.isLit, cls.isEmpty, cls.isLinePrefix
	if isLit {
		return replaceLiteralBounded(s, lit, repl)
	}
	if isEmpty && !hasExpand {
		return replaceEmptyBounded(s, repl)
	}
	if isLinePrefix {
		return replaceLinePrefixLiteralBounded(s, lit, repl)
	}

	const batchSize = 4096
	var b strings.Builder
	last := 0
	var exp []byte
	totalMatches := 0

	switch mode {
	case regexLeftFree:
		b.Grow(min(len(s)+64, 64<<10))
		pos := 0
		prevMatchEnd := -1
		for pos <= len(s) {
			var batch [][]int
			if hasExpand {
				batch = re.FindAllStringSubmatchIndex(s[pos:], batchSize)
			} else {
				batch = re.FindAllStringIndex(s[pos:], batchSize)
			}
			if len(batch) == 0 {
				break
			}
			startPos := pos
			for i, m := range batch {
				for k := range m {
					if m[k] >= 0 {
						m[k] += startPos
					}
				}
				if i == 0 && m[1] == startPos && m[0] == prevMatchEnd {
					continue
				}
				totalMatches++
				if totalMatches > maxSeqElems {
					return "", fmt.Errorf("regex_replace: match count exceeds %d", maxSeqElems)
				}
				if b.Len()+(m[0]-last) > maxStringBytes {
					return "", fmt.Errorf("regex_replace: output exceeds %d bytes", maxStringBytes)
				}
				b.WriteString(s[last:m[0]])
				if !hasExpand {
					if b.Len()+len(repl) > maxStringBytes {
						return "", fmt.Errorf("regex_replace: output exceeds %d bytes", maxStringBytes)
					}
					b.WriteString(repl)
				} else {
					exp = re.ExpandString(exp[:0], repl, s, m)
					if b.Len()+len(exp) > maxStringBytes {
						return "", fmt.Errorf("regex_replace: output exceeds %d bytes", maxStringBytes)
					}
					b.Write(exp)
				}
				last = m[1]
			}
			if len(batch) < batchSize {
				break
			}
			lastM := batch[len(batch)-1]
			prevMatchEnd = lastM[1]
			if lastM[0] == lastM[1] {
				if lastM[1] == len(s) {
					pos = len(s) + 1
				} else {
					_, w := utf8.DecodeRuneInString(s[lastM[1]:])
					if w <= 0 {
						w = 1
					}
					pos = lastM[1] + w
				}
			} else {
				pos = lastM[1]
			}
		}
	case regexLeftBegin:
		b.Grow(min(len(s)+64, maxStringBytes))
		var m []int
		if hasExpand {
			m = re.FindStringSubmatchIndex(s)
		} else {
			m = re.FindStringIndex(s)
		}
		if m != nil {
			if b.Len()+(m[0]-last) > maxStringBytes {
				return "", fmt.Errorf("regex_replace: output exceeds %d bytes", maxStringBytes)
			}
			b.WriteString(s[last:m[0]])
			if !hasExpand {
				if b.Len()+len(repl) > maxStringBytes {
					return "", fmt.Errorf("regex_replace: output exceeds %d bytes", maxStringBytes)
				}
				b.WriteString(repl)
			} else {
				exp = re.ExpandString(exp[:0], repl, s, m)
				if b.Len()+len(exp) > maxStringBytes {
					return "", fmt.Errorf("regex_replace: output exceeds %d bytes", maxStringBytes)
				}
				b.Write(exp)
			}
			last = m[1]
		}
	default:
		var matches [][]int
		if hasExpand {
			matches = re.FindAllStringSubmatchIndex(s, maxSeqElems+1)
		} else {
			matches = re.FindAllStringIndex(s, maxSeqElems+1)
		}
		if len(matches) > maxSeqElems {
			return "", fmt.Errorf("regex_replace: match count exceeds %d", maxSeqElems)
		}
		b.Grow(min(len(s)+64, maxStringBytes))
		for _, m := range matches {
			if b.Len()+(m[0]-last) > maxStringBytes {
				return "", fmt.Errorf("regex_replace: output exceeds %d bytes", maxStringBytes)
			}
			b.WriteString(s[last:m[0]])
			if !hasExpand {
				if b.Len()+len(repl) > maxStringBytes {
					return "", fmt.Errorf("regex_replace: output exceeds %d bytes", maxStringBytes)
				}
				b.WriteString(repl)
			} else {
				exp = re.ExpandString(exp[:0], repl, s, m)
				if b.Len()+len(exp) > maxStringBytes {
					return "", fmt.Errorf("regex_replace: output exceeds %d bytes", maxStringBytes)
				}
				b.Write(exp)
			}
			last = m[1]
		}
	}

	if b.Len()+(len(s)-last) > maxStringBytes {
		return "", fmt.Errorf("regex_replace: output exceeds %d bytes", maxStringBytes)
	}
	b.WriteString(s[last:])
	return b.String(), nil
}

// regexFindallBounded evaluates |regex_findall while rejecting match counts >
// maxSeqElems without allocating 1,000,001 per-match []string submatch slices.
func regexFindallBounded(entry *regexEntry, s string) (*List, error) {
	re := entry.re
	mode, lit, isLit, isEmpty := entry.noExpand.mode, entry.noExpand.lit, entry.noExpand.isLit, entry.noExpand.isEmpty
	if re.NumSubexp() == 0 {
		if isLit {
			n := strings.Count(s, lit)
			if n > maxSeqElems {
				return nil, fmt.Errorf("regex_findall: match count exceeds %d", maxSeqElems)
			}
			if n == 0 {
				return &List{}, nil
			}
			out := make([]any, n)
			for i := range out {
				out[i] = lit
			}
			return &List{out}, nil
		}
		if mode == regexLeftFree && !isEmpty {
			const batchSize = 4096
			var out []any
			pos := 0
			prevMatchEnd := -1
			for pos <= len(s) {
				batch := re.FindAllStringIndex(s[pos:], batchSize)
				if len(batch) == 0 {
					break
				}
				startPos := pos
				for i, m := range batch {
					m0, m1 := m[0]+startPos, m[1]+startPos
					if i == 0 && m1 == startPos && m0 == prevMatchEnd {
						continue
					}
					if len(out) >= maxSeqElems {
						return nil, fmt.Errorf("regex_findall: match count exceeds %d", maxSeqElems)
					}
					out = append(out, s[m0:m1])
				}
				if len(batch) < batchSize {
					break
				}
				lastM := batch[len(batch)-1]
				prevMatchEnd = lastM[1] + startPos
				if lastM[0] == lastM[1] {
					if prevMatchEnd == len(s) {
						pos = len(s) + 1
					} else {
						_, w := utf8.DecodeRuneInString(s[prevMatchEnd:])
						if w <= 0 {
							w = 1
						}
						pos = prevMatchEnd + w
					}
				} else {
					pos = prevMatchEnd
				}
			}
			if len(out) == 0 {
				return &List{}, nil
			}
			return &List{out}, nil
		}
		strs := re.FindAllString(s, maxSeqElems+1)
		if len(strs) > maxSeqElems {
			return nil, fmt.Errorf("regex_findall: match count exceeds %d", maxSeqElems)
		}
		if len(strs) == 0 {
			return &List{}, nil
		}
		out := make([]any, len(strs))
		for i, m := range strs {
			out[i] = m
		}
		return &List{out}, nil
	}

	if re.NumSubexp() == 1 {
		if entry.hasLitCap {
			lit := entry.litCapture
			n := strings.Count(s, lit)
			if n > maxSeqElems {
				return nil, fmt.Errorf("regex_findall: match count exceeds %d", maxSeqElems)
			}
			if n == 0 {
				return &List{}, nil
			}
			out := make([]any, n)
			for i := range out {
				out[i] = lit
			}
			return &List{out}, nil
		}
	}

	if mode == regexLeftFree && !isEmpty {
		const batchSize = 4096
		var out []any
		pos := 0
		prevMatchEnd := -1
		for pos <= len(s) {
			batch := re.FindAllStringSubmatchIndex(s[pos:], batchSize)
			if len(batch) == 0 {
				break
			}
			startPos := pos
			for i, m := range batch {
				m0, m1 := m[0]+startPos, m[1]+startPos
				if i == 0 && m1 == startPos && m0 == prevMatchEnd {
					continue
				}
				if len(out) >= maxSeqElems {
					return nil, fmt.Errorf("regex_findall: match count exceeds %d", maxSeqElems)
				}
				switch {
				case len(m) > 4:
					grps := make([]any, 0, len(m)/2-1)
					for k := 2; k < len(m); k += 2 {
						if m[k] >= 0 {
							grps = append(grps, s[m[k]+startPos:m[k+1]+startPos])
						} else {
							grps = append(grps, "")
						}
					}
					out = append(out, &List{grps})
				case len(m) == 4:
					if m[2] >= 0 {
						out = append(out, s[m[2]+startPos:m[3]+startPos])
					} else {
						out = append(out, "")
					}
				default:
					out = append(out, s[m0:m1])
				}
			}
			if len(batch) < batchSize {
				break
			}
			lastM := batch[len(batch)-1]
			prevMatchEnd = lastM[1] + startPos
			if lastM[0] == lastM[1] {
				if prevMatchEnd == len(s) {
					pos = len(s) + 1
				} else {
					_, w := utf8.DecodeRuneInString(s[prevMatchEnd:])
					if w <= 0 {
						w = 1
					}
					pos = prevMatchEnd + w
				}
			} else {
				pos = prevMatchEnd
			}
		}
		if len(out) == 0 {
			return &List{}, nil
		}
		return &List{out}, nil
	}

	// Capture groups present with left anchor: count matches with FindAllString first
	// so inputs exceeding maxSeqElems fail without allocating 1,000,001 []string slices.
	strs := re.FindAllString(s, maxSeqElems+1)
	if len(strs) > maxSeqElems {
		return nil, fmt.Errorf("regex_findall: match count exceeds %d", maxSeqElems)
	}
	if len(strs) == 0 {
		return &List{}, nil
	}
	matches := re.FindAllStringSubmatch(s, len(strs))
	out := make([]any, 0, len(matches))
	for _, m := range matches {
		switch {
		case len(m) > 2:
			// Multiple capture groups — python findall yields a
			// tuple of ALL groups per match, not just group 1.
			grps := make([]any, 0, len(m)-1)
			for _, g := range m[1:] {
				grps = append(grps, g)
			}
			out = append(out, &List{grps})
		case len(m) == 2:
			out = append(out, m[1])
		default:
			out = append(out, m[0])
		}
	}
	return &List{out}, nil
}
