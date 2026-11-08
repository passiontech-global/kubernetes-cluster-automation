// filters_format.go — the python printf-style engine behind the
// |format filter (pyFormat) plus its spec validator.
package jinja

import (
	"fmt"
	"strconv"
	"strings"
)

// pyFormat implements the python printf-style subset used by the
// format filter: %s/%r/%v, %d, %x/%X, %f/%e/%g (+upper) with
// flags/width/precision, %c, %%. A conversion we cannot honour
// errors rather than emitting silently wrong output.
func pyFormat(format string, args []any) (string, error) {
	out := format
	argi := 0
	var b strings.Builder
	for i := 0; i < len(out); i++ {
		if out[i] != '%' || i+1 >= len(out) {
			b.WriteByte(out[i])
			continue
		}
		// %% literal
		if out[i+1] == '%' {
			b.WriteByte('%')
			i++
			continue
		}
		j := i + 1
		// A spec is flags/width/precision then ONE conversion
		// letter — the first non-spec byte terminates it. Scanning
		// for "a letter we handle" let %o/%u/%p pass through
		// literally (or eat across text to the next real spec) and
		// left %F a dead case.
		for j < len(out) && strings.ContainsRune("0123456789-+. #", rune(out[j])) {
			j++
		}
		if j >= len(out) {
			// Trailing incomplete spec ("%5" at EOF) — emit as-is.
			b.WriteString(out[i:])
			break
		}
		spec := out[i+1 : j]
		conv := out[j]
		switch conv {
		case 's', 'd', 'v', 'r', 'x', 'X', 'f', 'F', 'e', 'E', 'g', 'G', 'c':
		default:
			return "", fmt.Errorf("format: unsupported conversion %%%c", conv)
		}
		if argi >= len(args) {
			return "", fmt.Errorf("format: not enough args for %%%s%c", spec, conv)
		}
		a := args[argi]
		argi++
		switch conv {
		case 'd':
			iv, ok := ToInt(a)
			if !ok {
				return "", fmt.Errorf("format: %%%sd arg %v is not a number", spec, a)
			}
			if !validFmtSpec(spec, false) {
				return "", fmt.Errorf("format: unsupported %%%s%c spec", spec, conv)
			}
			if strings.Contains(spec, "-") {
				width := 0
				_, _ = fmt.Sscanf(strings.TrimLeft(spec, "-+0"), "%d", &width)
				b.WriteString(fmt.Sprintf("%-"+strconv.Itoa(width)+"d", iv))
			} else {
				b.WriteString(fmt.Sprintf("%"+spec+"d", iv))
			}
		case 'x', 'X':
			iv, ok := ToInt(a)
			if !ok {
				return "", fmt.Errorf("format: %%%s%c arg %v is not a number", spec, conv, a)
			}
			if !validFmtSpec(spec, true) {
				return "", fmt.Errorf("format: unsupported %%%s%c spec", spec, conv)
			}
			b.WriteString(fmt.Sprintf("%"+spec+string(conv), iv))
		case 'f', 'F', 'e', 'E', 'g', 'G':
			fv, ok := toFloat(a)
			if !ok {
				return "", fmt.Errorf("format: %%%s%c arg %v is not a number", spec, conv, a)
			}
			if !validFmtSpec(spec, true) {
				return "", fmt.Errorf("format: unsupported %%%s%c spec", spec, conv)
			}
			b.WriteString(fmt.Sprintf("%"+spec+string(conv), fv))
		case 'c':
			// %c takes flags/width only — no precision.
			if !validFmtSpec(spec, false) {
				return "", fmt.Errorf("format: unsupported %%%s%c spec", spec, conv)
			}
			if iv, ok := ToInt(a); ok {
				b.WriteString(string(rune(iv)))
			} else if sv := Stringify(a); sv != "" {
				// First RUNE, not first byte — sv[:1] split a
				// multi-byte UTF-8 character.
				for _, r := range sv {
					b.WriteRune(r)
					break
				}
			}
		case 's', 'v', 'r':
			// Same flags→width→.precision order as the numeric
			// conversions — "%5-2s" used to slip through and
			// render Go's %!s(BAD) noise.
			if !validFmtSpec(spec, true) {
				return "", fmt.Errorf("format: unsupported %%%s%c spec", spec, conv)
			}
			sv := Stringify(a)
			// %.Ns truncates the string form (python precision
			// semantics on %s).
			if dot := strings.IndexByte(spec, '.'); dot >= 0 {
				if n, err := strconv.Atoi(spec[dot+1:]); err == nil && n >= 0 {
					if rs := []rune(sv); len(rs) > n {
						sv = string(rs[:n])
					}
				}
			}
			num := strings.TrimLeft(spec, "-")
			width := 0
			_, _ = fmt.Sscanf(num, "%d", &width)
			if strings.Contains(spec, "-") {
				b.WriteString(fmt.Sprintf("%-"+strconv.Itoa(width)+"s", sv))
			} else if width > 0 {
				b.WriteString(fmt.Sprintf("%"+strconv.Itoa(width)+"s", sv))
			} else {
				b.WriteString(sv)
			}
		}
		i = j
	}
	if argi < len(args) {
		return "", fmt.Errorf("format: not all arguments converted (%d given)", len(args))
	}
	return b.String(), nil
}

// validFmtSpec reports whether spec (between % and the conversion
// letter) is flags → width → .precision IN ORDER — the flat
// char-set check used to accept "%5-2f", whose mid-spec '-' then
// rendered as Go's %!f(BAD) noise. precision requires dot.
func validFmtSpec(spec string, dot bool) bool {
	i := 0
	for i < len(spec) && strings.ContainsRune("-+ #0", rune(spec[i])) {
		i++ // flags
	}
	for i < len(spec) && spec[i] >= '0' && spec[i] <= '9' {
		i++ // width
	}
	if i < len(spec) && spec[i] == '.' {
		if !dot {
			return false
		}
		i++
		for i < len(spec) && spec[i] >= '0' && spec[i] <= '9' {
			i++ // precision
		}
	}
	return i == len(spec)
}
