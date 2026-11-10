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
				b.WriteString(fmt.Sprintf("%-"+strconv.Itoa(specWidth(spec))+"d", iv))
			} else {
				b.WriteString(fmt.Sprintf("%"+safeFmtSpec(spec)+"d", iv))
			}
		case 'x', 'X':
			iv, ok := ToInt(a)
			if !ok {
				return "", fmt.Errorf("format: %%%s%c arg %v is not a number", spec, conv, a)
			}
			if !validFmtSpec(spec, true) {
				return "", fmt.Errorf("format: unsupported %%%s%c spec", spec, conv)
			}
			b.WriteString(fmt.Sprintf("%"+safeFmtSpec(spec)+string(conv), iv))
		case 'f', 'F', 'e', 'E', 'g', 'G':
			fv, ok := toFloat(a)
			if !ok {
				return "", fmt.Errorf("format: %%%s%c arg %v is not a number", spec, conv, a)
			}
			if !validFmtSpec(spec, true) {
				return "", fmt.Errorf("format: unsupported %%%s%c spec", spec, conv)
			}
			b.WriteString(fmt.Sprintf("%"+safeFmtSpec(spec)+string(conv), fv))
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
			// semantics on %s) — clamped like width so a huge
			// precision can't force an absurd rune slice.
			if digits, ok := specPrecDigits(spec); ok {
				if n := clampSpecNum(digits); n >= 0 {
					if rs := []rune(sv); len(rs) > n {
						sv = string(rs[:n])
					}
				}
			}
			width := specWidth(spec)
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

// specDigits returns spec[i:j] — the run of characters satisfying
// pred starting at i — used to isolate the width/precision digit
// fields of a validated printf spec.
func specDigits(spec string, i int, pred func(byte) bool) string {
	j := i
	for j < len(spec) && pred(spec[j]) {
		j++
	}
	return spec[i:j]
}

func isDigitByte(c byte) bool { return c >= '0' && c <= '9' }
func isFlagByte(c byte) bool {
	return strings.ContainsRune("-+ #0", rune(c))
}

// specWidthDigits extracts the width digits of a validated spec —
// leading flag chars ("-+ #0") and any .precision are excluded.
func specWidthDigits(spec string) string {
	i := 0
	for i < len(spec) && isFlagByte(spec[i]) {
		i++
	}
	return specDigits(spec, i, isDigitByte)
}

// specPrecDigits extracts the precision digits (after '.') of a
// validated spec; ok=false when the spec carries no precision.
func specPrecDigits(spec string) (digits string, ok bool) {
	dot := strings.IndexByte(spec, '.')
	if dot < 0 {
		return "", false
	}
	return specDigits(spec, dot+1, isDigitByte), true
}

// clampSpecNum converts a spec digit field to int, capped at
// maxIndentWidth. Leading zeros are stripped first so "000001"
// isn't mistaken for a huge width; an absurd digit count short-
// circuits to the cap instead of overflowing Atoi.
func clampSpecNum(digits string) int {
	digits = strings.TrimLeft(digits, "0")
	if digits == "" {
		return 0
	}
	if len(digits) > 5 {
		return maxIndentWidth
	}
	n, err := strconv.Atoi(digits)
	if err != nil || n > maxIndentWidth {
		return maxIndentWidth
	}
	return n
}

// specWidth is the clamped numeric width of a validated spec.
func specWidth(spec string) int { return clampSpecNum(specWidthDigits(spec)) }

// safeFmtSpec rebuilds a validated spec with width/precision clamped
// to maxIndentWidth — passing the raw spec to fmt.Sprintf let
// "%999999999f" allocate ~1GB of output (OOM).
func safeFmtSpec(spec string) string {
	i := 0
	for i < len(spec) && isFlagByte(spec[i]) {
		i++
	}
	var b strings.Builder
	b.WriteString(spec[:i])
	if w := specWidth(spec); w > 0 {
		b.WriteString(strconv.Itoa(w))
	}
	if digits, ok := specPrecDigits(spec); ok {
		b.WriteByte('.')
		b.WriteString(strconv.Itoa(clampSpecNum(digits)))
	}
	return b.String()
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
