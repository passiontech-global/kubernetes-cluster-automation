// binop.go — the binary-operator engine binExpr.eval dispatches to.
// binOp lives here (not value.go/num.go) because it IS the
// eval-time operator: the numeric helpers it leans on
// (toFloat/ToInt/isNum/addInt64/…) are split across value.go
// (coercions) and num.go (exact-number machinery).
package jinja

import (
	"errors"
	"fmt"
	"math"
	"math/bits"
	"strings"
)

// ---------------- binary operators ----------------

func binOp(op string, l, r any) (any, error) {
	switch op {
	case "~":
		return Stringify(l) + Stringify(r), nil
	case "+":
		// seq+seq concatenates across BOTH list representations:
		// DecodeYAML yields []any while list literals and filters
		// yield *List — `yaml_list + ['a']` used to fall through to
		// the unsupported-operands error.
		if ls, ok := seqElems(l); ok {
			if rs, ok := seqElems(r); ok {
				out := append(append([]any{}, ls...), rs...)
				if _, isList := l.(*List); isList {
					return &List{out}, nil
				}
				if _, isList := r.(*List); isList {
					return &List{out}, nil
				}
				return out, nil
			}
		}
		if isStr(l) || isStr(r) {
			// str+str concatenates; str+number silently producing
			// "53" for '5'+3 hides template bugs — python raises
			// TypeError (use ~ for concat-coercion).
			ls, lok := l.(string)
			rs, rok := r.(string)
			if lok && rok {
				return ls + rs, nil
			}
			// Name the NON-string operand — reporting r's type
			// blamed the string half when l was the offender.
			bad := r
			if !lok {
				bad = l
			}
			return nil, fmt.Errorf("cannot concatenate string and %T (use ~ for coercion)", bad)
		}
		if lf, ok := toFloat(l); ok {
			if rf, ok := toFloat(r); ok {
				li, lInt := ToInt(l)
				ri, rInt := ToInt(r)
				if lInt && rInt && isNum(l) && isNum(r) &&
					!isFloatNum(l) && !isFloatNum(r) {
					if s, ok := addInt64(li, ri); ok {
						return s, nil
					}
				}
				// An operand genuinely past int64 (uint64 > MaxInt64)
				// has no int64 fast path — while the exact sum fits
				// uint64 it must not degrade to float64 rounding.
				if isNum(l) && isNum(r) && !isFloatNum(l) && !isFloatNum(r) &&
					(!intFit(l) || !intFit(r)) {
					if lneg, lm, lok := numMag(l); lok {
						if rneg, rm, rok := numMag(r); rok {
							if s, ok := exactUint64Sum(lneg, lm, rneg, rm); ok {
								return s, nil
							}
						}
					}
				}
				return lf + rf, nil
			}
		}
		// list+num, dict+num, none+num … used to fall through to
		// a silent Stringify-concat — same bug-hiding class as
		// str+num. Only num+num, str+str and seq+seq are legal.
		return nil, fmt.Errorf("unsupported operand types for +: %T and %T", l, r)
	case "-", "*", "/", "//", "%":
		lf, lok := toFloat(l)
		rf, rok := toFloat(r)
		if !lok || !rok {
			return nil, fmt.Errorf("non-numeric %s operands", op)
		}
		li, lInt := ToInt(l)
		ri, rInt := ToInt(r)
		// ToInt TRUNCATES every float64 (5.5 → 5, ok=true), so
		// lInt/rInt alone would route `5.5 * 2.0` through the
		// integer branch below and silently drop the fraction
		// (10 instead of 11). The fast-path is only for genuinely
		// integer-typed operands — any float64 takes the float
		// math further down.
		if lInt && rInt && isNum(l) && isNum(r) &&
			!isFloatNum(l) && !isFloatNum(r) && op != "/" {
			switch op {
			case "-":
				if d, ok := subInt64(li, ri); ok {
					return d, nil
				}
			case "*":
				if p, ok := mulInt64(li, ri); ok {
					return p, nil
				}
			case "//":
				if ri == 0 {
					return nil, errors.New("division by zero")
				}
				if li == math.MinInt64 && ri == -1 {
					// The only int64 divide whose quotient
					// overflows: the hardware divide would raise
					// SIGFPE. MinInt64 is exact as a float64 and
					// /-1 gives exactly 2^63, so the float path
					// answers exactly.
					return math.Floor(lf / rf), nil
				}
				// python // FLOORS: -7//2 = -4, 7//-2 = -4 — Go's
				// truncating division would give -3 for both.
				q := li / ri
				if li%ri != 0 && (li < 0) != (ri < 0) {
					q--
				}
				return q, nil
			case "%":
				if ri == 0 {
					return nil, errors.New("modulo by zero")
				}
				if li == math.MinInt64 && ri == -1 {
					// Same divide-overflow SIGFPE hazard; the
					// remainder never overflows and is exactly 0
					// (x % -1 == 0 in python for every x).
					return int64(0), nil
				}
				// python's % takes the DIVISOR's sign: -7%2 = 1,
				// 7%-2 = -1 — Go's remainder truncates toward zero.
				m := li % ri
				if m != 0 && (m < 0) != (ri < 0) {
					m += ri
				}
				return m, nil
			}
		}
		// An operand genuinely past int64 (uint64 > MaxInt64) has no
		// int64 fast path — while the exact result fits uint64 it
		// must not degrade to float64 rounding.
		if op == "-" || op == "*" {
			if isNum(l) && isNum(r) && !isFloatNum(l) && !isFloatNum(r) &&
				(!intFit(l) || !intFit(r)) {
				if lneg, lm, lok := numMag(l); lok {
					if rneg, rm, rok := numMag(r); rok {
						switch op {
						case "-":
							if s, ok := exactUint64Sum(lneg, lm, !rneg, rm); ok {
								return s, nil
							}
						case "*":
							// The product of two magnitudes past
							// int64 can still fit uint64 exactly
							// (e.g. 2^63 * 3).
							hi, lo := bits.Mul64(lm, rm)
							if hi == 0 && lneg == rneg {
								return lo, nil
							}
						}
					}
				}
			}
		}
		switch op {
		case "-":
			return lf - rf, nil
		case "*":
			return lf * rf, nil
		case "/", "//":
			if rf == 0 {
				return nil, errors.New("division by zero")
			}
			if op == "//" {
				// python's float // floors too: -7.0//2 = -4.0
				// (plain division truncates toward zero).
				return math.Floor(lf / rf), nil
			}
			return lf / rf, nil
		case "%":
			if rf == 0 {
				return nil, errors.New("modulo by zero")
			}
			// math.Mod, NOT int64(lf) % int64(rf): operands reaching
			// this branch aren't int-representable (a float-string
			// like "0.5"), and truncating a sub-1 divisor to
			// int64(rf)==0 was an integer divide-by-zero PANIC.
			// Python's % takes the DIVISOR's sign (floored modulo),
			// so shift an fmod result whose sign disagrees with rf.
			m := math.Mod(lf, rf)
			if m != 0 && (m < 0) != (rf < 0) {
				m += rf
			}
			return m, nil
		}
	case "==":
		return deepEq(l, r), nil
	case "!=":
		return !deepEq(l, r), nil
	case "<", "<=", ">", ">=":
		if isNum(l) && isNum(r) {
			c, ok := numCmp(l, r)
			if !ok {
				// A NaN/±Inf operand makes EVERY ordering
				// comparison false (IEEE-754 / python) — falling
				// through to the string branch would compare
				// "NaN" < "5" lexically and answer nonsense.
				return false, nil
			}
			switch op {
			case "<":
				return c < 0, nil
			case "<=":
				return c <= 0, nil
			case ">":
				return c > 0, nil
			case ">=":
				return c >= 0, nil
			}
		}
		ls, rs := Stringify(l), Stringify(r)
		switch op {
		case "<":
			return ls < rs, nil
		case "<=":
			return ls <= rs, nil
		case ">":
			return ls > rs, nil
		case ">=":
			return ls >= rs, nil
		}
	case "in":
		switch rt := r.(type) {
		case string:
			return strings.Contains(rt, Stringify(l)), nil
		case *List:
			var rv []any
			if rt != nil {
				rv = rt.V
			}
			return binOp("in", l, rv)
		case []any:
			for _, it := range rt {
				if deepEq(it, l) {
					return true, nil
				}
			}
			return false, nil
		case *OMap:
			_, ok := rt.Get(Stringify(l))
			return ok, nil
		}
		// Plain Go maps get the same membership test *OMap has —
		// "k" in map[string]any was a silent false while deepEq
		// already treats all three mapping shapes equivalently.
		// mapLookup keeps the hit case O(1): asMapping's sorted-key
		// view bought nothing for a single membership probe.
		if _, found := mapLookup(r, Stringify(l)); found {
			return true, nil
		}
		return false, nil
	}
	return nil, fmt.Errorf("unsupported op %q", op)
}
