// num.go — the numeric machinery: asInt64/asUint64 normalize every
// Go integer type, numMag/magCmp give integer-typed pairs an exact
// compare that never degrades through float64 (past 2^53, and
// uint64 > MaxInt64), numNeg/addInt64/subInt64/mulInt64/
// exactIntAdd/exactIntSub/numAsFloat feed binOp's arithmetic, and
// numEq/numCmp/minMaxLess are the equality/ordering core the
// filters and tests share. The coercions (ToInt/toFloat) stay in
// value.go — this file is exact-number machinery only.
package jinja

import (
	"fmt"
	"math"
	"math/big"
	"math/bits"
)

// asInt64 normalizes every Go integer type to int64 — contexts feed
// the engine plain Go values (int, uint32, ...) that used to fall
// through every numeric branch and compare/stringify as garbage.
// uint64 (and uint on 64-bit) only converts while it fits int64;
// float64 is deliberately NOT here — it keeps its own (truncating,
// range-checked) path via floatToInt64.
func asInt64(v any) (int64, bool) {
	switch t := v.(type) {
	case int64:
		return t, true
	case int:
		return int64(t), true
	case int32:
		return int64(t), true
	case int16:
		return int64(t), true
	case int8:
		return int64(t), true
	case uint64:
		if t <= math.MaxInt64 {
			return int64(t), true
		}
	case uint:
		if uint64(t) <= math.MaxInt64 {
			return int64(t), true
		}
	case uint32:
		return int64(t), true
	case uint16:
		return int64(t), true
	case uint8:
		return int64(t), true
	}
	return 0, false
}

// asUint64 normalizes unsigned integer types for stringify — a
// uint64 above MaxInt64 still prints exactly.
func asUint64(v any) (uint64, bool) {
	switch t := v.(type) {
	case uint64:
		return t, true
	case uint:
		return uint64(t), true
	case uint32:
		return uint64(t), true
	case uint16:
		return uint64(t), true
	case uint8:
		return uint64(t), true
	}
	return 0, false
}

// numMag returns a number's exact magnitude as (negative?, |value|):
// the uint64 > MaxInt64 values asInt64 rejects keep their exact form
// here, so integer-typed pairs can compare exactly without going
// through float64 (which rounds past 2^53 and clamps past 2^63).
func numMag(v any) (neg bool, mag uint64, ok bool) {
	if i, isInt := asInt64(v); isInt {
		if i < 0 {
			return true, uint64(-(i + 1)) + 1, true
		}
		return false, uint64(i), true
	}
	if u, isUint := asUint64(v); isUint {
		return false, u, true
	}
	return false, 0, false
}

// magCmp orders two signed magnitudes: a negative number always
// loses to an unsigned one (zero never carries the negative flag).
func magCmp(aneg bool, amag uint64, bneg bool, bmag uint64) int {
	switch {
	case aneg != bneg:
		if aneg {
			return -1
		}
		return 1
	case amag < bmag:
		if aneg {
			return 1
		}
		return -1
	case amag > bmag:
		if aneg {
			return -1
		}
		return 1
	}
	return 0
}

func numNeg(v any) (any, error) {
	if f, ok := v.(float64); ok {
		return -f, nil
	}
	if neg, mag, ok := numMag(v); ok {
		if res, ok := magToInt(!neg, mag); ok {
			return res, nil
		}
		return -float64(mag), nil
	}
	return nil, fmt.Errorf("cannot negate %v", v)
}

// addInt64/subInt64/mulInt64 are the exact int64 fast paths for
// binOp's arithmetic: ok=false means the true result does not fit
// int64 and the caller promotes to float64 — a silent wraparound
// would flip the sign and corrupt template math (python ints are
// arbitrary precision).
func addInt64(a, b int64) (int64, bool) {
	s := a + b
	if (b > 0 && s < a) || (b < 0 && s > a) {
		return 0, false
	}
	return s, true
}

func subInt64(a, b int64) (int64, bool) {
	d := a - b
	if (b < 0 && d < a) || (b > 0 && d > a) {
		return 0, false
	}
	return d, true
}

func mulInt64(a, b int64) (int64, bool) {
	if a == 0 || b == 0 {
		return 0, true
	}
	if a == -1 {
		// p/a below would be MinInt64/-1 → SIGFPE when b is
		// MinInt64; handle the sign flip directly.
		if b == math.MinInt64 {
			return 0, false
		}
		return -b, true
	}
	p := a * b
	// Two's-complement wrap makes p/a != b exactly when the true
	// product left int64 range (a == 0 and a == -1 excluded above,
	// so the division can never panic).
	if p/a != b {
		return 0, false
	}
	return p, true
}

// magToInt renders a sign-magnitude result (neg, mag) in the
// engine's numeric types: int64 whenever it fits — either sign —
// uint64 for a non-negative value past MaxInt64, and ok=false when
// no exact form exists (a negative magnitude past |MinInt64|). The
// float64 fallback callers take on ok=false is the best
// representable answer — the same posture every int64 overflow in
// this file takes.
func magToInt(neg bool, mag uint64) (any, bool) {
	if mag == 0 {
		return int64(0), true
	}
	if !neg {
		if mag <= math.MaxInt64 {
			return int64(mag), true
		}
		return mag, true
	}
	// |MinInt64| = 2^63 is the largest negative magnitude int64
	// holds; one past it has no exact form.
	if mag > uint64(math.MaxInt64)+1 {
		return nil, false
	}
	if mag == uint64(math.MaxInt64)+1 {
		return int64(math.MinInt64), true
	}
	return -int64(mag), true
}

// exactIntAdd computes l + r for integer-typed operands (per numMag)
// whose int64 fast path overflowed or never applied — an int64 sum past
// MaxInt64 promotes to uint64, and mixed uint64 + (-int64) normalizes
// back to int64 when in range. ok=false means the true result fits
// neither int64 nor uint64 — the caller falls back to float64.
func exactIntAdd(lneg bool, lm uint64, rneg bool, rm uint64) (any, bool) {
	var neg bool
	var mag uint64
	switch {
	case lneg == rneg:
		// Same sign: magnitudes add.
		var carry uint64
		mag, carry = bits.Add64(lm, rm, 0)
		if carry != 0 {
			return nil, false
		}
		neg = lneg
	case lm >= rm:
		mag, neg = lm-rm, lneg
	default:
		mag, neg = rm-lm, rneg
	}
	return magToInt(neg, mag)
}

// exactIntSub computes l - r for integer-typed operands (per
// numMag) whose int64 fast path overflowed or never applied.
func exactIntSub(lneg bool, lm uint64, rneg bool, rm uint64) (any, bool) {
	// l - r == l + (-r): flip r's sign, then combine magnitudes.
	return exactIntAdd(lneg, lm, !rneg, rm)
}

// exactFloorDivMod computes python's // (floor toward -inf) and %
// (remainder taking the DIVISOR's sign) for integer-typed operands
// past int64 — float64 math rounds both operands to the same value
// and answers 0 where the true result is nonzero
// ((MaxInt64+2) % 2 is 1, not 0). rm == 0 never reaches here: the
// caller's float path raises the division-by-zero error.
func exactFloorDivMod(op string, lneg bool, lm uint64,
	rneg bool, rm uint64) (any, bool) {
	q, rem := lm/rm, lm%rm
	if op == "%" {
		if rem == 0 {
			return int64(0), true
		}
		// python's % result carries the DIVISOR's sign; its
		// magnitude is rem when the operands share a sign and
		// rm-rem when they differ.
		if lneg == rneg {
			return magToInt(rneg, rem)
		}
		return magToInt(rneg, rm-rem)
	}
	// "//": floor toward -inf — a negative quotient with a
	// nonzero remainder steps one magnitude further out
	// (-7//2 = -4, not the truncating -3).
	qneg := lneg != rneg
	if rem != 0 && qneg {
		q++
	}
	return magToInt(qneg, q)
}

// magFloatCmp orders an exact integer magnitude (neg, mag) against
// a FINITE float64 without float64 rounding — big.Rat holds the
// float's exact binary value (every float64 is k×2^e), so
// uint64(2^64-1) correctly compares below 2^64.0 where float64
// math collapsed both onto the same value and broke == transitivity
// across the int/float boundary.
func magFloatCmp(neg bool, mag uint64, f float64) int {
	r := new(big.Rat).SetUint64(mag)
	if neg {
		r.Neg(r)
	}
	return r.Cmp(new(big.Rat).SetFloat64(f))
}

// finiteFloat reports whether v is a float64 that is neither NaN
// nor ±Inf — the only float64 magFloatCmp can order exactly
// (SetFloat64 returns nil for non-finite input).
func finiteFloat(v any) (float64, bool) {
	f, ok := v.(float64)
	if !ok || math.IsNaN(f) || math.IsInf(f, 0) {
		return 0, false
	}
	return f, true
}

// numAsFloat converts only plain, finite numbers — no strings, no
// bools. numEq uses it to keep bool==number numeric (python
// True == 1) while bool==string stays unequal.
func numAsFloat(v any) (float64, bool) {
	switch t := v.(type) {
	case int64:
		return float64(t), true
	case uint64:
		return float64(t), true
	case float64:
		if math.IsNaN(t) || math.IsInf(t, 0) {
			return 0, false
		}
		return t, true
	}
	if i, ok := asInt64(v); ok {
		return float64(i), true
	}
	if u, ok := asUint64(v); ok {
		return float64(u), true
	}
	return 0, false
}

// numEq compares two scalars for equality without cross-type
// surprises:
//
//   - bool == bool is identity; a bool pairs numerically ONLY with
//     a plain number (python True == 1) — never with a string, so
//     false == '0' is false.
//   - string == string is lexicographic, NEVER numeric: '0' and
//     '00', '1e2' and '100' parse to the same float but are
//     different strings.
//   - numeric pairs (int64/float64/numeric-string) compare as
//     floats — '1' == 1 stays true.
//   - a non-finite number (toFloat rejects NaN/±Inf) equals
//     nothing, not even itself (IEEE-754) — the Stringify
//     fallback must not resurrect NaN == NaN as "NaN" == "NaN".
func numEq(l, r any) bool {
	if IsNilOrUndef(l) || IsNilOrUndef(r) {
		return IsNilOrUndef(l) && IsNilOrUndef(r)
	}
	lb, lIsBool := l.(bool)
	rb, rIsBool := r.(bool)
	switch {
	case lIsBool && rIsBool:
		return lb == rb
	case lIsBool:
		rf, ok := numAsFloat(r)
		if !ok {
			return false
		}
		lf := 0.0
		if lb {
			lf = 1
		}
		return lf == rf
	case rIsBool:
		lf, ok := numAsFloat(l)
		if !ok {
			return false
		}
		rf := 0.0
		if rb {
			rf = 1
		}
		return lf == rf
	}
	if ls, ok := l.(string); ok {
		if rs, ok := r.(string); ok {
			return ls == rs
		}
	}
	// Integer-typed pairs compare on exact magnitudes — routing
	// them through float64 rounds both sides to the same value past
	// 2^53 (9007199254740993 == 9007199254740992 used to be true),
	// and a uint64 past MaxInt64 has no int64 form at all.
	if lneg, lm, lok := numMag(l); lok {
		if rneg, rm, rok := numMag(r); rok {
			return magCmp(lneg, lm, rneg, rm) == 0
		}
	}
	// Mixed integer/float pairs compare EXACTLY — routing a uint64
	// past 2^53 through float64 rounds it onto a neighboring float,
	// so two distinct integers could equal the same float and ==
	// lost transitivity. big.Rat keeps the pair honest.
	if lneg, lm, lok := numMag(l); lok {
		if f, ok := finiteFloat(r); ok {
			return magFloatCmp(lneg, lm, f) == 0
		}
	}
	if rneg, rm, rok := numMag(r); rok {
		if f, ok := finiteFloat(l); ok {
			return magFloatCmp(rneg, rm, f) == 0
		}
	}
	lf, lok := toFloat(l)
	rf, rok := toFloat(r)
	if lok && rok {
		return lf == rf
	}
	// Exactly one side numeric (or a rejected NaN/Inf number): a
	// string form like "NaN" must not count as equality.
	if isNum(l) || isNum(r) {
		return false
	}
	return Stringify(l) == Stringify(r)
}

func isNum(v any) bool {
	switch v.(type) {
	case int64, float64:
		return true
	case bool:
		return true
	}
	if _, ok := asInt64(v); ok {
		return true
	}
	// A uint64 (or uint on 64-bit) past MaxInt64 fails asInt64 but
	// is still a number — sorting and comparisons must treat it as
	// one, not dump it into the "other" bucket.
	_, ok := asUint64(v)
	return ok
}

// isFloatNum reports whether v is a float64 — the one numeric type
// ToInt cannot convert losslessly (it truncates 5.5 to 5 and still
// reports ok). binOp's integer fast-paths must exclude it so float
// arithmetic keeps its fraction.
func isFloatNum(v any) bool {
	_, ok := v.(float64)
	return ok
}

// numCmp orders two numeric operands: integer-typed pairs compare on
// int64 (exact past 2^53), everything else on finite floats. ok=false
// means at least one side isn't a usable number (NaN/±Inf) — the
// caller falls back to string ordering instead of silently treating
// the rejected value as 0.0 (the old `lf, _ := toFloat(l)` did).
func numCmp(a, b any) (int, bool) {
	// Exact integer-typed path — int64 magnitudes past 2^53 stay
	// exact, and uint64 > MaxInt64 (no int64 form) compares exactly
	// against signed ints via numMag/magCmp.
	if aneg, am, aok := numMag(a); aok {
		if bneg, bm, bok := numMag(b); bok {
			return magCmp(aneg, am, bneg, bm), true
		}
		// Mixed integer/float ordering is exact too — the float64
		// fallback below rounds a uint64 past 2^53 onto a neighbor,
		// so uint64max < 2^64.0 used to answer "equal".
		if f, ok := finiteFloat(b); ok {
			return magFloatCmp(aneg, am, f), true
		}
	}
	if bneg, bm, bok := numMag(b); bok {
		if f, ok := finiteFloat(a); ok {
			// compare(a, b) = -(compare(b, a)).
			return -magFloatCmp(bneg, bm, f), true
		}
	}
	af, aok := toFloat(a)
	bf, bok := toFloat(b)
	if !aok || !bok {
		return 0, false
	}
	switch {
	case af < bf:
		return -1, true
	case af > bf:
		return 1, true
	}
	return 0, true
}

// minMaxLess is the min/max comparator: numeric when both operands
// are numbers, lexical on the string form otherwise — a non-numeric
// list used to keep the first element untouched (never comparing).
func minMaxLess(a, b any) bool {
	if isNum(a) && isNum(b) {
		if c, ok := numCmp(a, b); ok {
			return c < 0
		}
	}
	return Stringify(a) < Stringify(b)
}
