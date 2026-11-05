// unstructured.go — generic field accessors for objects read through
// the dynamic client, complementing the Ready* helpers in helpers.go.
// The modules reach into CRD status/spec constantly
// (unstructured.NestedString/NestedBool/NestedInt64/NestedFloat64/
// NestedSlice — 100+ call sites); these wrappers keep the same
// defensive contract — a malformed or absent read returns ok=false,
// never an error and never a panic — while dropping the third
// return every caller was discarding anyway, and accepting the raw
// map[string]any so nested maps (a condition entry, a status block)
// work as well as u.Object.
package shared

import (
	"time"

	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
)

// NestedString reads a string field at path fields — ("", false) on
// absence or wrong type. Equivalent to unstructured.NestedString with
// the error folded into ok.
func NestedString(obj map[string]any, fields ...string) (string, bool) {
	v, found, err := unstructured.NestedString(obj, fields...)
	return v, found && err == nil
}

// NestedBool reads a bool field at path fields.
func NestedBool(obj map[string]any, fields ...string) (bool, bool) {
	v, found, err := unstructured.NestedBool(obj, fields...)
	return v, found && err == nil
}

// NestedInt64 reads an int64 field at path fields — same strictness
// as unstructured.NestedInt64: a float64-stored number reads as
// absent (use NestedFloat64 for those).
func NestedInt64(obj map[string]any, fields ...string) (int64, bool) {
	v, found, err := unstructured.NestedInt64(obj, fields...)
	return v, found && err == nil
}

// NestedFloat64 reads a float64 field at path fields.
func NestedFloat64(obj map[string]any, fields ...string) (float64, bool) {
	v, found, err := unstructured.NestedFloat64(obj, fields...)
	return v, found && err == nil
}

// NestedSlice reads a []any field at path fields — (nil, false) on
// absence, wrong type, or a non-list value.
func NestedSlice(obj map[string]any, fields ...string) ([]any, bool) {
	v, found, err := unstructured.NestedSlice(obj, fields...)
	return v, found && err == nil
}

// Condition is one decoded entry of a conditions-style status list —
// the near-universal {type,status,reason,message,lastTransitionTime}
// shape cert-manager, Flux, OLM, Gateway-API and most operators
// stamp. Fields the entry lacks stay zero-valued; the decode never
// fails on a partial entry (same posture as ReadyConds).
type Condition struct {
	Type    string
	Status  string
	Reason  string
	Message string
	// LastTransitionTime is the parsed RFC3339 timestamp — zero when
	// absent or unparseable (same contract as ReadySince).
	LastTransitionTime time.Time
	// ObservedGeneration is the generation the condition's controller
	// last reconciled — Gateway-API resources report it inside
	// conditions instead of a top-level status.observedGeneration.
	// 0 when absent (a condition that never reported reads as
	// "never reconciled", matching the watchdog signatures).
	ObservedGeneration int64
}

// Conditions decodes every well-formed map entry of the list at path
// fields — "status","conditions" on an object's .Object map, or
// "conditions" on a nested map (a Gateway status.parents entry). A
// non-map element is skipped, never fatal. Returns nil when the path
// is absent or not a list.
func Conditions(obj map[string]any, fields ...string) []Condition {
	raw, found := NestedSlice(obj, fields...)
	if !found {
		return nil
	}
	out := make([]Condition, 0, len(raw))
	for _, c := range raw {
		m, ok := c.(map[string]any)
		if !ok {
			continue
		}
		cond := Condition{}
		cond.Type, _ = NestedString(m, "type")
		cond.Status, _ = NestedString(m, "status")
		cond.Reason, _ = NestedString(m, "reason")
		cond.Message, _ = NestedString(m, "message")
		if ts, ok := NestedString(m, "lastTransitionTime"); ok {
			if t, err := time.Parse(time.RFC3339, ts); err == nil {
				cond.LastTransitionTime = t
			}
		}
		cond.ObservedGeneration, _ = NestedInt64(m, "observedGeneration")
		out = append(out, cond)
	}
	return out
}

// FindCondition returns the first condition of type condType —
// ok=false when the type is absent (the same "no such condition"
// verdict NodeCondition gives for typed objects).
func FindCondition(conds []Condition, condType string) (Condition, bool) {
	for _, c := range conds {
		if c.Type == condType {
			return c, true
		}
	}
	return Condition{}, false
}

// ConditionOf is the one-call form for the canonical location:
// the named condition from obj's status.conditions — the shape
// apiserviceguard's apiServiceUnavailableSince and every
// "conditions[type=X].status==Y" check hand-rolls.
func ConditionOf(obj map[string]any, condType string) (Condition, bool) {
	return FindCondition(Conditions(obj, "status", "conditions"), condType)
}
