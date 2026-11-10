// conditions_test.go — the CondDefs registry invariants: every
// condition-surface key must be a registered latch name, every alt
// latch must be registered too, and no two latches may claim the
// same NodeCondition type (a shared type is expressed via Alts on
// ONE primary latch, never by two CondDefs rows).
package latchdefs

import "testing"

// registeredNames is the exact-match half of the latch registry —
// prefix families are excluded: a CondDefs key must name a concrete
// latch, never a parameterized family.
func registeredNames() map[string]bool {
	out := map[string]bool{}
	for _, d := range LatchDefs {
		if !d.Prefix {
			out[d.Name] = true
		}
	}
	return out
}

func TestCondDefsKeysAreRegisteredLatches(t *testing.T) {
	reg := registeredNames()
	for name := range CondDefs {
		if !reg[name] {
			t.Errorf("CondDefs key %q is not a registered latch name", name)
		}
	}
}

func TestCondDefsAltsAreRegisteredLatches(t *testing.T) {
	reg := registeredNames()
	for name, cd := range CondDefs {
		for _, alt := range cd.Alts {
			if !reg[alt] {
				t.Errorf("CondDefs[%q].Alts entry %q is not a registered latch name", name, alt)
			}
		}
	}
}

func TestCondDefsTypesUnique(t *testing.T) {
	seen := map[string]string{}
	for name, cd := range CondDefs {
		if cd.Type == "" {
			t.Errorf("CondDefs[%q].Type is empty", name)
		}
		if prev, dup := seen[cd.Type]; dup {
			t.Errorf("condition type %q claimed by both %q and %q — share via Alts on one primary instead", cd.Type, prev, name)
		}
		seen[cd.Type] = name
	}
}
