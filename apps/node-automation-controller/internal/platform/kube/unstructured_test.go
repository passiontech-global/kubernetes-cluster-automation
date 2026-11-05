package kube

import (
	"testing"
	"time"
)

func TestNestedScalars(t *testing.T) {
	obj := map[string]any{
		"spec": map[string]any{
			"paused":   true,
			"replicas": int64(3),
			"ratio":    float64(0.5),
			"name":     "widget",
			"nested":   map[string]any{"deep": "value"},
		},
	}
	for _, tc := range []struct {
		name   string
		fn     func(map[string]any, ...string) (string, bool)
		fields []string
		want   string
		ok     bool
	}{
		{"string", NestedString, []string{"spec", "name"}, "widget", true},
		{"string missing", NestedString, []string{"spec", "absent"}, "", false},
		{"string wrong type", NestedString, []string{"spec", "paused"}, "", false},
		{"deep path", NestedString, []string{"spec", "nested", "deep"}, "value", true},
		// A non-map intermediate must read as absent, not panic.
		{"through scalar", NestedString, []string{"spec", "name", "deeper"}, "", false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got, ok := tc.fn(obj, tc.fields...)
			if got != tc.want || ok != tc.ok {
				t.Fatalf("got (%q,%v), want (%q,%v)", got, ok, tc.want, tc.ok)
			}
		})
	}

	if v, ok := NestedBool(obj, "spec", "paused"); !ok || !v {
		t.Fatalf("NestedBool = (%v,%v)", v, ok)
	}
	if _, ok := NestedBool(obj, "spec", "name"); ok {
		t.Fatal("NestedBool accepted a string")
	}
	if v, ok := NestedInt64(obj, "spec", "replicas"); !ok || v != 3 {
		t.Fatalf("NestedInt64 = (%v,%v)", v, ok)
	}
	// Same strictness as unstructured.NestedInt64: a float64-stored
	// number is NOT an int64 — JSON round-trips that produce
	// float64 must go through NestedFloat64 instead.
	obj["spec"].(map[string]any)["replicas"] = float64(3)
	if _, ok := NestedInt64(obj, "spec", "replicas"); ok {
		t.Fatal("NestedInt64 accepted a float64")
	}
	if v, ok := NestedFloat64(obj, "spec", "ratio"); !ok || v != 0.5 {
		t.Fatalf("NestedFloat64 = (%v,%v)", v, ok)
	}
	if _, ok := NestedFloat64(obj, "spec", "paused"); ok {
		t.Fatal("NestedFloat64 accepted a bool")
	}
	if got, ok := NestedSlice(obj, "spec", "nested"); ok || got != nil {
		t.Fatalf("NestedSlice on a map = (%v,%v)", got, ok)
	}
}

func TestNestedNilObject(t *testing.T) {
	if _, ok := NestedString(nil, "status", "phase"); ok {
		t.Fatal("nil object reported a value")
	}
	if c := Conditions(nil, "status", "conditions"); c != nil {
		t.Fatalf("Conditions(nil) = %v", c)
	}
}

func TestConditionsDecode(t *testing.T) {
	obj := map[string]any{
		"status": map[string]any{
			"conditions": []any{
				map[string]any{
					"type":               "Ready",
					"status":             "False",
					"reason":             "Progressing",
					"message":            "waiting",
					"lastTransitionTime": "2026-11-05T10:00:00Z",
					"observedGeneration": int64(7),
				},
				"not-a-map", // malformed entries are skipped
				map[string]any{
					"type":   "Available",
					"status": "True",
					// no reason/message/timestamp — partial entries decode
				},
			},
		},
	}
	conds := Conditions(obj, "status", "conditions")
	if len(conds) != 2 {
		t.Fatalf("got %d conditions, want 2 (malformed skipped)", len(conds))
	}
	c := conds[0]
	if c.Type != "Ready" || c.Status != "False" ||
		c.Reason != "Progressing" || c.Message != "waiting" {
		t.Fatalf("cond = %+v", c)
	}
	want := time.Date(2026, 11, 5, 10, 0, 0, 0, time.UTC)
	if !c.LastTransitionTime.Equal(want) {
		t.Fatalf("LastTransitionTime = %v, want %v", c.LastTransitionTime, want)
	}
	if c.ObservedGeneration != 7 {
		t.Fatalf("ObservedGeneration = %d", c.ObservedGeneration)
	}
	if conds[1].Reason != "" || !conds[1].LastTransitionTime.IsZero() {
		t.Fatalf("partial cond = %+v", conds[1])
	}
}

func TestConditionsAbsentAndNestedPath(t *testing.T) {
	if c := Conditions(map[string]any{}, "status", "conditions"); c != nil {
		t.Fatalf("absent conditions = %v", c)
	}
	// A conditions list nested inside another object (e.g. a
	// status.parents entry) decodes through the same accessor.
	parent := map[string]any{
		"conditions": []any{map[string]any{"type": "Accepted", "status": "True"}},
	}
	conds := Conditions(parent, "conditions")
	if len(conds) != 1 || conds[0].Type != "Accepted" {
		t.Fatalf("nested conditions = %+v", conds)
	}
}

func TestFindConditionAndConditionOf(t *testing.T) {
	obj := map[string]any{
		"status": map[string]any{
			"conditions": []any{
				map[string]any{"type": "Available", "status": "False",
					"lastTransitionTime": "2026-11-05T11:00:00Z"},
			},
		},
	}
	c, ok := ConditionOf(obj, "Available")
	if !ok || c.Status != "False" {
		t.Fatalf("ConditionOf = (%+v,%v)", c, ok)
	}
	if _, ok := ConditionOf(obj, "Progressing"); ok {
		t.Fatal("ConditionOf found a condition that does not exist")
	}
}
