package kube

import (
	"testing"
	"time"

	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
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

func TestNestedNumber(t *testing.T) {
	obj := map[string]any{
		"spec": map[string]any{
			"fromAPI":     int64(7),      // unstructured decoding
			"fromJSON":    float64(8),    // encoding/json round-trip
			"fromLiteral": int(9),        // hand-built fixture
			"fractional":  float64(3.75), // truncates toward zero
			"name":        "widget",
		},
	}
	for _, tc := range []struct {
		name   string
		fields []string
		want   int64
		ok     bool
	}{
		{"int64", []string{"spec", "fromAPI"}, 7, true},
		{"float64", []string{"spec", "fromJSON"}, 8, true},
		{"int", []string{"spec", "fromLiteral"}, 9, true},
		{"float64 truncates", []string{"spec", "fractional"}, 3, true},
		{"missing", []string{"spec", "absent"}, 0, false},
		{"wrong type", []string{"spec", "name"}, 0, false},
		{"through scalar", []string{"spec", "name", "deep"}, 0, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got, ok := NestedNumber(obj, tc.fields...)
			if got != tc.want || ok != tc.ok {
				t.Fatalf("NestedNumber = (%d,%v), want (%d,%v)",
					got, ok, tc.want, tc.ok)
			}
		})
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
					// float64 observedGeneration — the JSON/fixture
					// shape — decodes through NestedNumber, not absent.
					"observedGeneration": float64(2),
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
	if conds[1].ObservedGeneration != 2 {
		t.Fatalf("float64 ObservedGeneration = %d, want 2",
			conds[1].ObservedGeneration)
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

// ---------------------------------------------------------------------------
// NestedMap / NestedStringMap / NestedStringSlice — copy semantics and
// strict type reads.
// ---------------------------------------------------------------------------

func TestNestedMap(t *testing.T) {
	obj := map[string]any{"status": map[string]any{"limits": map[string]any{"cpu": "2"}}}
	m, ok := NestedMap(obj, "status", "limits")
	if !ok || m["cpu"] != "2" {
		t.Fatalf("got (%v, %v)", m, ok)
	}
	m["cpu"] = "4"
	if obj["status"].(map[string]any)["limits"].(map[string]any)["cpu"] != "2" {
		t.Fatal("returned map aliases the object")
	}
	if _, ok := NestedMap(obj, "status", "absent"); ok {
		t.Fatal("absent path reported found")
	}
	if _, ok := NestedMap(obj, "status", "limits", "cpu"); ok {
		t.Fatal("non-map at leaf reported found")
	}
}

func TestNestedStringMap(t *testing.T) {
	obj := map[string]any{"labels": map[string]any{"a": "1", "b": "2"}}
	m, ok := NestedStringMap(obj, "labels")
	if !ok || m["a"] != "1" || len(m) != 2 {
		t.Fatalf("got (%v, %v)", m, ok)
	}
	m["a"] = "9"
	if obj["labels"].(map[string]any)["a"] != "1" {
		t.Fatal("returned map aliases the object")
	}
	obj2 := map[string]any{"labels": map[string]any{"a": "1", "b": 2}}
	if _, ok := NestedStringMap(obj2, "labels"); ok {
		t.Fatal("non-string leaf tolerated")
	}
	if _, ok := NestedStringMap(obj2, "missing"); ok {
		t.Fatal("absent path reported found")
	}
}

func TestNestedStringSlice(t *testing.T) {
	obj := map[string]any{"names": []any{"a", "b"}}
	s, ok := NestedStringSlice(obj, "names")
	if !ok || len(s) != 2 || s[1] != "b" {
		t.Fatalf("got (%v, %v)", s, ok)
	}
	s[0] = "z"
	if obj["names"].([]any)[0] != "a" {
		t.Fatal("returned slice aliases the object")
	}
	if _, ok := NestedStringSlice(map[string]any{"names": []any{"a", 3}}, "names"); ok {
		t.Fatal("non-string element tolerated")
	}
	if _, ok := NestedStringSlice(map[string]any{}, "names"); ok {
		t.Fatal("absent path reported found")
	}
}

// StripCRDSchemaVersions must mutate the CRD IN PLACE: the old
// implementation navigated via NestedSlice, which deep-copies — the
// delete hit the copy and the object kept every schema (the exact
// heap-pinning this strip exists to prevent). The test proves the
// ORIGINAL object loses spec.versions[*].schema.
func TestStripCRDSchemaVersions(t *testing.T) {
	crd := &unstructured.Unstructured{Object: map[string]any{
		"apiVersion": "apiextensions.k8s.io/v1",
		"kind":       "CustomResourceDefinition",
		"spec": map[string]any{
			"group":      "example.com",
			"conversion": map[string]any{"strategy": "None"},
			"versions": []any{
				map[string]any{
					"name": "v1",
					"schema": map[string]any{
						"openAPIV3Schema": map[string]any{"type": "object"},
					},
				},
				map[string]any{
					"name":   "v2",
					"served": true,
					"schema": map[string]any{
						"openAPIV3Schema": map[string]any{"type": "object"},
					},
				},
				"not-a-map", // non-map entries are skipped, not panics
			},
		},
	}}
	StripCRDSchemaVersions(crd)
	versions, ok := crd.Object["spec"].(map[string]any)["versions"].([]any)
	if !ok {
		t.Fatalf("spec.versions unreadable after strip: %#v", crd.Object["spec"])
	}
	for i, v := range versions[:2] {
		vm := v.(map[string]any)
		if _, has := vm["schema"]; has {
			t.Errorf("versions[%d] still carries schema after strip", i)
		}
		if vm["name"] == nil {
			t.Errorf("versions[%d] lost its name — strip must be surgical", i)
		}
	}
	// Conversion (what the audits read) survives.
	if conv, ok := crd.Object["spec"].(map[string]any)["conversion"].(map[string]any); !ok || conv["strategy"] != "None" {
		t.Fatalf("spec.conversion must survive the strip")
	}
	// Degenerate shapes are no-ops, not panics.
	StripCRDSchemaVersions(nil)
	StripCRDSchemaVersions(&unstructured.Unstructured{})
	StripCRDSchemaVersions(&unstructured.Unstructured{Object: map[string]any{
		"spec": "scalar"}})
	StripCRDSchemaVersions(&unstructured.Unstructured{Object: map[string]any{
		"spec": map[string]any{"versions": "not-a-list"}}})
}

func TestFindCondition(t *testing.T) {
	conds := []Condition{
		{Type: "Ready", Status: "True"},
		{Type: "Synced", Status: "False", Reason: "Err"},
	}
	if c, ok := FindCondition(conds, "Synced"); !ok || c.Reason != "Err" {
		t.Fatalf("FindCondition(Synced) = %+v, %v", c, ok)
	}
	if _, ok := FindCondition(conds, "Missing"); ok {
		t.Fatal("expected Missing condition to return false")
	}
}
