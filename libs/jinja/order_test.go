// order_test.go — *OMap insertion order must survive the to_yaml /
// to_json / to_nice_yaml filters: the ansible-derived vars regenerate
// ordered YAML (interdc_nodes.yaml), so a map round-trip that sorts
// keys would churn the rendered config on every unrelated edit.
package jinja

import (
	"strings"
	"testing"
)

func TestToYAMLPreservesOMapOrder(t *testing.T) {
	v, err := DecodeYAML([]byte("zebra: 1\nalpha: 2\nmike: 3\nnested:\n  y: 1\n  b: 2\n"))
	if err != nil {
		t.Fatal(err)
	}
	out, err := Render("{{ d | to_yaml }}", map[string]any{"d": v}, nil)
	if err != nil {
		t.Fatal(err)
	}
	want := "zebra: 1\nalpha: 2\nmike: 3\nnested:\n    \"y\": 1\n    b: 2\n"
	if out != want {
		t.Fatalf("to_yaml = %q want %q", out, want)
	}
}

func TestToJSONPreservesOMapOrder(t *testing.T) {
	v, err := DecodeYAML([]byte("zebra: 1\nalpha: 2\nmike: 3\n"))
	if err != nil {
		t.Fatal(err)
	}
	out, err := Render("{{ d | to_json }}", map[string]any{"d": v}, nil)
	if err != nil {
		t.Fatal(err)
	}
	if out != `{"zebra":1,"alpha":2,"mike":3}` {
		t.Fatalf("to_json = %q", out)
	}
	// Dict literals build an OMap too — literal order wins.
	out, err = Render(`{{ {'b': 1, 'a': 2} | to_json }}`, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	if out != `{"b":1,"a":2}` {
		t.Fatalf("dict-literal to_json = %q", out)
	}
}

// Scalar quoting must match the old yaml.Marshal path byte-for-byte:
// YAML 1.1 bool spellings and base-60 floats stay quoted so PyYAML
// consumers don't re-type them.
func TestToYAMLScalarQuotingParity(t *testing.T) {
	v, err := DecodeYAML([]byte("yes-key: 'yes'\nnum-key: '123'\nbase60: '1:20'\n"))
	if err != nil {
		t.Fatal(err)
	}
	out, err := Render("{{ d | to_yaml }}", map[string]any{"d": v}, nil)
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{`yes-key: "yes"`, `num-key: "123"`, `base60: "1:20"`} {
		if !strings.Contains(out, want) {
			t.Fatalf("to_yaml missing %q in:\n%s", want, out)
		}
	}
}
