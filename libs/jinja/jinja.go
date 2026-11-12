// Package jinja is a mini-Jinja2 evaluator — just enough of jinja2 +
// the ansible filter set to evaluate the vars files
// (defaults.yaml / cluster.yaml) and to render the vendored .j2
// templates byte-identically.
//
// Supported:
//
//	statements: {{ expr }}, {% set x = expr %}, {% for a[,b] in expr %},
//	            {% if expr %} {% elif %} {% else %} {% endif %}, {# c #}
//	whitespace control via {%-/-%} {{-/-}} {#-/-#}
//	expressions: literals (str/int/float/bool/none/list/dict), names,
//	             .attr ['key'] [idx] calls, methods (items/append/get/
//	             keys/values/endswith/startswith/split/strip/index/pop),
//	             filters |f(a), + - ~ * / // %, == != < <= > >=
//	             in/not in, is [not] t, and/or/not, x if c else y
//	tests: defined undefined none mapping iterable sequence string
//	       number boolean bool search equalto eq sameas changed
//	       failed succeeded skipped in
//	filters: basename bool b64decode b64encode count d default dict2items
//	         difference eq equalto first flatten float format from_json
//	         from_yaml hash indent int items2dict join last length list
//	         lower mandatory map min max regex_escape regex_findall
//	         regex_replace regex_search reject rejectattr search select
//	         selectattr sort split string ternary to_json to_yaml
//	         to_nice_yaml trim union unique upper zip
//	keyword args (jinja2/ansible parity): sort(reverse=, case_sensitive=,
//	         attribute=), int(default=, base=), float(default=),
//	         default(default_value=, boolean=), items2dict(key_name=,
//	         value_name=), indent(blank=), map(attribute=, default=)
//	functions: lookup('file'|'ansible.builtin.file'|'pipe'|...), range(...)
//
// NOT supported (unused by the ported sources): namespace(), macros,
// imports, raw blocks, slices, **.
package jinja

import (
	"maps"
	"strings"
)

// Undefined is the jinja `undefined` — falsy, default()-able.
type Undefined struct{ name string }

func (u Undefined) String() string { return "Undefined(" + u.name + ")" }

// NewUndefined returns the `undefined` value for a missing name —
// falsy, default()-able, stringifies to "".
func NewUndefined(name string) Undefined { return Undefined{name} }

// List wraps a slice so in-place mutation (append inside set/for)
// behaves like python lists across scope bindings.
type List struct{ V []any }

// flattenMaxDepth bounds |flatten recursion — a self-referential
// list would otherwise loop forever (python raises RecursionError;
// here the tail is left unexpanded).
const flattenMaxDepth = 100

// flattenMaxOut bounds |flatten OUTPUT. Depth alone doesn't stop
// a branching cycle — l.V=[l,l] stays shallow while doubling the
// result every level (2^100 appends), so total elements are
// budgeted too.
const flattenMaxOut = 100_000

// walkMaxDepth bounds the recursive value walkers (Stringify,
// deepEq, toYAMLNode, toJSON). A cyclic *List/*OMap is
// constructible in-template ({% set _ = l.append(l) %}) and would
// otherwise recurse until the goroutine stack burst — python
// raises RecursionError, here the deep tail is elided/false.
const walkMaxDepth = 200

// rangeMaxOut bounds range() materialization — python's range is
// lazy, ours builds a slice, so an open-ended range must fail
// rather than hang+OOM on the append.
const rangeMaxOut = 1_000_000

// Env carries render-time hooks.
type Env struct {
	// FileLookup resolves lookup('file'|'ansible.builtin.file', path).
	FileLookup func(path string) (string, error)
	// PipeLookup resolves lookup('pipe'|'ansible.builtin.pipe', cmd) —
	// only 'date +%s' is honoured (returns unix epoch string).
	PipeLookup func(cmd string) (string, error)
}

// Render evaluates template text against ctx (name → value).
func Render(text string, ctx map[string]any, env *Env) (string, error) {
	nodes, err := parsedTemplate(text)
	if err != nil {
		return "", err
	}
	vars := maps.Clone(ctx)
	if vars == nil {
		vars = map[string]any{}
	}
	s := &scope{vars: vars, env: env}
	var b strings.Builder
	if err := renderNodes(nodes, s, &b); err != nil {
		return "", err
	}
	return b.String(), nil
}

// RenderScoped renders template text where template names resolve
// through lookup BEFORE the builtins (unlike Render, whose names come
// from a fixed ctx map) — the lazy vars-file resolution path, where a
// var's {{ }} sees every other var through the same resolver.
// lookup returning nil or an Undefined falls through to the builtins.
func RenderScoped(text string, env *Env, lookup func(name string) any) (string, error) {
	nodes, err := parsedTemplate(text)
	if err != nil {
		return "", err
	}
	s := &scope{vars: map[string]any{}, env: env, lookup: lookup}
	var b strings.Builder
	if err := renderNodes(nodes, s, &b); err != nil {
		return "", err
	}
	return b.String(), nil
}
