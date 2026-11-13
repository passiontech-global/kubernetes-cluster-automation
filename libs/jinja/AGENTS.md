# libs/jinja

Mini-Jinja2 evaluator — just enough of jinja2 plus the ansible filter
set to evaluate vars files and render the vendored `.j2` templates
byte-identically. Leaf module: no I/O of its own (the `Env` hooks are
the inversion point), no knowledge of any consumer.

## Package layout

| File | Responsibility |
|---|---|
| `jinja.go` | Public API: `Render`, `RenderScoped`, `Env`, `Undefined`, `List`, budget constants |
| `lex.go` | Expression tokenizer (typed `tokKind`, string escapes, based/decimal number literals) |
| `parser.go` | `{{ }}`/`{% %}`/`{# #}` split + statement AST (set/for/if) |
| `parser_expr.go` | Expression parser — precedence: ternary → or → and → not → compare → `~` → add → mul → unary → postfix; `parseCallArgs` shared by filter/call |
| `expr.go` | Expression AST + `eval`; `evalCallArgs` (kwargs map nil when empty) |
| `binop.go` | `binOp` binary-operator engine |
| `render.go` | Statement nodes (`set`/`for`/`if`), `scope`, for-loop unpack rules |
| `value.go` | Coercions (`Truthy`, `ToInt`, `toFloat`), iteration (`ToIter`), walk budgets |
| `num.go` | Numeric machinery — `asInt64`/`numMag`/`magCmp` exact compares, int64 fast paths, `numEq`/`numCmp`/`minMaxLess` |
| `methods.go` | Attr/index lookup, bound-method dispatch, deep equality, mapping view |
| `stringify.go` | `Stringify`/`writeStringify` (python repr) + `writeJSONAt` (`to_json` writer) — one `*strings.Builder` threaded through |
| `filters.go` | Filter dispatch (`applyFilter`) + scalar/string/codec/regex cases, `parseMaxBytes` input cap |
| `filters_seq.go` | `unique`/`difference`/`union`/`flatten`/`min`/`max`/`zip`/`dict2items`/`items2dict` |
| `filters_sort.go` | `|sort` + `sortKey`/`numSortKind` key machinery (exact >2^53 integers) |
| `filters_select.go` | `map`/`select`/`reject`/`selectattr`/`rejectattr` family |
| `filters_format.go` | printf-style `format` |
| `tests.go` | `is <test>` predicate dispatch |
| `convert.go` | `to_json`/`to_yaml`/`to_nice_yaml` (order-preserving), `from_json`/`from_yaml` |
| `lookup.go` | `lookup('file'|'pipe', …)` dispatch via `Env` hooks |
| `cache.go` | Compiled-AST + regex compile caches — CLOCK (second-chance) rings behind `sync.RWMutex` (thread-safety contract below) |
| `omap.go` | `OMap` ordered map, YAML decode (`DecodeYAML`), typed getters |

## The OMap ordering guarantee

Ansible sources iterate registries and dicts in FILE order
(`interdc_nodes.yaml` is regenerated with `to_nice_yaml`; insertion
order is meaningful for derived probe/target lists that are NOT all
sorted). Go's `map[string]any` loses that order, so:

- Every YAML mapping decodes into `*OMap`, which preserves insertion
  (file) order. `Set` preserves first-insert position on overwrite;
  `Del` keeps the order of the rest.
- `to_yaml`/`to_nice_yaml`/`to_json` serialize `*OMap` in insertion
  order. Plain Go maps are SORTED (deterministic, but not insertion
  order) — never route ordered data through `map[string]any`.
- Iteration (`for k in dict`, `dict2items`, `.items()`) follows the
  same order for `*OMap`, sorted keys for plain maps.

Typed getters on `*OMap` (`Str`, `Bool`, `BoolDef`, `Int`, `Slice`,
`StrMap`) are the single home for the scalar coercions every consumer
used to re-implement (missing key and stored nil are deliberately the
same zero; all are nil-receiver safe). `Str` is NOT `Stringify`:
bools render `true`/empty (not python's `True`/`False`) and containers
render empty, matching the registry helpers' expectations.

## Render / thread-safety

- `Render`/`RenderScoped` share a compiled-AST clock cache keyed by
  template source (`cache.go`, cap 128). Parsed trees are immutable at render
  time — every node method reads its fields and writes only
  render-local state — so one tree is safely shared across concurrent
  renders. The full argument and the `-race` exercise
  (`TestTemplateCacheConcurrent`) live in `cache.go` /
  `cache_test.go`; keep that test green when touching node types.
- Regex patterns from `regex_*` filters and `is search` compile once
  per pattern (`cache.go`); compile failures stay uncached.
- Values passed INTO a render are shared mutable state by design —
  `{% append %}`-style loop mutation must stay visible to the caller
  (python list parity). Do not reuse a ctx map across concurrent
  renders if templates mutate its values.
- Cyclic values are constructible in-template; every recursive walker
  (stringify, deepEq, JSON/YAML, flatten) is depth- AND step-budgeted
  — see the constants in `jinja.go`/`value.go`. New recursion must
  carry the same budgets.

## Leaf-module invariant

`libs/jinja` must not import anything from `apps/*` or
`libs/hostkit` — it is the bottom of the `go.work` graph next to
`libs/jinja`-style leaves. The ONLY third-party dependency is
`go.yaml.in/yaml/v3`. Consumer-specific behavior belongs behind the
`Env` hooks (`FileLookup`, `PipeLookup`) or the caller's lookup
function (`RenderScoped`), never inside the engine.

## Adding a filter

1. Add a `case "name":` to `applyFilter` in `filters.go` (or a helper
   file if it clusters with siblings, like `filters_select.go`).
   Names follow the lowercase ansible/jinja2 spelling, aliases share
   a case (`"length", "count"`, `"equalto", "eq"`).
2. Keyword args arrive in `kw` (nil unless the call had kwargs —
   reading a nil map is fine). Match jinja2/ansible semantics exactly:
   pin expectations by probing real jinja2 before writing the
   implementation, and keep positional-arg order identical to the
   python signature (`sort(reverse, case_sensitive, attribute)`).
   Document new kw names in the package header in `jinja.go`.
3. Runtime errors: return a descriptive error; only an UNREGISTERED
   name may return `errUnknownFilter` — `filterMap`'s fallback keys on
   it via `errors.Is`, so a known filter's real failure must not be
   mistaken for "unknown filter" and swallowed into an Undefined.
4. Update the filter list in the `jinja.go` package header.

## Adding a test

- One table-driven suite per behavior contract; subtests for variants.
  Reuse `renderBounded` (audit_fixes_test.go) for anything that could
  hang — it turns a regression into a deadline failure instead of a
  stalled suite.
- Pin jinja2-parity expectations against real jinja2 (see the header
  of `filters_kw_test.go` for what was probed and on which version).
- New value types / node types: extend `cache_test.go`'s concurrent
  render so the immutability contract stays exercised.
- Verify module-scoped:

  ```
  cd libs/jinja && GOWORK=off go build ./... && GOWORK=off go vet ./... && GOWORK=off go test -race ./...
  ```
