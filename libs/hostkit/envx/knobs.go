// knobs.go — the declarative env-surface Knob table: one row per
// env var binding a Config field through the getters in envx.go, so
// a ConfigFromEnv reads as a table Apply walks in order. Split from
// envx.go to keep both files under the size ceiling; the getters
// themselves are unchanged.
package envx

import "time"

// Knob is one row of a package's declarative env surface: Name is the
// env var and Resolve lands its value — through the helpers above, so
// the env → conf → compiled-default chains keep their documented
// precedence — into the Config field the closure captured. The *Knob
// constructors cover the common single-getter chains; write a bare
// {Name, Resolve} literal for bespoke resolutions — Resolve receives
// Name, so the env string still appears exactly once per row. Build
// the table inside ConfigFromEnv (Resolve closures capture &cfg) and
// pass it to Apply.
type Knob struct {
	Name    string
	Resolve func(name string)
}

// Apply resolves each knob in table order — the engine behind a
// table-driven ConfigFromEnv env surface.
func Apply(knobs []Knob) {
	for _, k := range knobs {
		k.Resolve(k.Name)
	}
}

// StringKnob binds env name → *p via String (env → def).
func StringKnob(name string, p *string, def string) Knob {
	return Knob{name, func(k string) { *p = String(k, def) }}
}

// BoolKnob binds env name → *p via Bool (env → def).
func BoolKnob(name string, p *bool, def bool) Knob {
	return Knob{name, func(k string) { *p = Bool(k, def) }}
}

// IntKnob binds env name → *p via Int (env → def).
func IntKnob(name string, p *int, def int) Knob {
	return Knob{name, func(k string) { *p = Int(k, def) }}
}

// Int64Knob binds env name → *p via Int64 (env → def).
func Int64Knob(name string, p *int64, def int64) Knob {
	return Knob{name, func(k string) { *p = Int64(k, def) }}
}

// DurationKnob binds env name → *p via Duration (env → def).
func DurationKnob(name string, p *time.Duration, def time.Duration) Knob {
	return Knob{name, func(k string) { *p = Duration(k, def) }}
}

// OrKnob binds env name → *p via Or (env → conf; an empty conf flows
// to the consumer's compiled default, exactly as Or documents).
func OrKnob(name string, p *string, conf string) Knob {
	return Knob{name, func(k string) { *p = Or(k, conf) }}
}

// StrOrKnob binds env name → *p via Str(Or(k, conf), def) — the full
// env → conf → compiled-default string chain in one row.
func StrOrKnob(name string, p *string, conf, def string) Knob {
	return Knob{name, func(k string) { *p = Str(Or(k, conf), def) }}
}

// IntOrKnob binds env name → *p via IntOr (env → conf → def).
func IntOrKnob(name string, p *int, conf, def int) Knob {
	return Knob{name, func(k string) { *p = IntOr(k, conf, def) }}
}

// Int64OrKnob binds env name → *p via Int64Or (env → conf → def).
func Int64OrKnob(name string, p *int64, conf, def int64) Knob {
	return Knob{name, func(k string) { *p = Int64Or(k, conf, def) }}
}

// DurOrKnob binds env name → *p via DurOr (env → conf-seconds → def).
func DurOrKnob(name string, p *time.Duration, confSeconds int, def time.Duration) Knob {
	return Knob{name, func(k string) { *p = DurOr(k, confSeconds, def) }}
}

// ListKnob binds env name → *p via List (unset/empty → nil).
func ListKnob(name string, p *[]string) Knob {
	return Knob{name, func(k string) { *p = List(k) }}
}

// IntListKnob binds env name → *p via IntList (unset/empty → nil).
func IntListKnob(name string, p *[]int) Knob {
	return Knob{name, func(k string) { *p = IntList(k) }}
}
