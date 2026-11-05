package jinja

import (
	"fmt"
	"strings"
)

type scope struct {
	vars   map[string]any
	env    *Env
	lookup func(name string) any // external var resolver (checked first)
}

func (s *scope) get(name string) any {
	if s.lookup != nil {
		if v := s.lookup(name); v != nil {
			if _, u := v.(Undefined); !u {
				return v
			}
		}
	}
	if v, ok := s.vars[name]; ok {
		return v
	}
	switch name {
	case "lookup", "ansible.builtin.lookup":
		return builtinFunc(func(args []any, kw map[string]any, sc *scope) (any, error) {
			return doLookup(args, sc)
		})
	case "range":
		return builtinFunc(func(args []any, kw map[string]any, _ *scope) (any, error) {
			var lo, hi, step int64 = 0, 0, 1
			if len(args) == 1 {
				hi, _ = ToInt(args[0])
			} else if len(args) >= 2 {
				lo, _ = ToInt(args[0])
				hi, _ = ToInt(args[1])
			}
			if len(args) > 2 {
				step, _ = ToInt(args[2])
			}
			if step == 0 {
				// lo<hi with step 0 never advances — unbounded
				// append = hang+OOM. Python raises ValueError.
				return nil, fmt.Errorf("range: step cannot be zero")
			}
			// Compute the length arithmetically BEFORE looping —
			// a `for i += step` condition check can't see step
			// wrap the counter (range(-1,-2,MinInt64): -1 wraps to
			// MaxInt64 which still satisfies i>hi → unbounded
			// append). hi-lo itself overflows int64 at the
			// extremes, so count in unsigned space where the
			// difference is exact.
			var count uint64
			if step > 0 && hi > lo {
				d, u := uint64(hi)-uint64(lo), uint64(step)
				count = d / u
				if d%u != 0 {
					count++
				}
			} else if step < 0 && lo > hi {
				// -uint64(step) is |step| even for MinInt64,
				// where -step can't exist as an int64.
				d, u := uint64(lo)-uint64(hi), -uint64(step)
				count = d / u
				if d%u != 0 {
					count++
				}
			}
			if count > rangeMaxOut {
				return nil, fmt.Errorf("range: %d elements exceeds cap %d", count, rangeMaxOut)
			}
			// Drive the loop by the precomputed count, not the
			// boundary condition — i += step may wrap the counter,
			// the count still terminates the append.
			out := make([]any, 0, count)
			for k, i := uint64(0), lo; k < count; k++ {
				out = append(out, i)
				i += step
			}
			return &List{out}, nil
		})
	}
	return Undefined{name}
}

// ---------------- template nodes ----------------

type tnode interface {
	render(s *scope, b *strings.Builder) error
}

type textNode string

func (t textNode) render(_ *scope, b *strings.Builder) error {
	b.WriteString(string(t))
	return nil
}

type exprNode struct{ e expr }

func (n exprNode) render(s *scope, b *strings.Builder) error {
	v, err := n.e.eval(s)
	if err != nil {
		return err
	}
	b.WriteString(Stringify(v))
	return nil
}

type setNode struct {
	name string
	e    expr
}

func (n setNode) render(s *scope, _ *strings.Builder) error {
	v, err := n.e.eval(s)
	if err != nil {
		return err
	}
	s.vars[n.name] = v
	return nil
}

type forNode struct {
	names []string
	list  expr
	conds []expr // {% for x in seq if cond [if cond2] %} filters
	body  []tnode
}

// bind assigns the loop variable(s) for one item. Unpacking N
// names requires the item to yield exactly N values — python
// raises "cannot unpack"/"too many values to unpack" where the
// loose match used to bind literal "key"/"value" strings off
// dict2items pairs, char-split keys, or silently drop extras.
func (n forNode) bind(s *scope, it any) error {
	if len(n.names) == 1 {
		s.vars[n.names[0]] = it
		return nil
	}
	// A mapping is not a pair — iterating it yields keys, and a
	// 2-key mapping would "unpack" into its own key names. The
	// idiom is x.key/x.value on a single loop var, or .items()
	// which yields real [k,v] pairs.
	if _, ok := it.(*OMap); ok {
		return fmt.Errorf("for: cannot unpack a mapping into %d names — use .items() or a single loop var", len(n.names))
	}
	pair := ToIter(it)
	if len(pair) != len(n.names) {
		return fmt.Errorf("for: cannot unpack item with %d values into %d names", len(pair), len(n.names))
	}
	for i, nm := range n.names {
		s.vars[nm] = pair[i]
	}
	return nil
}

func (n forNode) render(s *scope, b *strings.Builder) error {
	v, err := n.list.eval(s)
	if err != nil {
		return err
	}
	// Iterating a mapping yields its KEYS as plain strings — a
	// `for k,v in omap` then char-splits each key (or binds garbage
	// where python raises "cannot unpack"). Fail loud: the idiom is
	// `.items()`/`dict2items`, which yields real pairs.
	if _, ok := v.(*OMap); ok && len(n.names) == 2 {
		return fmt.Errorf("for: cannot unpack mapping keys — use .items() or dict2items")
	}
	// Jinja scopes a for body: the loop var(s) and any {% set %}
	// inside do NOT leak past {% endfor %}. Run the loop on a copy
	// of the bindings — shared *List/*OMap values still mutate
	// through (append-in-loop keeps working), only rebindings are
	// block-local.
	saved := s.vars
	defer func() { s.vars = saved }()
	inner := make(map[string]any, len(saved))
	for k, x := range saved {
		inner[k] = x
	}
	s.vars = inner
	// Apply the `if` filters first: the loop var is bound for each
	// candidate and every condition must be Truthy for the item to
	// iterate — loop.index/count then track the FILTERED sequence
	// (jinja semantics).
	var kept []any
	for _, it := range ToIter(v) {
		if err := n.bind(s, it); err != nil {
			return err
		}
		ok := true
		for _, ce := range n.conds {
			cv, err := ce.eval(s)
			if err != nil {
				return err
			}
			if !Truthy(cv) {
				ok = false
				break
			}
		}
		if ok {
			kept = append(kept, it)
		}
	}
	ln := len(kept)
	for i, it := range kept {
		if err := n.bind(s, it); err != nil {
			return err
		}
		loop := NewOMap()
		loop.Set("index", int64(i+1))
		loop.Set("index0", int64(i))
		loop.Set("revindex", int64(ln-i))
		loop.Set("revindex0", int64(ln-i-1))
		loop.Set("first", i == 0)
		loop.Set("last", i == ln-1)
		loop.Set("length", int64(ln))
		s.vars["loop"] = loop
		if err := renderNodes(n.body, s, b); err != nil {
			return err
		}
	}
	return nil
}

type ifArm struct {
	cond expr // nil = else
	body []tnode
}

type ifNode struct{ arms []ifArm }

func (n ifNode) render(s *scope, b *strings.Builder) error {
	for _, arm := range n.arms {
		if arm.cond == nil {
			return renderNodes(arm.body, s, b)
		}
		v, err := arm.cond.eval(s)
		if err != nil {
			return err
		}
		if Truthy(v) {
			return renderNodes(arm.body, s, b)
		}
	}
	return nil
}

func renderNodes(nodes []tnode, s *scope, b *strings.Builder) error {
	for _, n := range nodes {
		if err := n.render(s, b); err != nil {
			return err
		}
	}
	return nil
}
