// resolution.go — lazy var/jinja resolution: the Vars view over the
// merged vars maps ({{ }} resolved on demand with cycle detection,
// same net effect as ansible's late binding) plus NewEnv, the
// render-time lookup hooks the resolution runs under.
package topology

import (
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-host-agent/internal/platform/jinja"
)

// Vars is a lazily-resolved view over the merged vars maps.
type Vars struct {
	raw       *OMap
	extra     map[string]any // interdc_nodes / interdc_dns_zone preloaded
	resolved  map[string]any
	resolving map[string]bool
	cur       string // var being resolved (for error attribution)
	errs      []string
	env       *Env
}

// Errors returns the accumulated resolution failures (eval errors,
// reference cycles). Consumers should surface these — ansible failed
// the converge on the same inputs.
func (v *Vars) Errors() []string { return v.errs }

func (v *Vars) get(name string) any {
	if x, ok := v.resolved[name]; ok {
		return x
	}
	if v.resolving[name] {
		v.errs = append(v.errs, "var "+name+": reference cycle")
		return jinja.NewUndefined(name + "(cycle)")
	}
	if x, ok := v.extra[name]; ok {
		// Preloaded files (interdc_nodes/interdc_dns_zone) go
		// through the same jinja resolution as defaults/cluster
		// values — they used to bypass it, so embedded {{ }}
		// never rendered. Cached under resolved like a raw var,
		// with the same cycle protection.
		v.resolving[name] = true
		prev := v.cur
		v.cur = name
		v.resolved[name] = v.resolve(x)
		v.cur = prev
		delete(v.resolving, name)
		return v.resolved[name]
	}
	rv, ok := v.raw.Get(name)
	if !ok {
		return jinja.NewUndefined(name)
	}
	v.resolving[name] = true
	prev := v.cur
	v.cur = name
	v.resolved[name] = v.resolve(rv)
	v.cur = prev
	delete(v.resolving, name)
	return v.resolved[name]
}

func (v *Vars) resolve(x any) any {
	switch t := x.(type) {
	case string:
		if strings.Contains(t, "{{") || strings.Contains(t, "{%") || strings.Contains(t, "{#") {
			out, err := jinja.RenderScoped(t, v.env, v.get)
			if err != nil {
				// Fail-closed: raw {{...}} text written into rendered
				// config files is worse than undefined — record and
				// return Undefined (falsy, default()-able).
				v.errs = append(v.errs,
					"var "+v.cur+": eval failed: "+err.Error())
				return jinja.NewUndefined(v.cur)
			}
			return out
		}
		return t
	case *OMap:
		m := NewOMap()
		for _, k := range t.Keys() {
			vv, _ := t.Get(k)
			m.Set(k, v.resolve(vv))
		}
		return m
	case *List:
		out := &List{V: make([]any, len(t.V))}
		for i, x := range t.V {
			out.V[i] = v.resolve(x)
		}
		return out
	case []any:
		out := make([]any, len(t))
		for i, x := range t {
			out[i] = v.resolve(x)
		}
		return out
	}
	return x
}

// Accessors.
func (v *Vars) Get(name string) any { return v.get(name) }

func (v *Vars) Str(name string) string { return jinja.Stringify(v.get(name)) }

func (v *Vars) Bool(name string) bool { return jinja.Truthy(v.get(name)) }

func (v *Vars) Int(name string) int64 {
	i, _ := jinja.ToInt(v.get(name))
	return i
}

func (v *Vars) List(name string) []any { return jinja.ToIter(v.get(name)) }

func (v *Vars) StrList(name string) []string {
	var out []string
	for _, it := range v.List(name) {
		out = append(out, jinja.Stringify(it))
	}
	return out
}

// NewEnv builds the render-time lookup hooks rooted at varsDir:
// lookup('file', p) reads filepath.Base(p) inside varsDir (the
// ansible convention of resolving file lookups against the vars dir)
// and lookup('pipe', 'date +%s') returns the unix epoch (nowFn
// injectable for tests; nil → time.Now). No other pipe command is
// honoured.
func NewEnv(varsDir string, nowFn func() time.Time) *Env {
	return &Env{
		FileLookup: func(p string) (string, error) {
			b, err := os.ReadFile(filepath.Join(varsDir, filepath.Base(p)))
			return string(b), err
		},
		PipeLookup: func(cmd string) (string, error) {
			if strings.TrimSpace(cmd) == "date +%s" {
				now := time.Now()
				if nowFn != nil {
					now = nowFn()
				}
				return strconv.FormatInt(now.Unix(), 10), nil
			}
			return "", fmt.Errorf("unsupported pipe lookup %q", cmd)
		},
	}
}
