// exports.go — the jinja engine surface re-exported under
// topology.* so pre-split consumers compile unchanged.
package topology

import (
	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-host-agent/internal/platform/jinja"
)

// ---- re-exported jinja engine surface ----
//
// The mini-Jinja2 evaluator + its ordered-map/YAML values live in
// internal/platform/jinja. These aliases and thin forwarders keep
// the historical topology.X API so consumers (hostconfig, hubsync,
// ops/nebulasign, workerhygiene) compile unchanged.
type (
	// OMap is an insertion-ordered string-keyed map (see jinja.OMap).
	OMap = jinja.OMap
	// List wraps a slice so in-place mutation behaves like python
	// lists across scope bindings (see jinja.List).
	List = jinja.List
	// Undefined is the jinja `undefined` — falsy, default()-able
	// (see jinja.Undefined).
	Undefined = jinja.Undefined
	// Env carries render-time hooks (see jinja.Env).
	Env = jinja.Env
)

// NewOMap returns an empty insertion-ordered map (see jinja.NewOMap).
func NewOMap() *OMap { return jinja.NewOMap() }

// DecodeYAML parses a YAML document into jinja values (see
// jinja.DecodeYAML).
func DecodeYAML(data []byte) (any, error) { return jinja.DecodeYAML(data) }

// Render evaluates template text against ctx (see jinja.Render).
func Render(text string, ctx map[string]any, env *Env) (string, error) {
	return jinja.Render(text, ctx, env)
}
