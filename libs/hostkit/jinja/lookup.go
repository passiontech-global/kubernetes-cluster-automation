// lookup.go — the ansible lookup() plugin dispatch (file/pipe),
// resolved against the render-time Env hooks.
package jinja

import (
	"errors"
	"fmt"
)

// ---------------- lookup ----------------

// doLookup mirrors ansible's lookup() — fail-loud: a lookup that
// cannot be honoured (unknown plugin, missing term, no env hook)
// errors the render instead of silently emitting "", which would let
// a missing file converge to an empty config value.
func doLookup(args []any, s *scope) (any, error) {
	if len(args) == 0 {
		return nil, errors.New("lookup: missing plugin name")
	}
	kind := Stringify(args[0])
	switch kind {
	case "file", "ansible.builtin.file":
		if len(args) < 2 {
			return nil, fmt.Errorf("lookup(%q): missing file path", kind)
		}
		if s.env == nil || s.env.FileLookup == nil {
			return nil, fmt.Errorf("lookup(%q): no file lookup configured", kind)
		}
		return s.env.FileLookup(Stringify(args[1]))
	case "pipe", "ansible.builtin.pipe":
		if len(args) < 2 {
			return nil, fmt.Errorf("lookup(%q): missing command", kind)
		}
		if s.env == nil || s.env.PipeLookup == nil {
			return nil, fmt.Errorf("lookup(%q): no pipe lookup configured", kind)
		}
		return s.env.PipeLookup(Stringify(args[1]))
	}
	return nil, fmt.Errorf("lookup: unsupported plugin %q", kind)
}
