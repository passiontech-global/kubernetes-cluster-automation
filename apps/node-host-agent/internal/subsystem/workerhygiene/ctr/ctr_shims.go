// ctr_shims.go — the containerd-shim scope machinery shared by the
// ctr-tasks reaper (31) and the ctr-meta orphan-shim sweep
// (meta-db-corruption): which containerd-shim-runc-v2 processes belong to the
// containerd instance this agent watches, and where their task dirs
// live. The scope test is deliberately fail-closed — an
// unidentifiable shim is foreign, never a kill candidate.
package ctr

import (
	"path/filepath"
	"regexp"
	"strings"

	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-host-agent/internal/subsystem/workerhygiene/wdeps"
)

var (
	// `containerd-shim-runc-v2 ... -id <64hex>` — orphan-shim task id
	// extraction (shell sed pattern).
	shimIDRe = regexp.MustCompile(`-id ([0-9a-f]{64})`)
)

// shimFlagValue extracts `-name value` / `-name=value` (double-dash
// forms tolerated) from a shim argv. ok=false when the flag is absent
// or value-less.
func shimFlagValue(argv []string, name string) (string, bool) {
	for i, a := range argv {
		if a == "-"+name || a == "--"+name {
			if i+1 < len(argv) {
				return argv[i+1], true
			}
			return "", false
		}
		if v, ok := strings.CutPrefix(a, "-"+name+"="); ok {
			return v, true
		}
		if v, ok := strings.CutPrefix(a, "--"+name+"="); ok {
			return v, true
		}
	}
	return "", false
}

// hostSidePath maps an in-pod /host-mounted path back to the path a
// host process reports — the shim's -address carries the HOST socket
// path (/run/k0s/containerd.sock) while config paths live under the
// host-root mount (/host/run/k0s/containerd.sock).
func hostSidePath(p string) string {
	if rest, ok := strings.CutPrefix(p, "/host/"); ok {
		return "/" + rest
	}
	if p == "/host" {
		return "/"
	}
	return p
}

// normalizeCtrAddr canonicalizes a containerd grpc socket address so
// a cosmetic difference can't mark our own shim foreign: the unix://
// scheme and the /var/run symlink collapse to the canonical /run path.
func normalizeCtrAddr(a string) string {
	a = strings.TrimPrefix(a, "unix://")
	if a == "" {
		return ""
	}
	a = filepath.Clean("/" + strings.TrimPrefix(a, "/"))
	if rest, ok := strings.CutPrefix(a, "/var/run/"); ok {
		a = "/run/" + rest
	}
	return a
}

// ctrShimSockets returns the host-side socket paths the k0s
// containerd is expected to listen on: the configured
// ContainerdSocket plus the path derived from CtrTaskRoot
// (…/containerd/io.containerd.runtime.v2.task/k8s.io → the sibling
// …/k0s/containerd.sock — k0s keeps the socket next to the containerd
// root dir, not inside it).
func ctrShimSockets(d *wdeps.Deps) map[string]bool {
	out := map[string]bool{}
	if s := normalizeCtrAddr(hostSidePath(d.Cfg.CtrSocket)); s != "" {
		out[s] = true
	}
	derived := filepath.Join(
		filepath.Dir(filepath.Dir(filepath.Dir(d.Cfg.CtrTaskRoot))),
		"containerd.sock")
	if s := normalizeCtrAddr(hostSidePath(derived)); s != "" {
		out[s] = true
	}
	return out
}

// validShimNamespace guards the per-namespace task-dir join against
// path traversal — a shim cmdline is host-controlled input.
func validShimNamespace(ns string) bool {
	return ns != "" && ns != "." && ns != ".." &&
		!strings.ContainsAny(ns, "/\\")
}

// shimTaskDir resolves the task dir a shim of namespace ns + id would
// own under THIS containerd: k8s.io is CtrTaskRoot itself, a foreign
// namespace on the same daemon lives at the sibling
// io.containerd.runtime.v2.task/<ns>/<id> dir.
func shimTaskDir(d *wdeps.Deps, ns, id string) string {
	return filepath.Join(filepath.Dir(d.Cfg.CtrTaskRoot), ns, id)
}

// ctrShimScope parses a containerd-shim-runc-v2 argv and reports the
// task id + whether the shim belongs to the containerd instance this
// agent watches. A shim is in-scope only when BOTH flags are present
// AND -address names our containerd socket — a missing/unparseable
// flag means the instance can't be verified, so the shim is treated
// as foreign (fail closed: never reap an unidentified shim).
func ctrShimScope(d *wdeps.Deps, argv []string) (ns, sid string, inScope bool) {
	m := shimIDRe.FindStringSubmatch(strings.Join(argv, " "))
	if m == nil {
		return "", "", false
	}
	ns, nsOK := shimFlagValue(argv, "namespace")
	addr, addrOK := shimFlagValue(argv, "address")
	if !nsOK || !addrOK || !validShimNamespace(ns) {
		return "", "", false
	}
	if !ctrShimSockets(d)[normalizeCtrAddr(addr)] {
		return "", "", false
	}
	return ns, m[1], true
}
