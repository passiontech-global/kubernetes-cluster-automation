// ctr_shims.go — the containerd-shim scope machinery shared by the
// ctr-tasks reaper (31) and the ctr-meta orphan-shim sweep
// (meta-db-corruption): which containerd-shim-runc-v2 processes belong to the
// containerd instance this agent watches, and where their task dirs
// live. The scope test is deliberately fail-closed — an
// unidentifiable shim is foreign, never a kill candidate.
package ctr

import (
	"os"
	"path/filepath"
	"regexp"
	"strings"

	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-host-agent/internal/subsystem/workerhygiene/wdeps"
	"github.com/passiontech-global/kubernetes-cluster-automation/libs/hostkit/fsx"
)

var (
	// `containerd-shim-runc-v2 ... -id <64hex>` — orphan-shim task id
	// extraction (shell sed pattern).
	shimIDRe = regexp.MustCompile(`-id ([0-9a-f]{64})`)
)

// procCommKnown returns the pid's comm when the cycle's stat
// snapshot (StatsOnce, or a direct stat for hand-built envs)
// positively identifies it — known=false means "cannot rule the
// pid out", and callers take the old full-read path. The shim
// scans use it to skip the mm-backed cmdline read for every
// non-shim pid.
func procCommKnown(e *wdeps.CycleEnv, d *wdeps.Deps, pid int) (comm string, known bool) {
	if e != nil && e.StatsOnce != nil {
		if st, ok := e.StatsOnce()[pid]; ok && st.HasComm {
			return st.Comm, true
		}
		return "", false
	}
	if st, ok := d.Proc.Stat(pid); ok && st.HasComm {
		return st.Comm, true
	}
	return "", false
}

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
	if s := normalizeCtrAddr(fsx.HostSidePath(d.Cfg.CtrSocket)); s != "" {
		out[s] = true
	}
	derived := filepath.Join(
		filepath.Dir(filepath.Dir(filepath.Dir(d.Cfg.CtrTaskRoot))),
		"containerd.sock")
	if s := normalizeCtrAddr(fsx.HostSidePath(derived)); s != "" {
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

// relInside reports target's path relative to base, ok=false when
// target escapes base (".." segments) or equals it — the containment
// gate every fd-path scope check runs before trusting a component.
func relInside(base, target string) (string, bool) {
	rel, err := filepath.Rel(base, target)
	if err != nil || rel == "." || rel == ".." ||
		strings.HasPrefix(rel, ".."+string(filepath.Separator)) {
		return "", false
	}
	return rel, true
}

// dzShimScope is the D/Z-state fallback for the shim scan: a wedged
// shim's cmdline is mm-backed and unreadable (the read would hang
// on mmap_lock — the D-state deadlock the procfs guard exists for),
// but its stat comm and open-fd readlinks are mmap_lock-free. The
// shim keeps fds into its task dir — <taskParent>/<ns>/<64hex>/…
// (or <CtrTaskRoot>/<sid>/… for k8s.io) — and the path's root doubles
// as the -address scope proof: a foreign containerd's shim holds fds
// under ITS root, never ours. ok=false for non-D/Z states, non-shim
// comms, or no fd evidence — an unverifiable shim is never
// escalated (fail closed, same posture as ctrShimScope).
func dzShimScope(d *wdeps.Deps, pid int) (ns, sid string, ok bool) {
	ns, sid, ok, _ = dzShimScopeChecked(d, pid)
	return ns, sid, ok
}

func dzShimScopeChecked(d *wdeps.Deps, pid int) (ns, sid string, ok, inconclusive bool) {
	st, sok := d.Proc.Stat(pid)
	if !sok || !st.HasComm ||
		!strings.HasPrefix(st.Comm, "containerd-shim") ||
		(st.Fields[0] != "D" && st.Fields[0] != "Z") {
		return "", "", false, false
	}
	if d.Cfg.CtrTaskRoot == "" {
		return "", "", false, false
	}
	hostTaskRoot := fsx.HostSidePath(d.Cfg.CtrTaskRoot)
	if hostTaskRoot == "" {
		return "", "", false, false
	}
	fdDir := d.Proc.File(pid, "fd")
	fds, err := os.ReadDir(fdDir)
	if err != nil {
		return "", "", false, !os.IsNotExist(err)
	}
	taskParent := filepath.Dir(hostTaskRoot)
	fdReadErr := false
	for _, fd := range fds {
		target, err := os.Readlink(filepath.Join(fdDir, fd.Name()))
		if err != nil {
			if !os.IsNotExist(err) {
				fdReadErr = true
			}
			continue
		}
		// An orphan's task dir is already unlinked — the readlink
		// target keeps the path with a " (deleted)" suffix.
		target = strings.TrimSuffix(target, " (deleted)")
		// k8s.io task dir: <hostTaskRoot>/<sid>/…
		if rel, inside := relInside(hostTaskRoot, target); inside {
			if parts := strings.Split(rel, string(filepath.Separator)); len(parts) >= 1 && hexTaskIDRe.MatchString(parts[0]) {
				return "k8s.io", parts[0], true, false
			}
			continue
		}
		// Foreign namespace on the same containerd:
		// <taskParent>/<ns>/<sid>/…
		rel, inside := relInside(taskParent, target)
		if !inside {
			continue
		}
		parts := strings.Split(rel, string(filepath.Separator))
		if len(parts) < 2 || !validShimNamespace(parts[0]) ||
			!hexTaskIDRe.MatchString(parts[1]) {
			continue
		}
		return parts[0], parts[1], true, false
	}
	return "", "", false, fdReadErr
}
