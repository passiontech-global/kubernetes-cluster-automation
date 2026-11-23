// kernel_drift.go — Wave-4 #9: Host Kernel Drift Guard (THP + rp_filter).
//
// Monitors transparent_hugepage/{enabled,defrag} under <HostRoot>/sys
// and net.ipv4.conf.{all,default,<neb*|cilium_*|lxc*>}.rp_filter under
// <ProcRoot>/sys/net/ipv4/conf:
//   - THP targets: enabled=madvise, defrag=defer+madvise by default
//     (precedence: Deps.THPEnabled/THPDefrag > VarsDir host_thp_* >
//     DefaultTHPEnabled/DefaultTHPDefrag).
//   - rp_filter targets: "0" on all, default, and overlay/CNI
//     interfaces (neb*, nebula*, cilium_*, lxc*). Linux computes
//     max(conf.all.rp_filter, conf.<dev>.rp_filter), so all must stay
//     "0" or it overrides per-interface CNI/overlay settings and breaks
//     Cilium eBPF/netkit traffic. Physical NICs are ignored.
//
// When KernelDriftHeal is true, drifted targets are healed via
// RunHostCmd (PID-1 mount/net namespaces — never direct os.WriteFile
// on /host/sys which is read-only in DaemonSet mode) and logged as
// ACTION: lines. A single transient drift cycle attempts heal without
// raising LatchHostKernelDrift; if drift persists for >= 2 consecutive
// cycles, ensureStateLatch sets state-host-kernel-drift and logs
// STATE-ENTER. When all readable targets converge, Store.Exit clears
// the latch cleanly. Zero readable targets is treated as inconclusive
// (never clears an existing latch or resets streak).
package kernelfail

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-host-agent/internal/latchdefs"
)

const (
	// DefaultTHPEnabled / DefaultTHPDefrag are the compiled target
	// transparent_hugepage postures shared with hostconfig.
	DefaultTHPEnabled = "madvise"
	DefaultTHPDefrag  = "defer+madvise"

	kernelDriftConfirmTicks = 2
	thpSysfsPrefix          = "/sys/kernel/mm/transparent_hugepage/"
)

type kernelDriftKind string

const (
	driftKindTHP      kernelDriftKind = "thp"
	driftKindRPFilter kernelDriftKind = "rp_filter"
)

type kernelDriftItem struct {
	kind      kernelDriftKind
	key       string // "enabled"/"defrag" or iface name
	got       string
	want      string
	sysfsPath string // host PID-1 ns path for THP
}

// parseBracketedSysfs extracts the active [bracketed] option from a
// sysfs file (e.g. "always [madvise] never\n" -> "madvise"). Falls
// back to a single bare token when unbracketed; returns ("", false) on
// empty or ambiguous multi-token output.
func parseBracketedSysfs(data []byte) (string, bool) {
	fields := strings.Fields(string(data))
	for _, tok := range fields {
		if len(tok) > 2 && tok[0] == '[' && tok[len(tok)-1] == ']' {
			return tok[1 : len(tok)-1], true
		}
	}
	if len(fields) == 1 {
		return fields[0], true
	}
	return "", false
}

// isOverlayCNIIface reports whether name is an overlay or CNI
// interface whose rp_filter must stay 0 to avoid asymmetric-routing
// drops (neb* covers both neb1 and nebula*).
func isOverlayCNIIface(name string) bool {
	return strings.HasPrefix(name, "neb") ||
		strings.HasPrefix(name, "cilium_") ||
		strings.HasPrefix(name, "lxc")
}

// isSafeSysctlToken restricts target values and interface names before
// passing them to RunHostCmd (sh -c / sysctl -w).
func isSafeSysctlToken(s string) bool {
	if s == "" {
		return false
	}
	for i := 0; i < len(s); i++ {
		c := s[i]
		if !((c >= 'A' && c <= 'Z') ||
			(c >= 'a' && c <= 'z') ||
			(c >= '0' && c <= '9') ||
			c == '.' || c == '_' || c == '+' || c == '-') {
			return false
		}
	}
	return true
}

// THPTargets resolves the active transparent_hugepage target posture
// using the same precedence as hostconfig: explicit Deps/env override
// > VarsDir (host_thp_enabled / host_thp_defrag) > compiled defaults
// (DefaultTHPEnabled / DefaultTHPDefrag). Safe for concurrent calls.
func (r *Runner) THPTargets() (enabled, defrag string) {
	wantEnabled := strings.TrimSpace(r.deps.THPEnabled)
	wantDefrag := strings.TrimSpace(r.deps.THPDefrag)
	if (wantEnabled == "" || wantDefrag == "") && r.deps.VarsDir != "" {
		varEnabled, varDefrag := r.thpVars.get(r.deps.VarsDir, r.deps.NodeName, r.deps.Clock)
		if wantEnabled == "" {
			wantEnabled = varEnabled
		}
		if wantDefrag == "" {
			wantDefrag = varDefrag
		}
	}
	if wantEnabled == "" {
		wantEnabled = DefaultTHPEnabled
	}
	if wantDefrag == "" {
		wantDefrag = DefaultTHPDefrag
	}
	return wantEnabled, wantDefrag
}

func (r *Runner) collectKernelDrift() (drifts []kernelDriftItem, readable int) {
	hostRoot := r.deps.HostRoot
	if hostRoot == "" {
		hostRoot = "/"
	}
	wantEnabled, wantDefrag := r.THPTargets()

	for _, knob := range []struct {
		name string
		want string
	}{
		{"enabled", wantEnabled},
		{"defrag", wantDefrag},
	} {
		p := filepath.Join(hostRoot, "sys", "kernel", "mm", "transparent_hugepage", knob.name)
		data, err := os.ReadFile(p)
		if err != nil {
			continue
		}
		cur, ok := parseBracketedSysfs(data)
		if !ok {
			continue
		}
		readable++
		if cur != knob.want {
			drifts = append(drifts, kernelDriftItem{
				kind:      driftKindTHP,
				key:       knob.name,
				got:       cur,
				want:      knob.want,
				sysfsPath: thpSysfsPrefix + knob.name,
			})
		}
	}

	procRoot := r.deps.ProcRoot
	if procRoot == "" {
		procRoot = "/proc"
	}
	confDir := filepath.Join(procRoot, "sys", "net", "ipv4", "conf")
	ents, err := os.ReadDir(confDir)
	if err == nil {
		for _, e := range ents {
			if !e.IsDir() && e.Type()&os.ModeSymlink == 0 {
				continue
			}
			name := e.Name()
			var want string
			switch {
			case name == "all" || name == "default" || isOverlayCNIIface(name):
				want = "0"
			default:
				continue
			}
			data, rerr := os.ReadFile(filepath.Join(confDir, name, "rp_filter"))
			if rerr != nil {
				continue
			}
			cur := strings.TrimSpace(string(data))
			if cur == "" {
				continue
			}
			readable++
			if cur != want {
				drifts = append(drifts, kernelDriftItem{
					kind: driftKindRPFilter,
					key:  name,
					got:  cur,
					want: want,
				})
			}
		}
	}

	return drifts, readable
}

func (r *Runner) logKernelDriftAction(msg string) {
	if r.deps.Store != nil {
		r.deps.Store.AppendLog(latchdefs.ActionPrefix + msg)
		return
	}
	logger().Info(latchdefs.ActionPrefix + msg)
}

func formatKernelDriftEvidence(drifts []kernelDriftItem) string {
	parts := make([]string, 0, len(drifts))
	for _, d := range drifts {
		parts = append(parts, fmt.Sprintf("%s.%s=%s!=%s", d.kind, d.key, d.got, d.want))
	}
	ev := strings.Join(parts, ", ")
	const maxEvidenceLen = 200
	if len(ev) > maxEvidenceLen {
		return ev[:maxEvidenceLen]
	}
	return ev
}

func (r *Runner) updateKernelDrift(ctx context.Context) {
	drifts, readable := r.collectKernelDrift()
	if readable == 0 {
		// Inconclusive (missing sysfs/procfs): preserve streak and any held latch.
		return
	}
	if len(drifts) == 0 {
		r.kernelDriftStreak = 0
		if r.deps.Store != nil {
			r.deps.Store.Exit(latchdefs.LatchHostKernelDrift, nil)
		}
		return
	}

	if r.deps.KernelDriftHeal {
		for _, d := range drifts {
			if !isSafeSysctlToken(d.want) || (d.kind == driftKindRPFilter && !isSafeSysctlToken(d.key)) {
				logger().Warn("hostmetrics: kernel drift heal skipped unsafe token",
					"kind", string(d.kind), "key", d.key, "want", d.want)
				continue
			}
			switch d.kind {
			case driftKindTHP:
				// RunHostCmd executes in PID-1 mount ns (NSAll); never os.WriteFile /host/sys.
				if out, err := r.deps.RunHostCmd(ctx, "sh", "-c", "printf '%s' \"$1\" > \"$2\"", "sh", d.want, d.sysfsPath); err != nil {
					logger().Warn("hostmetrics: THP drift heal failed",
						"key", d.key, "want", d.want, "out", out, "error", err)
				} else {
					r.logKernelDriftAction(fmt.Sprintf("healed THP %s %s->%s", d.key, d.got, d.want))
				}
			case driftKindRPFilter:
				kv := fmt.Sprintf("net.ipv4.conf.%s.rp_filter=%s", d.key, d.want)
				if out, err := r.deps.RunHostCmd(ctx, "sysctl", "-w", kv); err != nil {
					logger().Warn("hostmetrics: rp_filter drift heal failed",
						"key", d.key, "want", d.want, "out", out, "error", err)
				} else {
					r.logKernelDriftAction(fmt.Sprintf("healed %s (was %s)", kv, d.got))
				}
			}
		}
	}

	r.kernelDriftStreak++
	if r.kernelDriftStreak >= kernelDriftConfirmTicks && r.deps.Store != nil {
		latchName := latchdefs.LatchFilePrefix + latchdefs.LatchHostKernelDrift
		r.ensureStateLatch(r.statePath(latchName), latchName, formatKernelDriftEvidence(drifts))
	}
}
