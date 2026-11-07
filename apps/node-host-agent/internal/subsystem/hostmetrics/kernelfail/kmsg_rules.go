// kmsg_rules.go — the classifier half of W10-KR1 checkKernelDmesg:
// the kernel-message detector regexes, the cross-line OOM pairing
// context and the line→detector dispatch. This file answers "what
// does this message mean"; the plumbing it dispatches into (the
// kmsg session/cursor machinery, the marker writes, the dmesg
// fallback, the conntrack sysctl bump) stays in kmsg.go. The
// Wave-10 contract overview lives in kernelfail.go.
package kernelfail

import (
	"regexp"
	"strings"
)

// --- kernel-message detectors (W10-KR1) ---

var (
	// Filesystem/block error signatures — the plan's literal set.
	fsErrorRe = regexp.MustCompile(
		`blk_update_request: I/O error|Buffer I/O error on dev|` +
			`EXT4-fs error|XFS \([^)]*\): Metadata I/O error|XFS_ERROR`)
	// nf_conntrack table-full — packets are being DROPPED.
	conntrackFullRe = regexp.MustCompile(`nf_conntrack: table full`)
	// "Out of memory: Killed process <pid> (<comm>) ..." — global
	// OOM — and "Memory cgroup out of memory: Killed process ..."
	// — the memcg variant the kernel prints for cgroup OOMs, which
	// is the COMMON case under kubepods pressure.
	oomKillRe = regexp.MustCompile(
		`(?i)(?:memory cgroup )?out of memory: killed process \d+ \(([^)]+)\)`)
	// The constraint line printed just before the kill line —
	// carries oom_memcg/task_memcg, the cgroup verdict's evidence.
	oomConstraintRe = regexp.MustCompile(`oom-kill:constraint=`)
	oomMemcgRe      = regexp.MustCompile(`(?:oom_memcg|task_memcg)=([^\s,]+)`)
	oomTaskRe       = regexp.MustCompile(`(?:^|,)task=([^\s,]+)`)
	// W13-KR1: higher-order page allocation failure — the buddy
	// allocator can't find a contiguous order>=1 block for
	// sk_buff/WireGuard/XFS even while MemAvailable stays high.
	// order:0 failures are routine pressure noise; order:[1-9] is
	// the fragmentation signature workerhygiene defragments via
	// vm.compact_memory.
	pageAllocFailRe = regexp.MustCompile(`page allocation failure: order:[1-9]`)
)

// oomKillCtx is the pending constraint-line state — the kernel prints
// "oom-kill:constraint=..." immediately before "Out of memory:
// Killed process ..."; the pair classifies one kill event.
type oomKillCtx struct {
	memcg string // first memcg path seen (oom_memcg preferred)
	comm  string // task= comm when present
}

// classifyKernelLine feeds one kernel message into the detectors.
// Order matters: the oom-kill constraint line is captured as pending
// context for the kill line that follows it.
func (r *Runner) classifyKernelLine(msg string, st *kernelScanState) {
	switch {
	case oomConstraintRe.MatchString(msg):
		st.oomPending = parseOOMConstraint(msg)
	case oomKillRe.MatchString(msg):
		r.noteHostOOMKill(msg, st)
	case fsErrorRe.MatchString(msg):
		r.noteKernelFsError(msg)
	case conntrackFullRe.MatchString(msg):
		r.noteConntrackFull()
	case pageAllocFailRe.MatchString(msg):
		r.notePageAllocFailure(msg)
	}
}

// parseOOMConstraint extracts the memcg + task fields from an
// "oom-kill:constraint=..." line.
func parseOOMConstraint(msg string) *oomKillCtx {
	ctx := &oomKillCtx{}
	if m := oomMemcgRe.FindStringSubmatch(msg); m != nil {
		ctx.memcg = m[1]
	}
	if m := oomTaskRe.FindStringSubmatch(msg); m != nil {
		ctx.comm = m[1]
	}
	return ctx
}

// isHostOOMComm reports whether comm names a host-level daemon —
// the containerd/k0s/kubelet set plus the W13-KR1 infra daemons
// (nebula, haproxy on the api-lb VM, the coredns host stub, the
// postgres/pgbouncer pair on db-vm, every cilium daemon and the
// agent itself) whose kernel-OOM death is as load-bearing as the
// kubelet's. comm is TASK_COMM_LEN truncated (15 chars), so
// prefix/substring matching is required ("cilium-operator" and
// "node-host-agent" are exactly 15).
func isHostOOMComm(comm string) bool {
	switch comm {
	case "kubelet", "nebula", "haproxy", "coredns", "postgres",
		"pgbouncer", "node-host-agent":
		return true
	}
	return strings.HasPrefix(comm, "k0s") ||
		strings.HasPrefix(comm, "cilium-") ||
		strings.Contains(comm, "containerd")
}

func ctxMemcg(ctx *oomKillCtx) string {
	if ctx == nil {
		return ""
	}
	return ctx.memcg
}
