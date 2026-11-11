// group_gomemlimit.go — the gomemlimit-sum GOMEMLIMIT sum guard for
// k0scontroller (split out of group_base.go — pure move, same
// package).
package hostconfig

import (
	"fmt"
	"regexp"
	"strconv"
	"strings"

	"github.com/passiontech-global/kubernetes-cluster-automation/libs/jinja"
)

// ---------- gomemlimit-sum: k0scontroller GOMEMLIMIT sum guard ----------

// goMemlimitSiblingReserve is the budget the OTHER k0scontroller
// children need inside MemoryMax while the capped child sits at
// GOMEMLIMIT: etcd/kine ~0.9-1.5G + kcm/scheduler ~0.6G +
// konnectivity + non-heap/cgroup overhead (the cicd 2026-10-22..25
// incident shape: 2.4G apiserver + ~2.3G siblings on a 5G unit).
// It bounds the guard at MemoryMax-2GiB, which keeps BOTH documented
// sizing anchors feasible: 2900MiB <= 5G-2G on cicd and ~4500MiB <=
// 7G-2G on the kine-split clusters.
const goMemlimitSiblingReserve = 2 << 30 // 2 GiB

// goMemlimitGuardDropIn is the override file — it sorts AFTER
// 51-go-memlimit.conf lexically, so an Environment=GOMEMLIMIT it
// carries wins over the per-host value only while the guard needs
// to clamp; when the configured value is safe the file is removed
// and 51- stands alone.
const goMemlimitGuardDropIn = "/etc/systemd/system/k0scontroller.service.d/52-go-memlimit-sumguard.conf"

// k0scontrollerGoMemlimitSumGuard is the cgroup-OOMKill side of
// gomemlimit-sum. GOMEMLIMIT is a PER-PROCESS soft cap systemd plants on
// every Go child of k0scontroller.service (kube-apiserver, kine or
// etcd, kube-controller-manager, kube-scheduler,
// konnectivity-server) — no single child's GC ever sees the
// aggregate. If a configured cap leaves less than
// goMemlimitSiblingReserve for the siblings, the SUM of children
// RSS can overrun MemoryMax and the cgroup OOM-kills the whole unit
// (API down 20-45s — fatal on single-controller clusters). The
// guard renders/removes 52-go-memlimit-sumguard.conf:
//
//   - gomemlimit <= MemoryMax - reserve → drop-in removed, the
//     51-go-memlimit.conf value stands;
//   - gomemlimit > cap → drop-in written with the clamped value
//     (its lexical position overrides 51-'s Environment=);
//   - either var missing/unparseable → drop-in removed, nothing to
//     clamp against (fail-open: the per-host maps are the intent).
func (c *cyc) k0scontrollerGoMemlimitSumGuard() {
	r := c.r
	memMaxOm, _ := c.t.Vars.Get("k0scontroller_memory_max_by_host").(*jinja.OMap)
	limitOm, _ := c.t.Vars.Get("k0scontroller_go_memlimit_by_host").(*jinja.OMap)
	memMax, maxOK := parseByteSize(memMaxOm.Str(r.cfg.NodeName))
	limit, limOK := parseByteSize(limitOm.Str(r.cfg.NodeName))
	capBytes := memMax - goMemlimitSiblingReserve
	if !maxOK || !limOK || capBytes <= 0 || limit <= capBytes {
		if ch, _ := r.removeManaged(goMemlimitGuardDropIn); ch {
			r.daemonReload(c.ctx)
		}
		return
	}
	clamped := capBytes / (1 << 20) // floor to whole MiB
	logger().Warn("base: k0scontroller GOMEMLIMIT exceeds MemoryMax-"+
		"2GiB sibling reserve — clamping (a single child's soft cap "+
		"must leave room for the other unit children)",
		"configured", limitOm.Str(r.cfg.NodeName),
		"memory_max", memMaxOm.Str(r.cfg.NodeName),
		"clamped_mib", clamped)
	if ch, _ := r.writeManaged(goMemlimitGuardDropIn,
		[]byte(fmt.Sprintf(`# Managed by node-config-agent - gomemlimit-sum GOMEMLIMIT sum guard
# The configured cap leaves < 2GiB for the unit's other children
# (etcd/kine + kcm + scheduler + konnectivity + non-heap). Sum of
# children RSS must stay under MemoryMax or the cgroup OOM-kills
# the whole control-plane unit. Overrides 51-go-memlimit.conf.
[Service]
Environment=GOMEMLIMIT=%dMiB
`, clamped)), 0o644); ch {
		r.daemonReload(c.ctx)
	}
}

// byteSizeRe parses systemd/Go memory quantities — "7G", "512M",
// "2900MiB", "5GB", "1500MiB", bare bytes.
var byteSizeRe = regexp.MustCompile(`^([0-9]+(?:\.[0-9]+)?)\s*([KMGT](?:i?B)?|B)?$`)

// parseByteSize parses a size string into bytes. K/M/G/T (and their
// *iB/*B forms) are powers of 1024 — the systemd convention both
// MemoryMax and GOMEMLIMIT follow.
func parseByteSize(s string) (int64, bool) {
	m := byteSizeRe.FindStringSubmatch(strings.TrimSpace(s))
	if m == nil {
		return 0, false
	}
	num, err := strconv.ParseFloat(m[1], 64)
	if err != nil || num < 0 {
		return 0, false
	}
	suffix := strings.ToUpper(m[2])
	suffix = strings.TrimSuffix(suffix, "IB") // "GiB"→"G", "KiB"→"K", "MiB"→"M"
	suffix = strings.TrimSuffix(suffix, "B")  // "GB"→"G", "B"→""
	var mult float64
	switch suffix {
	case "":
		mult = 1
	case "K":
		mult = 1 << 10
	case "M":
		mult = 1 << 20
	case "G":
		mult = 1 << 30
	case "T":
		mult = 1 << 40
	default:
		return 0, false
	}
	return int64(num * mult), true
}
