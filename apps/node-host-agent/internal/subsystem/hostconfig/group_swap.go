// group_swap.go — swap safety-net group ported from hub_converge.yaml
// (tasks/node_tuning_swap.yaml): per-class swapfile + swappiness
// converge on controllers and the kine DB VMs.
package hostconfig

import (
	"fmt"
	"os"
	"regexp"
	"strings"

	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-host-agent/internal/domain/topology"
)

// ---------- swap (node_tuning_swap.yaml) ----------
//
// Swap is a transient OOM buffer, not real capacity (incident
// 2026-10-02: kine fill debt > cgroup MemoryMax -> metastable OOM
// loop; with swap, hitting memory.max swaps out instead of
// OOM-killing so guards get a window to run):
//   - k0s controllers        -> kine_swap_size_mb (default 12288)
//   - node_exporter_extra_hosts entries with kine_db: true
//                            -> db_swap_size_mb (default 2048)
//   - everything else        -> no swapfile managed

// The ansible include pinned the swapfile path + swappiness per
// class: controllers got swap_path=/swapfile-kine + swappiness 60
// (12G kine-boot buffer); the kine DB include passed NO swap_path
// (the task's /swapfile default) + swappiness 10. Sharing
// /swapfile-kine on the DB VM created a second 2G file + fstab line
// next to the existing /swapfile — 4G total and an orphaned fstab
// entry.
const (
	kineSwapPath = "/swapfile-kine"
	dbSwapPath   = "/swapfile"
)

func (c *cyc) groupSwap() {
	var mb int64
	var path, swDef string
	switch {
	case c.controller():
		mb = c.vi("kine_swap_size_mb")
		if mb <= 0 {
			mb = 12288
		}
		path = kineSwapPath
		swDef = "60" // ansible: swap_swappiness 60 on controllers
	case c.kineDBHost():
		mb = c.vi("db_swap_size_mb")
		if mb <= 0 {
			mb = 2048
		}
		path = dbSwapPath
		swDef = "10" // ansible: swap_swappiness 10 on the kine DB VM
	default:
		return
	}
	// swap_swappiness stays a cluster.yaml override; the default is
	// per-class (60 controller / 10 db — a shared 10 regressed the
	// controller tunable the ansible include set to 60).
	c.ensureSwapfile(path, mb, defStr(c.v("swap_swappiness"), swDef))
}

// kineDBHost — this node's name matches a node_exporter_extra_hosts
// entry carrying kine_db: true (the pgbouncer/postgres SPOF VMs).
func (c *cyc) kineDBHost() bool {
	for _, it := range c.vl("node_exporter_extra_hosts") {
		m, _ := it.(*topology.OMap)
		if m == nil {
			continue
		}
		if strOf(m, "name") != c.r.cfg.NodeName {
			continue
		}
		if v, ok := m.Get("kine_db"); ok {
			switch t := v.(type) {
			case bool:
				return t
			case string:
				return t == "true" || t == "True" || t == "yes" || t == "1"
			case int64:
				return t != 0
			}
			return v != nil
		}
		return false // kine_db unset -> item.kine_db | default(false)
	}
	return false
}

// ensureSwapfile ports node_tuning_swap.yaml: idempotent create
// (fallocate, dd fallback), 0600, mkswap only when blkid sees no swap
// signature, fstab line, swapon, and the swappiness drop-in (sw is
// the caller's per-class value). A file at the wrong size is
// recreated ONLY while not active — an active swapfile is never
// deleted out from under the kernel.
func (c *cyc) ensureSwapfile(path string, mb int64, sw string) {
	r, ctx := c.r, c.ctx
	wantBytes := mb * 1048576
	dst := r.hp(path)
	fi, statErr := os.Stat(dst)
	exists := statErr == nil

	activeOut, activeErr := r.run(ctx, "swapon", "--show=NAME", "--noheadings")
	if activeErr != nil {
		// Fail closed: with no probe result we cannot tell whether the
		// file is live swap — removing/recreating an ACTIVE swapfile
		// pulls the kernel's swap target out from under it. Skip the
		// cycle instead of guessing inactive.
		c.err("swap: swapon --show failed — cannot determine active state; skipping cycle",
			"path", path, "error", activeErr)
		return
	}
	// exact NAME-column match — a substring probe would mark /swapfile
	// active just because /swapfile-kine is listed (independent files).
	active := false
	for _, name := range strings.Split(activeOut, "\n") {
		if strings.TrimSpace(name) == path {
			active = true
			break
		}
	}

	if exists && fi.Size() != wantBytes && !active {
		logger().Info("swap: removing wrong-size inactive file", "path", path,
			"size", fi.Size(), "want", wantBytes)
		if err := os.Remove(dst); err != nil {
			c.err("swap: remove wrong-size file", "path", path, "error", err)
			return
		}
		exists = false
	}
	if !exists {
		if _, err := r.run(ctx, "fallocate", "-l", fmt.Sprintf("%dM", mb), path); err != nil {
			// Best-effort primary path — dd below is the fallback;
			// only its failure counts.
			logger().Warn("swap: fallocate failed — dd fallback", "path", path, "error", err)
			if _, derr := r.run(ctx, "dd", "if=/dev/zero", "of="+path, "bs=1M",
				fmt.Sprintf("count=%d", mb), "status=none"); derr != nil {
				c.err("swap: dd create failed", "path", path, "error", derr)
				return
			}
		}
	}
	if err := os.Chmod(dst, 0o600); err != nil {
		c.err("swap: chmod 0600 failed", "path", path, "error", err)
		return
	}
	out, _ := r.run(ctx, "blkid", "-o", "value", "-s", "TYPE", path)
	if strings.TrimSpace(out) != "swap" {
		if _, err := r.run(ctx, "mkswap", path); err != nil {
			c.err("swap: mkswap failed", "path", path, "error", err)
			return
		}
	}
	// fstab parity (lineinfile regexp '^<path>\s').
	want := path + " none swap sw 0 0"
	fstab, fstabErr := os.ReadFile(r.hp("/etc/fstab"))
	if fstabErr != nil && !os.IsNotExist(fstabErr) {
		// Best-effort pre-warning — a failed fstab write is counted
		// by writeManaged's noteErr below.
		logger().Warn("swap: cannot read /etc/fstab — swap fstab entry will fail",
			"error", fstabErr)
	}
	re := regexp.MustCompile(`(?m)^` + regexp.QuoteMeta(path) + `\s.*$`)
	var nf []byte
	if re.Match(fstab) {
		nf = re.ReplaceAll(fstab, []byte(want))
	} else {
		if len(fstab) > 0 && fstab[len(fstab)-1] != '\n' {
			fstab = append(fstab, '\n')
		}
		nf = append(fstab, []byte(want+"\n")...)
	}
	if string(nf) != string(fstab) {
		_, _ = r.writeManaged("/etc/fstab", nf, 0o644)
	}
	if !active {
		if _, err := r.run(ctx, "swapon", path); err != nil {
			c.err("swap: swapon failed — file exists but swap not active",
				"path", path, "error", err)
		}
	}
	_, _ = r.writeManaged("/etc/sysctl.d/99-kine-swap.conf",
		[]byte("# Managed by node-config-agent - swap safety-net (node_tuning_swap.yaml)\n"+
			"vm.swappiness = "+sw+"\n"), 0o644)
	r.actions.WithLabelValues("sysctl -w vm.swappiness").Inc()
	if _, err := r.run(ctx, "sysctl", "-w", "vm.swappiness="+sw); err != nil {
		c.err("swap: sysctl -w vm.swappiness failed — drop-in converged, live value unchanged",
			"value", sw, "error", err)
	}
}
