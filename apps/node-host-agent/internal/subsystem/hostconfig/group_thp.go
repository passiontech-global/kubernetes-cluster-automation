// group_thp.go — Wave-4 #9: transparent_hugepage convergence
// (enabled=madvise, defrag=defer+madvise by default) via a persistent
// /etc/tmpfiles.d/ drop-in and live PID-1 mount-namespace sysfs writes.
package hostconfig

import (
	"fmt"
	"os"
	"strings"
)

const (
	defaultTHPEnabled = "madvise"
	defaultTHPDefrag  = "defer+madvise"
	thpEnabledPath    = "/sys/kernel/mm/transparent_hugepage/enabled"
	thpDefragPath     = "/sys/kernel/mm/transparent_hugepage/defrag"
	thpTmpfilesPath   = "/etc/tmpfiles.d/99-transparent-hugepage.conf"
)

// parseTHPActive extracts the active [bracketed] kernel option from a
// transparent_hugepage sysfs file (e.g. "always [madvise] never\n" ->
// "madvise"). Falls back to a single bare token when unbracketed;
// returns "" on empty or ambiguous multi-token output.
func parseTHPActive(raw string) string {
	fields := strings.Fields(raw)
	for _, tok := range fields {
		if len(tok) > 2 && tok[0] == '[' && tok[len(tok)-1] == ']' {
			return tok[1 : len(tok)-1]
		}
	}
	if len(fields) == 1 {
		return fields[0]
	}
	return ""
}

// thpTarget resolves target precedence: Config/env > cluster vars > compiled default.
func (c *cyc) thpTarget(cfgVal, varName, def string) string {
	if v := strings.TrimSpace(cfgVal); v != "" {
		return v
	}
	if c.t != nil {
		if v := strings.TrimSpace(c.v(varName)); v != "" {
			return v
		}
	}
	return def
}

// convergeTHP persists /etc/tmpfiles.d/99-transparent-hugepage.conf
// and converges live /sys/kernel/mm/transparent_hugepage/{enabled,defrag}
// via Runner (PID-1 mount ns under NsenterRunner) because DaemonSet
// mounts /host/sys readOnly: true.
func (c *cyc) convergeTHP() {
	r := c.r
	ctx := c.ctx

	wantEnabled := c.thpTarget(r.cfg.THPEnabled, "host_thp_enabled", defaultTHPEnabled)
	wantDefrag := c.thpTarget(r.cfg.THPDefrag, "host_thp_defrag", defaultTHPDefrag)

	// Gate both targets before rendering tmpfiles.d or invoking sh -c.
	if !c.shToken("host_thp_enabled", wantEnabled) || !c.shToken("host_thp_defrag", wantDefrag) {
		return
	}

	content := fmt.Sprintf(
		"# Managed by node-config-agent - transparent hugepage tuning\n"+
			"w %s - - - - %s\n"+
			"w %s - - - - %s\n",
		thpEnabledPath, wantEnabled, thpDefragPath, wantDefrag,
	)
	if ch, err := r.writeManaged(thpTmpfilesPath, []byte(content), 0o644); err == nil && ch {
		logger().Info("base: transparent hugepage tmpfiles persisted",
			"path", thpTmpfilesPath, "enabled", wantEnabled, "defrag", wantDefrag)
		if out, terr := r.run(ctx, "systemd-tmpfiles", "--create", thpTmpfilesPath); terr != nil {
			logger().Warn("base: systemd-tmpfiles --create failed — direct sysfs converge continues",
				"path", thpTmpfilesPath, "out", out, "error", terr)
		}
	}

	for _, item := range []struct {
		label string
		path  string
		want  string
	}{
		{"enabled", thpEnabledPath, wantEnabled},
		{"defrag", thpDefragPath, wantDefrag},
	} {
		data, err := os.ReadFile(r.hp(item.path))
		if err != nil {
			if !os.IsNotExist(err) {
				logger().Warn("base: read THP sysfs failed", "path", item.path, "error", err)
			}
			continue
		}
		cur := parseTHPActive(string(data))
		if cur == item.want {
			continue
		}
		// Never os.WriteFile on /host/sys/... — DaemonSet mounts /host/sys
		// read-only; Runner executes inside PID-1's mount namespace.
		cmd := fmt.Sprintf("printf '%%s\\n' %s > %s", sq(item.want), item.path)
		if _, err := r.run(ctx, "sh", "-c", cmd); err != nil {
			c.err("base: write THP sysfs failed",
				"path", item.path, "from", cur, "want", item.want, "error", err)
			continue
		}
		r.actions.WithLabelValues("thp:" + item.label).Inc()
		logger().Info("base: THP converged", "path", item.path, "from", cur, "to", item.want)
	}
}
