// Package k0sdrift owns the `check-k0s-drift` subcommand — the
// on-node half of scripts/check-node-config-drift.sh: flag parsing
// plus the human-readable DRIFT / REMOVED-FLAG report and the 0/1
// exit mapping.
//
// The scan itself is hostmetrics.ScanK0sDrift — the same
// removed-flag / extra-key / missing-key findings the
// node_k0s_config_drift collector exports, computed on THIS node's
// /etc/k0s/k0s.yaml. Exit 0 clean (or not a k0s controller), 1 on
// drift.
//
// cmd/agent wires this as the `check-k0s-drift` subcommand via Cmd.
package k0sdrift

import (
	"context"
	"flag"
	"fmt"
	"io"
	"os"
	"slices"
	"strings"

	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-host-agent/internal/ops/opsx"
	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-host-agent/internal/subsystem/hostmetrics"
)

// Cmd is the `check-k0s-drift` subcommand entrypoint: flag parsing +
// dispatch, returning the process exit code (0 clean, 1 drift,
// 2 usage error — same contract as the other ops subcommands).
func Cmd(ctx context.Context, args []string) int {
	fs := opsx.FlagSet("check-k0s-drift")
	config := fs.String("config", "/etc/k0s/k0s.yaml", "k0s config to scan")
	expected := fs.String("expected-keys", "",
		"comma-separated expected controllerManager.extraArgs keys "+
			"(default: the repo-pinned set)")
	removed := fs.String("removed-flags", "",
		"comma-separated config keys removed upstream "+
			"(default: concurrent-service-syncs)")
	unit := fs.String("unit-file", "/etc/systemd/system/k0scontroller.service",
		"k0s controller gate — the check only runs when this unit file "+
			"exists (point at /dev/null to force on a non-controller)")
	if code, ok := opsx.Parse(fs, args); !ok {
		return code
	}
	// Provided-vs-absent matters: --expected-keys= (explicit empty)
	// means "no expected keys" while a missing flag means "use the
	// repo-pinned default" — see K0sDriftConfig.
	provided := map[string]bool{}
	fs.Visit(func(f *flag.Flag) { provided[f.Name] = true })
	var exp, rem []string
	if provided["expected-keys"] {
		exp = splitCSV(*expected)
	}
	if provided["removed-flags"] {
		rem = splitCSV(*removed)
	}
	return runCheck(ctx, hostmetrics.K0sDriftConfig{
		ConfigFile:   *config,
		UnitFile:     *unit,
		ExpectedKeys: exp,
		RemovedFlags: rem,
	}, os.Stdout)
}

// runCheck scans the k0s config and prints one DRIFT /
// REMOVED-FLAG line per finding in the shell script's phrasing.
// Returns the process exit code: 0 when clean (or the node is not a
// k0s controller), 1 on any drift.
func runCheck(ctx context.Context, cfg hostmetrics.K0sDriftConfig,
	out io.Writer) int {
	// The scan itself is a fast file read — honoring the signal ctx
	// is an upfront cancellation gate.
	if err := ctx.Err(); err != nil {
		fmt.Fprintln(os.Stderr, "check-k0s-drift:", err)
		return opsx.ExitRuntime
	}
	scan := hostmetrics.ScanK0sDrift(cfg)
	cfg = scan.Config // print the normalized (defaults-applied) paths
	if scan.NotController {
		_, _ = fmt.Fprintf(out, "check-k0s-drift: %s absent — "+
			"not a k0s controller, skip\n", cfg.UnitFile)
		return opsx.ExitOK
	}
	if len(scan.Findings) == 0 {
		_, _ = fmt.Fprintln(out, "check-k0s-drift: OK (no drift)")
		return opsx.ExitOK
	}

	// Aggregate the way the script did: one line listing every extra
	// key, one for every missing key, one REMOVED-FLAG line per flag.
	var extra, missing, removed []string
	unreadable := false
	for _, f := range scan.Findings {
		switch f.Reason {
		case "extra-key":
			extra = append(extra, f.Key)
		case "missing-key":
			missing = append(missing, f.Key)
		case "removed-flag":
			removed = append(removed, f.Key)
		default: // unreadable
			unreadable = true
		}
	}
	if unreadable {
		_, _ = fmt.Fprintf(out,
			"DRIFT %s: cannot read / parse k0s.yaml\n",
			cfg.ConfigFile)
	}
	if len(extra) > 0 {
		slices.Sort(extra)
		_, _ = fmt.Fprintf(out,
			"DRIFT %s: key present on node but not in expected set: %s\n",
			cfg.ConfigFile, strings.Join(extra, " "))
	}
	if len(missing) > 0 {
		_, _ = fmt.Fprintf(out,
			"DRIFT %s: key in expected set but missing on node: %s\n",
			cfg.ConfigFile, strings.Join(missing, " "))
	}
	slices.Sort(removed)
	for _, flag := range removed {
		_, _ = fmt.Fprintf(out,
			"REMOVED-FLAG %s: k0s.yaml still has '%s' "+
				"(removed upstream -> component will crashloop after upgrade)\n",
			cfg.ConfigFile, flag)
	}
	return opsx.ExitRuntime
}

// splitCSV splits a comma-separated flag value, trimming spaces and
// dropping empty elements. Empty input yields an empty NON-nil
// slice — callers distinguish "flag absent" (nil -> defaults) from
// "flag provided empty" (empty set honored).
func splitCSV(s string) []string {
	out := []string{}
	for _, p := range strings.Split(s, ",") {
		if p = strings.TrimSpace(p); p != "" {
			out = append(out, p)
		}
	}
	return out
}
