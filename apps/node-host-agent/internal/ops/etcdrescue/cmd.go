// cmd.go — the `rescue-etcd` subcommand entrypoint: flag parsing +
// dispatch, returning the process exit code (0 clean, 1 runtime
// failure, 2 usage error — same contract as the other ops
// subcommands).
//
// Port of scripts/rescue-etcd.sh — rescues a k0s controller etcd
// that hit the backend quota; run as root ON the controller.
// Compact -> online defrag -> offline defrag when the online pass
// reclaims nothing (or --force-offline) -> alarm disarm -> write
// canary.
//
// The rescue itself lives in internal/domain/etcdmaint (Run): this file is
// only the flag layer so the controllerhygiene etcd guard can share
// the domain logic without importing a CLI package.
package etcdrescue

import (
	"context"
	"fmt"
	"os"

	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-host-agent/internal/domain/etcdmaint"
	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-host-agent/internal/ops/opsx"
)

// Cmd is the `rescue-etcd` subcommand entrypoint.
func Cmd(ctx context.Context, args []string) int {
	fs := opsx.FlagSet("rescue-etcd")
	k0sDir := fs.String("k0s-dir", "/var/lib/k0s",
		"k0s data dir (derives bin/etcd*, pki/ cert paths)")
	endpoint := fs.String("endpoint", "https://127.0.0.1:2379",
		"etcd client endpoint")
	forceOffline := fs.Bool("force-offline", false,
		"skip the online defrag attempt, go straight to offline defrag")
	if code, ok := opsx.Parse(fs, args); !ok {
		return code
	}
	if err := etcdmaint.Run(ctx, etcdmaint.Config{
		K0sDir:       *k0sDir,
		Endpoint:     *endpoint,
		ForceOffline: *forceOffline,
	}, os.Stdout); err != nil {
		fmt.Fprintln(os.Stderr, "rescue-etcd:", err)
		return opsx.ExitRuntime
	}
	return opsx.ExitOK
}
