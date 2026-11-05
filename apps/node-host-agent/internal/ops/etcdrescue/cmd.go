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
package etcdrescue

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"os"
)

// Cmd is the `rescue-etcd` subcommand entrypoint.
func Cmd(ctx context.Context, args []string) int {
	fs := flag.NewFlagSet("rescue-etcd", flag.ContinueOnError)
	fs.SetOutput(os.Stderr)
	k0sDir := fs.String("k0s-dir", "/var/lib/k0s",
		"k0s data dir (derives bin/etcd*, pki/ cert paths)")
	endpoint := fs.String("endpoint", "https://127.0.0.1:2379",
		"etcd client endpoint")
	forceOffline := fs.Bool("force-offline", false,
		"skip the online defrag attempt, go straight to offline defrag")
	if err := fs.Parse(args); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return 0 // -h/--help is a clean exit, not a usage error
		}
		return 2
	}
	if err := Run(ctx, Config{
		K0sDir:       *k0sDir,
		Endpoint:     *endpoint,
		ForceOffline: *forceOffline,
	}, os.Stdout); err != nil {
		fmt.Fprintln(os.Stderr, "rescue-etcd:", err)
		return 1
	}
	return 0
}
