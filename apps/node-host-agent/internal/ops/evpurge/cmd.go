// cmd.go — the `purge-events` subcommand entrypoint: flag parsing +
// dispatch, returning the process exit code (0 clean, 1 runtime
// failure, 2 usage error — same contract as the other ops
// subcommands).
//
// Port of scripts/purge-events.py — bulk-deletes apiserver Events
// older than a cutoff through the k0s admin client certs; run as
// root ON a controller node. The cutoff is a flag (--before) or a
// bare positional RFC3339 arg, like the script's sys.argv[1]; the
// empty default is the script's "1970-01-01T00:00:00Z" (delete
// everything).
//
// The purge itself lives in internal/domain/eventpurge (Run): this file is
// only the flag layer so the controllerhygiene etcd guard can share
// the domain logic without importing a CLI package.
package evpurge

import (
	"context"
	"fmt"
	"os"
	"slices"
	"strings"
	"time"

	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-host-agent/internal/domain/eventpurge"
	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-host-agent/internal/ops/opsx"
)

// Cmd is the `purge-events` subcommand entrypoint.
func Cmd(ctx context.Context, args []string) int {
	fs := opsx.FlagSet("purge-events")
	api := fs.String("api", "https://127.0.0.1:6443", "apiserver base URL")
	ca := fs.String("ca", "",
		"CA bundle (default /var/lib/k0s/pki/ca.crt, fallback /var/lib/k0s/pki/etcd/ca.crt)")
	cert := fs.String("cert", "/var/lib/k0s/pki/admin.crt", "client certificate")
	key := fs.String("key", "/var/lib/k0s/pki/admin.key", "client key")
	workers := fs.Int("workers", 8,
		"parallel DELETE workers (drop to 2 on a weak cluster)")
	before := fs.String("before", "",
		"delete events created before this RFC3339 timestamp "+
			"(positional arg also accepted; default deletes everything)")
	// flag stops parsing at the first positional, so
	// `purge-events <ts> --workers=2` would silently drop --workers —
	// pull the positional cutoff out first, then parse what remains.
	// Value-taking flags in `--flag value` form skip their value so
	// it is not mistaken for the cutoff.
	valueFlags := map[string]bool{
		"api": true, "ca": true, "cert": true,
		"key": true, "workers": true, "before": true,
	}
	// Work on a clone: args aliases the os.Args backing array and the
	// in-place compaction below (`append(args[:i], args[i+1:]...)`)
	// would corrupt argv for anything that reads it afterwards.
	args = slices.Clone(args)
	var positional string
	for i := 0; i < len(args); i++ {
		a := args[i]
		if a == "--" {
			if i+1 < len(args) {
				positional = args[i+1]
				args = append(args[:i+1], args[i+2:]...)
			}
			break
		}
		if !strings.HasPrefix(a, "-") {
			positional = a
			args = append(args[:i], args[i+1:]...)
			break
		}
		if name := strings.TrimLeft(a, "-"); !strings.Contains(name, "=") &&
			valueFlags[name] {
			i++
		}
	}
	if code, ok := opsx.Parse(fs, args); !ok {
		return code
	}
	cutStr := *before
	if cutStr == "" && positional != "" {
		cutStr = positional
	}
	if cutStr == "" && fs.NArg() > 0 {
		cutStr = fs.Arg(0)
	}
	if cutStr == "" {
		// "default deletes everything" — the purge predicate keeps
		// events with CreationTimestamp BEFORE the cutoff, so the
		// far-future bound is what makes an unset --before delete
		// all of them (1970 would delete nothing).
		cutStr = "9999-12-31T23:59:59Z"
	}
	cutoff, err := time.Parse(time.RFC3339, cutStr)
	if err != nil {
		fmt.Fprintf(os.Stderr, "purge-events: bad cutoff %q: %v\n", cutStr, err)
		return opsx.ExitUsage
	}
	if err := eventpurge.Run(ctx, eventpurge.Config{
		API:      *api,
		CAFile:   *ca,
		CertFile: *cert,
		KeyFile:  *key,
		Workers:  *workers,
	}, cutoff, os.Stdout); err != nil {
		fmt.Fprintln(os.Stderr, "purge-events:", err)
		return opsx.ExitRuntime
	}
	return opsx.ExitOK
}
