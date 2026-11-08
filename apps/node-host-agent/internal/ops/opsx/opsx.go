// opsx.go — shared helpers for the one-shot ops subcommands under
// internal/ops: the exit-code contract (0 clean / 1 runtime
// failure / 2 usage error), the flag.FlagSet boilerplate every Cmd
// used to duplicate (ContinueOnError, usage to stderr,
// ErrHelp-is-a-clean-exit), and the shared flag constructors for the
// declarations several Cmds repeated byte-for-byte (the env-resolved
// vars dir, the nebula certs dir). Importing envnames + envx keeps
// it import-safe for every ops package without a depguard edge —
// envnames is the contract leaf and envx is a libs/hostkit leaf.
package opsx

import (
	"errors"
	"flag"
	"os"

	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-host-agent/internal/envnames"
	"github.com/passiontech-global/kubernetes-cluster-automation/libs/hostkit/envx"
)

// Exit-code contract shared by every ops Cmd — cmd/agent's
// subcommand dispatch returns these straight to os.Exit.
const (
	ExitOK      = 0 // clean run (also -h/--help: not a usage error)
	ExitRuntime = 1 // runtime failure (check found drift, op errored)
	ExitUsage   = 2 // usage error (bad flags, missing required args)
)

// FlagSet returns the standard ops FlagSet: ContinueOnError so the
// caller can map parse failures onto the exit-code contract itself
// (ExitOnError would os.Exit(2) inside flag, bypassing Cmd's return
// value), with flag errors and usage text going to stderr.
func FlagSet(name string) *flag.FlagSet {
	fs := flag.NewFlagSet(name, flag.ContinueOnError)
	fs.SetOutput(os.Stderr)
	return fs
}

// Parse wraps fs.Parse with the ops exit-code mapping. ok reports
// whether the caller should continue into its run logic; when ok is
// false, code is the exit code Cmd should return — ExitOK for
// -h/--help (flag.ErrHelp is a clean exit, not a usage error),
// ExitUsage for any other parse failure.
func Parse(fs *flag.FlagSet, args []string) (code int, ok bool) {
	if err := fs.Parse(args); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return ExitOK, false
		}
		return ExitUsage, false
	}
	return 0, true
}

// VarsDirFlag registers the --vars-dir flag every ops Cmd that reads
// the registry shares: the vars dir holding cluster.yaml /
// interdc_nodes.yaml, defaulting to the
// NODE_HOST_AGENT_HOSTCONFIG_VARS_DIR env knob over
// /etc/node-host-agent/vars. It returns the flag's value
// pointer — dereference it only after fs.Parse (opsx.Parse), never at
// registration time, or the parsed value is lost.
func VarsDirFlag(fs *flag.FlagSet) *string {
	return fs.String("vars-dir",
		envx.String(envnames.EnvHostconfigVarsDir, "/etc/node-host-agent/vars"),
		"vars dir holding defaults.yaml/cluster.yaml/interdc_nodes.yaml; nebula-<name>.crt lands here")
}

// NebulaCertsDirFlag registers the --nebula-certs-dir flag: the
// nebula cert dir hubsync pushes certs into, defaulting to the
// NODE_HOST_AGENT_NEBULA_CERTS_DIR env knob over
// /etc/node-host-agent/nebula-certs. It returns the flag's value
// pointer — dereference it only after fs.Parse (opsx.Parse).
func NebulaCertsDirFlag(fs *flag.FlagSet) *string {
	return fs.String("nebula-certs-dir",
		envx.String(envnames.EnvNebulaCertsDir, "/etc/node-host-agent/nebula-certs"),
		"nebula cert dir (hubsync pushes to /etc/node-host-agent/nebula-certs)")
}
