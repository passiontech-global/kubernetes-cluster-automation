// opsx.go — shared helpers for the one-shot ops subcommands under
// internal/ops: the exit-code contract (0 clean / 1 runtime
// failure / 2 usage error) plus the flag.FlagSet boilerplate every
// Cmd used to duplicate (ContinueOnError, usage to stderr,
// ErrHelp-is-a-clean-exit). Leaf package — stdlib only, so every
// ops package may import it without a depguard edge.
package opsx

import (
	"errors"
	"flag"
	"os"
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
