// cmd.go — the `concourse-worker-init` subcommand entrypoint:
// flag parsing + dispatch, returning the process exit code (0 clean,
// 1 runtime failure, 2 usage error — same contract as the other ops
// subcommands).
package concourseinit

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"os"
)

// Cmd is the init-rm subcommand: the flags map onto Config's path
// knobs so the container invocation can point at its mounts
// (`--wrapper-source=/usr/local/bin/node-host-agent` self-installs
// the agent as the runc wrapper even when argv[0] resolves
// elsewhere).
func Cmd(ctx context.Context, args []string) int {
	fs := flag.NewFlagSet("concourse-worker-init", flag.ContinueOnError)
	fs.SetOutput(os.Stderr)
	workDir := fs.String("work-dir", "",
		"concourse work dir to soft-reset (default "+DefaultWorkDir+")")
	runcDir := fs.String("runc-dir", "",
		"emptyDir shared with the worker holding runc + runc.real (default "+
			DefaultRuncDir+")")
	runcSource := fs.String("runc-source", "",
		"the image's real runc, copied to <runc-dir>/runc.real (default "+
			DefaultRuncSource+")")
	wrapperSource := fs.String("wrapper-source", "",
		"binary installed as <runc-dir>/runc — the multi-call agent "+
			"(default: os.Executable)")
	if err := fs.Parse(args); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return 0 // -h/--help is a clean exit, not a usage error
		}
		return 2
	}
	if err := WorkerInit(ctx, Config{
		WorkDir:       *workDir,
		RuncDir:       *runcDir,
		RuncSource:    *runcSource,
		WrapperSource: *wrapperSource,
	}); err != nil {
		fmt.Fprintln(os.Stderr, "concourse-worker-init:", err)
		return 1
	}
	return 0
}
