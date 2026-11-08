// Package hostconverge owns the `converge-once` subcommand — one
// hostconfig converge on the host, then exit. It is the systemd
// timer / manual "converge now" entrypoint for standalone targets
// (DirectRunner: already inside the host namespaces).
//
// cmd/agent wires this as the `converge-once` subcommand via Cmd.
package hostconverge

import (
	"context"
	"fmt"
	"os"

	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-host-agent/internal/envnames"
	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-host-agent/internal/ops/opsx"
	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-host-agent/internal/platform/hostctx"
	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-host-agent/internal/subsystem/hostconfig"
	"github.com/passiontech-global/kubernetes-cluster-automation/libs/hostkit/envx"
)

// HostRoot/RunnerFactory wire the production standalone contract
// ("/" + DirectRunner) — tests stub both to run a scripted converge
// against a tempdir host root instead of exec'ing real host
// commands.
var (
	HostRoot      = "/"
	RunnerFactory = func() hostconfig.Runner { return hostconfig.DirectRunner{} }
)

// Cmd is the `converge-once` subcommand entrypoint: flag parsing +
// dispatch, returning the process exit code (0 clean, 1 runtime
// failure, 2 usage error — same contract as the other ops
// subcommands).
func Cmd(ctx context.Context, args []string) int {
	fs := opsx.FlagSet("converge-once")
	varsDir := fs.String("vars-dir",
		envx.String(envnames.EnvHostconfigVarsDir, "/etc/node-host-agent/vars"),
		"vars dir holding defaults.yaml/cluster.yaml/interdc_nodes.yaml")
	nodeName := fs.String("node-name", "",
		"registry node name (default: NODE_HOST_AGENT_NODE_NAME/NODE_NAME env, then OS hostname)")
	certsDir := fs.String("nebula-certs-dir",
		envx.String(envnames.EnvNebulaCertsDir, "/etc/node-host-agent/nebula-certs"),
		"nebula cert dir (hubsync pushes to /etc/node-host-agent/nebula-certs)")
	if code, ok := opsx.Parse(fs, args); !ok {
		return code
	}
	// hostctx.NodeName owns the NODE_HOST_AGENT_NODE_NAME > NODE_NAME
	// > flag precedence (main.go parity); converge keeps the OS
	// hostname as the final fallback.
	return converge(ctx, *varsDir, hostctx.NodeName(*nodeName), *certsDir)
}

// converge runs exactly one hostconfig cycle on the host.
func converge(ctx context.Context, varsDir, nodeName, certsDir string) int {
	hostname, _ := os.Hostname()
	nn := nodeName
	if nn == "" {
		nn = hostname
	}
	hc, err := hostconfig.New(hostconfig.Config{
		NodeName:       nn,
		Hostname:       hostname,
		HostRoot:       HostRoot,
		VarsDir:        varsDir,
		NebulaCertsDir: certsDir,
		Runner:         RunnerFactory(),
	}, nil)
	if err != nil {
		fmt.Fprintln(os.Stderr, "converge-once:", err)
		return opsx.ExitRuntime
	}
	logger().Info("converge-once starting",
		"node", nn, "varsDir", varsDir, "certsDir", certsDir)
	// CycleWithErrors counts topology/vars failures, group
	// write/command errors and panics — a non-zero count means the
	// converge did not fully apply, so the timer/CI caller gets a
	// non-zero exit (ansible failed_when parity).
	if errs := hc.CycleWithErrors(ctx); errs > 0 {
		logger().Error("converge-once finished with errors",
			"node", nn, "errors", errs)
		return opsx.ExitRuntime
	}
	return opsx.ExitOK
}
