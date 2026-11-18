// runc_hang_internal_test.go — package-internal coverage for the
// cmdline qualification parser: the containerd-shim's real argv
// (`runc --root <dir> --log <file> --log-format json <subcmd>`) must
// resolve to the lifecycle subcommand, not to the flag VALUE. The
// exec/run exclusion, the bracket-comm shortcut and the missing-value
// edge cases stay pinned here too.
package ctr

import (
	"fmt"
	"path/filepath"
	"testing"

	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-host-agent/internal/subsystem/workerhygiene/wdepstest"
)

func TestRuncCmdlineQualifiesGlobalFlags(t *testing.T) {
	const (
		root  = "/run/k0s/containerd/runc/k8s.io"
		logFn = "/run/k0s/containerd/runc/k8s.io/abc123/log.json"
	)
	tests := []struct {
		name    string
		comm    string
		cmdline string
		want    bool
	}{
		{
			name: "containerd-shim create with space-separated global flags",
			comm: "runc",
			cmdline: "runc\x00--root\x00" + root + "\x00--log\x00" + logFn +
				"\x00--log-format\x00json\x00create\x00abc123\x00",
			want: true,
		},
		{
			name: "containerd-shim exec is still excluded",
			comm: "runc",
			cmdline: "runc\x00--root\x00" + root + "\x00--log\x00" + logFn +
				"\x00--log-format\x00json\x00exec\x00-t\x00abc123\x00sh\x00",
			want: false,
		},
		{
			name:    "containerd-shim run is still excluded",
			comm:    "runc",
			cmdline: "runc\x00--root\x00" + root + "\x00run\x00abc123\x00",
			want:    false,
		},
		{
			name:    "inline equals flags do not consume the next token",
			comm:    "runc",
			cmdline: "runc\x00--root=" + root + "\x00--log-format=json\x00start\x00abc123\x00",
			want:    true,
		},
		{
			name:    "short -r/-l flags consume their values",
			comm:    "runc",
			cmdline: "runc\x00-r\x00/var/run/runc\x00-l\x00/var/log/runc.log\x00kill\x00abc123\x00SIGKILL\x00",
			want:    true,
		},
		{
			name:    "--criu consumes its value",
			comm:    "runc",
			cmdline: "runc\x00--criu\x00/usr/sbin/criu\x00delete\x00abc123\x00",
			want:    true,
		},
		{
			name:    "missing value at end of cmdline",
			comm:    "runc",
			cmdline: "runc\x00--root\x00" + root + "\x00--log\x00",
			want:    false,
		},
		{
			name:    "bare --root with no subcommand",
			comm:    "runc",
			cmdline: "runc\x00--root\x00",
			want:    false,
		},
		{
			name:    "plain lifecycle subcommand",
			comm:    "runc",
			cmdline: "runc\x00create\x00abc123\x00",
			want:    true,
		},
		{
			name:    "unknown subcommand is not a lifecycle command",
			comm:    "runc",
			cmdline: "runc\x00--root\x00" + root + "\x00version\x00",
			want:    false,
		},
		{
			name:    "crun lifecycle with global flags",
			comm:    "crun",
			cmdline: "crun\x00--root\x00/run/crun\x00start\x00abc123\x00",
			want:    true,
		},
		{
			name:    "bracket comm shortcut wins over an exec argv",
			comm:    "runc:[2:INIT]",
			cmdline: "runc\x00exec\x00abc123\x00sh\x00",
			want:    true,
		},
		{
			name:    "empty cmdline falls back to bare comm",
			comm:    "runc",
			cmdline: "",
			want:    true,
		},
	}
	for i, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			f := wdepstest.New(t)
			d := ctrDeps(t, f)
			pid := 9000 + i
			wdepstest.WriteFile(t,
				filepath.Join(f.ProcDir, fmt.Sprint(pid), "cmdline"), tc.cmdline)
			if got := runcCmdlineQualifies(d, pid, tc.comm); got != tc.want {
				t.Fatalf("runcCmdlineQualifies(%q) = %v, want %v",
					tc.cmdline, got, tc.want)
			}
		})
	}
}
