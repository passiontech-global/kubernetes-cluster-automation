// hostctx.go — the shared "watchdog/host context" bundle: the
// host-side inputs resolved ONCE per process by DepsFromEnv
// (deps_env.go — the hostPath join over the host-fs root, the parsed
// node-watchdog.conf plus its per-cycle reloader, the shared
// systemd client, the journald blindness-detector inputs, and the
// shared state/log/vars/textfile dirs + resolved node name) and
// then spliced into every subsystem's EnvDeps. Each EnvDeps embeds
// Deps anonymously so ConfigFromEnv keeps reading d.Watchdog,
// d.HostPath(...) etc. via field promotion; subsystem-unique inputs
// (kube client, hostname, standalone flag, …) stay named fields on
// the EnvDeps itself.
package hostctx

import (
	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-host-agent/internal/platform/systemd"
	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-host-agent/internal/platform/watchdogconf"
	"github.com/passiontech-global/kubernetes-cluster-automation/libs/hostkit/timex"
)

// Deps is the shared watchdog/host context — one value per process,
// built by DepsFromEnv and spliced verbatim into every subsystem
// EnvDeps that needs any of it. Fields a subsystem does not consume
// stay zero-valued in its view of the bundle; nil Watchdog/Systemd/
// HostPath degrade exactly like the nil-dep contracts the
// individual EnvDeps used to document (nil HostPath → identity
// join, nil Watchdog → empty conf).
type Deps struct {
	// Watchdog is the parsed /etc/node-watchdog.conf — the middle
	// layer of every env → conf → package-default chain. Nil →
	// empty conf (all conf values zero → package defaults apply).
	Watchdog *watchdogconf.Config
	// WatchdogSrc is the per-cycle conf reloader — hostconfig
	// rewrites the conf every converge, so conf-consuming
	// subsystems re-read it per cycle instead of pinning the
	// startup parse.
	WatchdogSrc *watchdogconf.Reloader
	// WatchdogStateDir / WatchdogLogFile are the shared
	// node-watchdog state dir + log file — one mount for the whole
	// pod.
	WatchdogStateDir string
	WatchdogLogFile  string
	// HostPath joins a host-absolute path under the host-fs root
	// ("/host" in the DaemonSet, identity standalone).
	// Nil → identity (host paths used verbatim).
	HostPath func(string) string
	// HostRoot is the resolved host-fs root itself ("/host" in the
	// DaemonSet, "/" standalone) — the nsenter decision input and
	// the ShouldRun/Detect probe root.
	HostRoot string
	// Systemd is the shared host-systemd client — may be nil:
	// consumers degrade to "no systemd client wired" and the
	// dependent checks no-op/log-degrade.
	Systemd *systemd.Client
	// JournalDirs / JournalUnreadableNeeded are the shared
	// journald blindness-detector inputs — the storage dirs are the
	// "journald is installed" witness.
	JournalDirs             []string
	JournalUnreadableNeeded int
	// VarsDir is the shared hostconfig vars dir (cluster.yaml & co.)
	// — also read by workerhygiene's T15 host-list fallback,
	// kinedb's Detect and hubsync.
	VarsDir string
	// TextfileDir is the shared node-exporter textfile dir — feeds
	// the standalone prom writer and kinedb's prom files.
	TextfileDir string
	// NodeName is the resolved node identity
	// (NODE_HOST_AGENT_NODE_NAME/NODE_NAME/--node-name, resolved in
	// main) — the pods-filter key, the topology.Load registry key,
	// and the NodeCondition target.
	NodeName string
	// Clock is the shared settable clock — ONE timex.Cell spliced
	// into every subsystem Config, so a test stubbing the cell once
	// (deps.Clock.Set) is observed by every subsystem's hoststate
	// store and clock reads. Nil → each subsystem's applyDefaults
	// arms its own NewCell(nil); DepsFromEnv always fills it.
	Clock *timex.Cell
}

// PathJoin is the nil-safe form of the HostPath join: nil HostPath →
// identity (the nil-dep contract Deps documents — tests and
// partially-built bundles join host paths verbatim), non-nil →
// HostPath(p). Consumers call it straight off the promoted field
// instead of re-declaring the nil fallback inline.
func (d Deps) PathJoin(p string) string {
	if d.HostPath == nil {
		return p
	}
	return d.HostPath(p)
}
