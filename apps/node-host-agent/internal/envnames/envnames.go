// envnames.go — the entrypoint/shared slice of the env contract:
// the NODE_HOST_AGENT_ENABLE_* enable gates, the knobs cmd/agent
// itself reads, the shared hostctx knobs, and the knobs read by
// more than one package. Subsystem-private knobs live in
// envnames_<subsystem>.go.
//
// Package envnames is the single source of truth for the
// NODE_HOST_AGENT_* env contract: every env var name the binary
// reads is declared here exactly once as an Env-prefixed const,
// and every call site references the const instead of repeating
// the string literal — a typo in an env name used to compile fine
// and only surface at runtime. Const names are derived
// mechanically: `Env` + CamelCase of the var-name tail
// (NODE_HOST_AGENT_SWEEP_BASE_DIR → EnvSweepBaseDir), keeping the
// usual Go initialisms (EnvConvergeSSHKey, EnvAPISelf, …). Files
// are split per subsystem domain to mirror the config_env.go
// layout.
//
// It is a depguard leaf: it must never import another package in
// this module (the const values ARE the contract; nothing here
// needs wiring).
package envnames

// Enable gates — the NODE_HOST_AGENT_ENABLE_* knobs, declared
// together so the envdoc generator's gates table sees every gate like
// the others. Most are tri-state (true/false/auto) knobs wired as
// Descriptor.EnvFlag in cmd/agent/wiring.go; EnvEnableFeeder is a
// bool sub-gate controllerhygiene reads directly (no descriptor —
// the generator renders its row with an empty subsystem/default).
const (
	EnvEnableSweeper           = "NODE_HOST_AGENT_ENABLE_SWEEPER"
	EnvEnableConcourseCache    = "NODE_HOST_AGENT_ENABLE_CONCOURSE_CACHE"
	EnvEnableApiprober         = "NODE_HOST_AGENT_ENABLE_APIPROBER"
	EnvEnableHostmetrics       = "NODE_HOST_AGENT_ENABLE_HOSTMETRICS"
	EnvEnableHygiene           = "NODE_HOST_AGENT_ENABLE_HYGIENE"
	EnvEnableNethealth         = "NODE_HOST_AGENT_ENABLE_NETHEALTH"
	EnvEnableJanitor           = "NODE_HOST_AGENT_ENABLE_JANITOR"
	EnvEnableReporter          = "NODE_HOST_AGENT_ENABLE_REPORTER"
	EnvEnableControllerhygiene = "NODE_HOST_AGENT_ENABLE_CONTROLLERHYGIENE"
	EnvEnableHostconfig        = "NODE_HOST_AGENT_ENABLE_HOSTCONFIG"
	EnvEnableKinedb            = "NODE_HOST_AGENT_ENABLE_KINEDB"
	// EnvEnableFeeder gates the standalone api-backend feeder
	// inside controllerhygiene — read directly via envx.BoolKnob
	// (it is NOT a Descriptor.EnvFlag in wiring.go).
	EnvEnableFeeder = "NODE_HOST_AGENT_ENABLE_FEEDER"
)

// Core knobs — read by cmd/agent's entrypoint path (main.go,
// localbin.go, the wiring registry).
const (
	// EnvStandalone flips the binary into standalone-host mode
	// (equivalent to --standalone).
	EnvStandalone = "NODE_HOST_AGENT_STANDALONE"
	// EnvHostRoot prefixes every host path the agent opens
	// ("/host" in the DaemonSet, "/" standalone).
	EnvHostRoot = "NODE_HOST_AGENT_HOST_ROOT"
	// EnvNodeName overrides the resolved node identity — shared by
	// cmd/agent, platform/hostctx and ops/hostconverge
	// (precedence: NODE_HOST_AGENT_NODE_NAME > NODE_NAME >
	// --node-name).
	EnvNodeName = "NODE_HOST_AGENT_NODE_NAME"
	// EnvRequestTimeout is the kube-API request budget — shared by
	// cmd/agent and the sweeper.
	EnvRequestTimeout = "NODE_HOST_AGENT_REQUEST_TIMEOUT"
	// EnvHubsyncLocalBinary points hubsync at a local binary to
	// push instead of downloading one.
	EnvHubsyncLocalBinary = "NODE_HOST_AGENT_HUBSYNC_LOCAL_BINARY"
	// EnvTextfileInterval is the cadence of the standalone
	// hostmetrics textfile writer (wired in cmd/agent).
	EnvTextfileInterval = "NODE_HOST_AGENT_TEXTFILE_INTERVAL"
)

// Shared host-context knobs — resolved once by
// platform/hostctx's DepsFromEnv and spliced into every
// subsystem's EnvDeps.
const (
	EnvWatchdogConf            = "NODE_HOST_AGENT_WATCHDOG_CONF"
	EnvWatchdogStateDir        = "NODE_HOST_AGENT_WATCHDOG_STATE_DIR"
	EnvWatchdogLog             = "NODE_HOST_AGENT_WATCHDOG_LOG"
	EnvJournalDirs             = "NODE_HOST_AGENT_JOURNAL_DIRS"
	EnvJournalUnreadableNeeded = "NODE_HOST_AGENT_JOURNAL_UNREADABLE_NEEDED"
	// EnvHostconfigVarsDir is the shared vars dir — read by
	// hostctx and both ops subcommands (hostconverge, nebulasign).
	EnvHostconfigVarsDir = "NODE_HOST_AGENT_HOSTCONFIG_VARS_DIR"
	EnvTextfileDir       = "NODE_HOST_AGENT_TEXTFILE_DIR"
)

// Cross-package knobs — one env var read by more than one
// subsystem or ops package; the name lives here so both readers
// share it.
const (
	// EnvProcRoot is the procfs mount root — janitor,
	// workerhygiene and controllerhygiene.
	EnvProcRoot = "NODE_HOST_AGENT_PROC_ROOT"
	// EnvHostResolvConf is the host resolv.conf path — nethealth
	// and workerhygiene.
	EnvHostResolvConf = "NODE_HOST_AGENT_HOST_RESOLV_CONF"
	// EnvSweepBaseDir is the openebs hostdir root — sweeper and
	// concoursecache (the pruner walks the same root's
	// pvc-*/shared-cache children).
	EnvSweepBaseDir = "NODE_HOST_AGENT_SWEEP_BASE_DIR"
	// EnvNebulaCertsDir is the nebula cert dir — hostconfig,
	// hubsync and ops/hostconverge.
	EnvNebulaCertsDir = "NODE_HOST_AGENT_NEBULA_CERTS_DIR"
	// EnvConvergeSSHKey is the SSH key path for host converge —
	// hubsync and ops/nebulasign.
	EnvConvergeSSHKey = "NODE_HOST_AGENT_CONVERGE_SSH_KEY"
)

// DefaultSweepBaseDir is the default value of EnvSweepBaseDir —
// shared for the same reason the knob is: sweeper and
// concoursecache must agree on the openebs root, so the
// duplicated per-package defaultBaseDir const collapsed here.
const DefaultSweepBaseDir = "/var/openebs/local"
