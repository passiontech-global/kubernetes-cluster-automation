// deps.go — the parent-side seam after the per-domain split. The
// check-facing dependency surface itself moved to wdeps (the
// shared package every domain check imports: Config+Seams, Deps,
// CycleEnv, Check, the CtrTask machinery and the shared helpers).
// What lives here are ALIASES so the external API
// (workerhygiene.Config/EnvDeps/ConfigFromEnv/New) and the
// package-internal test contract keep working verbatim: tests in
// this package still name Config, Seams, cycleEnv, Check,
// the check-name constants and the parser/helper funcs by
// their pre-split spellings — each alias points at the ONE
// definition in the owning package, so nothing can drift.
package workerhygiene

import (
	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-host-agent/internal/platform/hoststate"
	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-host-agent/internal/subsystem/workerhygiene/cilium"
	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-host-agent/internal/subsystem/workerhygiene/ctr"
	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-host-agent/internal/subsystem/workerhygiene/guards"
	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-host-agent/internal/subsystem/workerhygiene/kubelet"
	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-host-agent/internal/subsystem/workerhygiene/wdeps"
)

// Type aliases — the pre-split spellings of the types that moved
// (or whose canonical definition moved) into wdeps.
type (
	Config         = wdeps.Config
	EnvDeps        = wdeps.EnvDeps
	KubeletConfig  = wdeps.KubeletConfig
	TeardownConfig = wdeps.TeardownConfig
	CtrConfig      = wdeps.CtrConfig
	CiliumConfig   = wdeps.CiliumConfig
	DiskConfig     = wdeps.DiskConfig
	NetConfig      = wdeps.NetConfig
	PressureConfig = wdeps.PressureConfig
	CalicoConfig   = wdeps.CalicoConfig
	JournalConfig  = wdeps.JournalConfig
	HostConfig     = wdeps.HostConfig
	RuntimeConfig  = wdeps.RuntimeConfig
	Seams          = wdeps.Seams
	cycleEnv       = wdeps.CycleEnv
	Check          = wdeps.Check
)

// ConfigFromEnv resolves every NODE_HOST_AGENT_* knob workerhygiene
// reads — implementation lives in wdeps (it owns the Config
// defaults); the name stays here because the subsystem convention
// puts it next to New.
func ConfigFromEnv(d EnvDeps) Config { return wdeps.ConfigFromEnv(d) }

// Const aliases — the defaults and latch/check names tests assert
// against. The canonical values are exported from their owning
// packages (wdeps for config defaults and check names, kubelet/
// guards for check-side thresholds, hoststate for the latch itself).
const (
	minUptimeSeconds               = wdeps.MinUptimeSeconds
	defaultInterval                = wdeps.DefaultInterval
	defaultKubeletHealthzURL       = wdeps.DefaultKubeletHealthzURL
	defaultKubeletWdMaxFail        = wdeps.DefaultKubeletWdMaxFail
	defaultJournalUnreadableNeeded = wdeps.DefaultJournalUnreadableNeeded
	defaultCiliumHealthzURL        = wdeps.DefaultCiliumHealthzURL
	defaultKubeletTokenPath        = wdeps.DefaultKubeletTokenPath
	defaultCalicoFelixReadyURL     = wdeps.DefaultCalicoFelixReadyURL
	poddirThreshold                = kubelet.PoddirThreshold
	minEvictRSSBytes               = guards.MinEvictRSSBytes
	calicoFelixRestartFails        = guards.CalicoFelixRestartFails
	stateJournalUnreadable         = hoststate.LatchJournalUnreadable

	checkTeardown         = wdeps.CheckTeardown
	checkKonn             = wdeps.CheckKonn
	checkDNS              = wdeps.CheckDNS
	checkStall            = wdeps.CheckStall
	checkWatch            = wdeps.CheckWatch
	checkCtrTasks         = wdeps.CheckCtrTasks
	checkCilium           = wdeps.CheckCilium
	checkCiliumInit       = wdeps.CheckCiliumInit
	checkCtrImages        = wdeps.CheckCtrImages
	checkCiliumIPAM       = wdeps.CheckCiliumIPAM
	checkKubeletWd        = wdeps.CheckKubeletWd
	checkSyncloop         = wdeps.CheckSyncloop
	checkCtrSock          = wdeps.CheckCtrSock
	checkIngestGC         = wdeps.CheckIngestGC
	checkZombieStorm      = wdeps.CheckZombieStorm
	checkJournald         = wdeps.CheckJournald
	checkCiliumEnvoy      = wdeps.CheckCiliumEnvoy
	checkCiliumMTU        = wdeps.CheckCiliumMTU
	checkCiliumWG         = wdeps.CheckCiliumWG
	checkDiskBloat        = wdeps.CheckDiskBloat
	checkDState           = wdeps.CheckDState
	checkSysScopes        = wdeps.CheckSysScopes
	checkCiliumLRP        = wdeps.CheckCiliumLRP
	checkSpegel           = wdeps.CheckSpegel
	checkCalico           = wdeps.CheckCalico
	checkCiliumBPF        = wdeps.CheckCiliumBPF
	checkPSIThrash        = wdeps.CheckPSIThrash
	checkCNINetns         = wdeps.CheckCNINetns
	checkCtrMeta          = wdeps.CheckCtrMeta
	checkHostOOM          = wdeps.CheckHostOOM
	checkOrphanHP         = wdeps.CheckOrphanHP
	checkCgroupDying      = wdeps.CheckCgroupDying
	checkSystemdSessions  = wdeps.CheckSystemdSessions
	checkOverlayFSStale   = wdeps.CheckOverlayFSStale
	checkIOPressure       = wdeps.CheckIOPressure
	checkConntrackLiberal = wdeps.CheckConntrackLiberal
	checkClockJump        = wdeps.CheckClockJump
)

// Func aliases — parsers/helpers tests call by their old names;
// the implementations live in their owning packages.
var (
	parseWGAllowedIPs       = wdeps.ParseWGAllowedIPs
	kubeletWatchdogHosts    = wdeps.KubeletWatchdogHosts
	withDefaultAPIPort      = kubelet.WithDefaultAPIPort
	parseEnvoyXDSRejected   = cilium.ParseEnvoyXDSRejected
	parseCiliumIPAM         = cilium.ParseCiliumIPAM
	parseCiliumBPFMaps      = cilium.ParseCiliumBPFMaps
	parseCiliumEncryptPeers = cilium.ParseCiliumEncryptPeers
	normalizeCRIImageName   = ctr.NormalizeCRIImageName
	dstateRuntimeComm       = guards.DstateRuntimeComm
)
