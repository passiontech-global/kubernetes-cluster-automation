// check.go — the Check contract the parent orchestrator dispatches
// and every domain check implements, plus the canonical name tables:
// the prometheus `check` label values, the state-* latch names and
// the on-disk bookkeeping file names. The names are byte-identical
// to the pre-split constants — they are the one canonical
// definition; the values double as the cross-process contract with
// any still-deployed shell watchdog pieces (last-sig13-restart is
// the shared restart budget).
//
// This is the cdeps half of the controllerhygiene per-domain split:
// every domain package (kine, apiserver, etcd, pki, oom, feeder)
// gets the same *Deps — see deps.go.
package cdeps

import (
	"context"
	"regexp"
	"strings"

	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-host-agent/internal/platform/hoststate"
)

// Check names — prometheus `check` label + log context.
const (
	CheckHub         = "apiserver-hub"
	CheckKineTTL     = "kine-ttl"
	CheckKinePool    = "kine-pool"
	CheckOOMLoop     = "oomloop"
	CheckFeeder      = "feeder"
	CheckEtcd        = "etcd-quota" // etcdguard
	CheckCPFreeze    = "cp-freeze"  // W8-CP3 KCM/scheduler freeze auto-heal
	CheckKineStorage = "kine-storage"
	CheckPKIDrift    = "cp-cert-drift" // W8-CP4 PKI reload drift
	CheckKubeCert    = "kubeconfig-cert"
	// CheckJournal is the pseudo-check label the journal-unreadable
	// blindness accounting counts under — journald readability is a
	// cross-cutting witness, not one of the gated checks.
	CheckJournal = "journal"
)

// State latch names — identical to the shell signal names (NPD +
// prom_emit contract, node_watchdog_state{signal=...}); the values
// come from the canonical hoststate latch registry.
const (
	StateCacheStale       = hoststate.LatchAPIServerCacheStale
	StateCacheWedged      = hoststate.LatchAPIServerCacheWedged
	StateKineUnreachable  = hoststate.LatchKineBackendUnreachable
	StateKinePoolRunaway  = hoststate.LatchKinePoolRunaway
	StateKineTTLDead      = hoststate.LatchKineTTLDead
	StateKineTTLLoop      = hoststate.LatchKineTTLLoop
	StateControllerOOMLop = hoststate.LatchK0sControllerOOMLoop
	// StateJournalUnreadable latches while journal reads keep
	// producing nothing although journal storage exists — every
	// journal-grep check is blind until it clears (suspectLog's
	// last-suspect- budget drops with the latch via stateExit).
	StateJournalUnreadable = hoststate.LatchJournalUnreadable
	// StateCPComponentFrozen is the W8-CP3 latch: a KCM/scheduler
	// component frozen while the peer apiserver stays healthy.
	StateCPComponentFrozen = hoststate.LatchCPComponentFrozen
	// StatePKIReloadStale is the W8-CP4 latch: an on-disk PKI cert
	// newer than what the live socket presents — the daemon never
	// reloaded the rotated cert.
	StatePKIReloadStale = hoststate.LatchCPCertReloadStale
	// StateKubeCertExpiring latches while an embedded kubeconfig
	// client cert sits inside the warn window — surfaces through
	// node_host_agent_watchdog_state{state=...} like every other
	// state-* latch.
	StateKubeCertExpiring = hoststate.LatchKubeconfigCertExpiring
)

// On-disk bookkeeping file names under WatchdogStateDir — same names
// as the shell scripts so concurrent shell pieces share the budget.
const (
	FileRateRestart   = "last-sig13-restart" // shared restart budget
	FileRateTTLKill   = "last-ttl-restart"
	FileRatePoolKill  = "last-kinepool-kill"
	FileRateEtcdGuard = "last-etcd-guard" // eventpurge+rescue budget
	FileCtrGap        = "consecutive-sig13-gap"
	FileCtrFrozen     = "consecutive-sig13-frozen"
	FileCtrPeerFrozen = "consecutive-sig13-peer-frozen"
	FileCtrDead       = "consecutive-sig13-dead"
	FileCtrPool       = "consecutive-kine-pool"
	FileCtrTTLRewedge = "consecutive-ttl-rewedge"
	FileLastRVC       = "last-rvc"
	FileLastPRVC      = "last-prvc"
	FileTTLWedgedPID  = "ttl-last-wedged-pid"
	FileOOMSeen       = "oomloop-seen"
	FileOOMKills      = "oomloop-kills"
	FileOOMShielded   = "oomloop-shielded"
	FileFeederLastRst = "last-restart" // under FeederStateDir
	// W8-CP3 (KCM/scheduler freeze auto-heal) + W8-CP4 (PKI reload
	// drift) bookkeeping.
	FileRateCPRestart  = "last-cp-restart"
	FileRatePKIRestart = "last-cp-cert-restart"
	FileCtrCPFreeze    = "consecutive-cp-freeze"
	FileCtrKCMQuiet    = "consecutive-kcm-quiet"
	FileCtrPKIDriftPre = "consecutive-cp-cert-stale-"
	// FileKCMQueueSnap is the persisted KCM workqueue snapshot under
	// WatchdogStateDir (W10 bookkeeping).
	FileKCMQueueSnap = "kcm-queue-snapshot.json"
	// FileRateKineCheckpoint is the WAL-checkpoint cooldown file
	// under WatchdogStateDir.
	FileRateKineCheckpoint = "last-kine-wal-checkpoint"
	// LogKeyDeadFallbk keys the dead-fallback hold lines —
	// suspectLog dedupe budget keys are dropped by stateExit when
	// they match a latch name; the dead-fallback lines have no
	// dedicated latch so they get their own key.
	LogKeyDeadFallbk = "dead-fallback"
	// ClkTck is getconf CLK_TCK on x86_64 Linux — the /proc stat
	// starttime unit the pid-age math needs.
	ClkTck = 100.0
	// tcpStateListen is the hex st column of /proc/net/tcp(6) rows
	// in LISTEN — excluded from the kine conn-spiral count.
	TCPStateListen = "0A"
)

// Check is one hygiene probe+remedy pair. Name() is the prometheus
// `check` label AND the log-context key — it must equal the Check*
// constant the counters/logs already use so latch names, metric
// label values and log lines stay identical. Run executes one
// round and must never panic: implementations reach the shared
// seams (procfs view, mTLS client, state store, journal tracker,
// metrics, cfg knobs) through their *Deps (deps.go — the
// check-facing dependency surface) and keep their streak
// bookkeeping on disk (consecutive-* files stay the cross-process
// contract with any still-deployed shell watchdog pieces).
type Check interface {
	Name() string
	Run(ctx context.Context)
}

// CountMatches mirrors `grep -cE '<re>'` — matching line count.
// strings.Cut iterates in place — no giant []string allocation on a
// multi-MiB journal snapshot. Shared by the journal-grep checks
// (apiserver hub early-warning, kine TTL dead).
func CountMatches(re *regexp.Regexp, text string) int {
	n := 0
	for rest := text; rest != ""; {
		line, after, _ := strings.Cut(rest, "\n")
		rest = after
		if re.MatchString(line) {
			n++
		}
	}
	return n
}
