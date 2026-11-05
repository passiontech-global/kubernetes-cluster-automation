// cpwave.go — Wave 8/10 control-plane additions:
//
//	W8-CP3  KCM/scheduler freeze auto-heal. k0s hosts
//	        kube-controller-manager (:10257) and kube-scheduler
//	        (:10259) inside k0scontroller — when either /healthz
//	        stays dead for CPFreezeCycles consecutive cycles, or the
//	        KCM workqueue shows a stalled backlog (W10-FIX1) for
//	        longer than CPFreezeQuietFor, while the peer apiserver
//	        still answers, the component (not the apiserver) is
//	        frozen → restart k0scontroller.service under the
//	        last-cp-restart budget.
//	W8-CP4  PKI reload drift. After cert rotation the on-disk cert
//	        can be newer than the one a live socket still presents
//	        (the daemon never reloaded). Compare SerialNumber +
//	        NotAfter of the on-disk file vs the socket-presented
//	        leaf for each PKIDriftPair; drift for PKIDriftCycles
//	        consecutive cycles latches state-cp-cert-reload-stale
//	        and restarts the owning unit under the
//	        last-cp-cert-restart budget.
//	W10-CP2 Kine store health. Sizes the SQLite state.db(+ -wal) —
//	        or the etcd/JetStream filestore on non-SQLite backends —
//	        into node_agent_kine_{db,wal}_bytes and forces a sqlite3
//	        wal_checkpoint(TRUNCATE) when the WAL grows past the
//	        threshold (30m cooldown).
//	W10-CP5 Embedded kubeconfig client-cert expiry. Parses
//	        client-certificate-data out of the k0s admin/ccm/
//	        scheduler/kubelet kubeconfigs and exports
//	        node_agent_kubeconfig_cert_min_days_remaining; inside
//	        the warn window it latches state-kubeconfig-cert-expiring.
//
// W10 metrics note: the subsystem prometheus registry is owned by
// controllerhygiene.go's New() (outside this file), so the node_agent_*
// gauges are emitted through the node-exporter textfile channel —
// the DaemonSet bind-mounts /host/var/lib/node-exporter rw for
// exactly this (kinedb/hostconfig parity).
package controllerhygiene

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"math"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"time"

	"k8s.io/client-go/tools/clientcmd"
)

const checkCPFreeze = "cp-freeze"
const checkPKIDrift = "cp-cert-drift"

// W10 check names — prometheus `check` label + log context.
const (
	checkKineStorage = "kine-storage"
	checkKubeCert    = "kubeconfig-cert"
)

// W10 bookkeeping: the KCM queue snapshot file and the WAL
// checkpoint cooldown file, both under WatchdogStateDir.
const (
	fileKCMQueueSnap       = "kcm-queue-snapshot.json"
	fileRateKineCheckpoint = "last-kine-wal-checkpoint"
	// stateKubeCertExpiring latches while an embedded kubeconfig
	// client cert sits inside the warn window — surfaces through
	// node_host_agent_watchdog_state{state=...} like every other
	// state-* latch.
	stateKubeCertExpiring = "kubeconfig-cert-expiring"
)

// W10-FIX1 stall thresholds — a stalled KCM workqueue, never an
// idle one. depthSum==0 (the healthy idle reading) can NEVER fire.
const (
	kcmStallDepthSum     = 50  // (a) total queued items across queues
	kcmStallQueueDepth   = 20  // (b) single-queue depth for retry storm
	kcmStallRetriesDelta = 200 // (b) retries_total growth per window
	// kcmStallAddsEpsilon is "increased by ~0" for arm (a): counter
	// deltas are integer-valued, so <1 enqueue across ALL queues in
	// the window counts as flat (tolerates float noise).
	kcmStallAddsEpsilon = 0.5
	// kcmSnapshotMaxGap bounds how old the previous snapshot may be
	// — the delta math only means "no progress" between consecutive
	// scrapes; a stale baseline (agent restart, missed cycles) is
	// inconclusive.
	kcmSnapshotMaxGap = 15 * time.Minute
)

// W10-CP2/W10-CP5 knobs — package vars rather than Config fields
// (Config lives in controllerhygiene.go, outside this file); tests
// shrink them freely. Defaults mirror the plan.
var (
	kineWALCheckpointMinBytes = int64(512 << 20) // 512 MiB WAL → checkpoint
	kineWALCheckpointCooldown = 30 * time.Minute // last-kine-wal-checkpoint budget
	// kineCheckpointFn runs `PRAGMA wal_checkpoint(TRUNCATE)` —
	// package seam (same role Config.xxxFn seams play elsewhere).
	kineCheckpointFn = sqlite3WALCheckpoint
	// kineTextfileDirOverride wins over the K0sDir-derived textfile
	// dir — test seam.
	kineTextfileDirOverride = ""
	// kubeconfigCertMinDays is the W10-CP5 warn window (plan: <14d).
	kubeconfigCertMinDays = 14.0
)

// errKineNoSQLite3 marks "host has no sqlite3 binary" — distinct
// from a checkpoint failure so the cooldown stays unspent.
var errKineNoSQLite3 = errors.New("sqlite3 binary not found on host")

const (
	kineCheckpointBudget = 2 * time.Minute // per-checkpoint exec bound
	kineStoreMaxFiles    = 1 << 16         // bounded filestore walk

	// Metric names — the Prometheus alerts (KineDatabaseSizeCritical,
	// NodeKubeconfigCertExpiringSoon) key on these exact series.
	kineDBBytesMetric  = "node_agent_kine_db_bytes"
	kineWALBytesMetric = "node_agent_kine_wal_bytes"
	certDaysMetric     = "node_agent_kubeconfig_cert_min_days_remaining"
)

// probeHTTP2xx is cpHealthFn's default: GET url, true on a 2xx — the
// KCM/scheduler healthz contract (500 = component wedged, any other
// failure = unreachable). KCM/scheduler serve self-signed certs, so
// the shared insecure transport is used.
func probeHTTP2xx(ctx context.Context, url string, timeout time.Duration) bool {
	cctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	req, err := http.NewRequestWithContext(cctx, http.MethodGet, url, nil)
	if err != nil {
		return false
	}
	resp, err := probeClient.Do(req)
	if err != nil {
		return false
	}
	defer resp.Body.Close()
	_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 64<<10))
	return resp.StatusCode >= 200 && resp.StatusCode < 300
}

// httpGetInsecure is kcmMetricsFn's default — body or error.
func httpGetInsecure(ctx context.Context, url string, timeout time.Duration) (string, error) {
	cctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	req, err := http.NewRequestWithContext(cctx, http.MethodGet, url, nil)
	if err != nil {
		return "", err
	}
	resp, err := probeClient.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	b, err := io.ReadAll(io.LimitReader(resp.Body, 4<<20))
	if err != nil {
		return "", err
	}
	return string(b), nil
}

// tlsDialCert returns the leaf certificate addr presents — drift is
// judged on the presented cert, not on chain trust, so the dial is
// insecure by design.
func tlsDialCert(ctx context.Context, addr string) (*x509.Certificate, error) {
	d := &net.Dialer{Timeout: 8 * time.Second}
	conn, err := tls.DialWithDialer(d, "tcp", addr,
		&tls.Config{InsecureSkipVerify: true}) //nolint:gosec // drift check wants the presented cert
	if err != nil {
		return nil, err
	}
	defer conn.Close()
	state := conn.ConnectionState()
	if len(state.PeerCertificates) == 0 {
		return nil, fmt.Errorf("no peer certificate")
	}
	return state.PeerCertificates[0], nil
}

// kcmQueueSnapshot is one scrape of the KCM /metrics workqueue
// state, persisted under WatchdogStateDir so consecutive scrapes
// can be compared for stall evidence (W10-FIX1).
type kcmQueueSnapshot struct {
	At       int64              `json:"at"` // scrape epoch (nowFn)
	Leader   bool               `json:"leader"`
	DepthSum float64            `json:"depth_sum"`
	Depths   map[string]float64 `json:"depths"`
	Adds     map[string]float64 `json:"adds"`
	Retries  map[string]float64 `json:"retries"`
}

var (
	kcmLeaderRe = regexp.MustCompile(
		`(?m)^leader_election_master_status(?:\{[^}]*\})?\s+([0-9.]+)`)
	// workqueue_{depth,adds_total,retries_total}{labels} value —
	// the three series the stall predicate needs.
	kcmWorkqueueRe = regexp.MustCompile(
		`(?m)^workqueue_(depth|adds_total|retries_total)(\{[^}]*\})?\s+([0-9.eE+-]+)`)
	kcmQueueNameRe = regexp.MustCompile(`name="([^"]+)"`)
)

// kcmQueueKey extracts the workqueue name from a metric label set —
// `name="..."` is the queue identifier shared by all three series;
// the raw label text is the fallback so differently-labelled
// variants still join consistently between scrapes.
func kcmQueueKey(labels string) string {
	if labels == "" {
		return ""
	}
	if m := kcmQueueNameRe.FindStringSubmatch(labels); m != nil {
		return m[1]
	}
	return labels
}

// parseKCMQueueSnapshot extracts leader state + per-queue
// workqueue depth/adds/retries from a KCM /metrics body. parsed=false
// when the leader metric is absent — inconclusive, same contract
// the old kcmLeaderIdle had.
func parseKCMQueueSnapshot(body string, at int64) (*kcmQueueSnapshot, bool) {
	lm := kcmLeaderRe.FindStringSubmatch(body)
	if lm == nil {
		return nil, false
	}
	lv, _ := strconv.ParseFloat(lm[1], 64)
	snap := &kcmQueueSnapshot{
		At:      at,
		Leader:  lv >= 1,
		Depths:  map[string]float64{},
		Adds:    map[string]float64{},
		Retries: map[string]float64{},
	}
	for _, m := range kcmWorkqueueRe.FindAllStringSubmatch(body, -1) {
		v, err := strconv.ParseFloat(m[3], 64)
		if err != nil {
			continue
		}
		key := kcmQueueKey(m[2])
		switch m[1] {
		case "depth":
			snap.Depths[key] += v
			snap.DepthSum += v
		case "adds_total":
			snap.Adds[key] += v
		case "retries_total":
			snap.Retries[key] += v
		}
	}
	return snap, true
}

// kcmDeltas returns per-queue counter deltas (cur - prev) over the
// queues present in BOTH snapshots. ok=false when any shared
// counter decreased — a KCM restart resets every counter and the
// delta math is meaningless.
func kcmDeltas(prev, cur map[string]float64) (map[string]float64, bool) {
	out := make(map[string]float64, len(cur))
	for q, cv := range cur {
		pv, ok := prev[q]
		if !ok {
			continue
		}
		d := cv - pv
		if d < 0 {
			return nil, false
		}
		out[q] = d
	}
	return out, true
}

// kcmQueueStalled is the W10-FIX1 stall predicate — true ONLY when
// this node is the KCM leader (leader_election_master_status >= 1)
// AND the workqueue shows a backlog with zero forward progress
// across two consecutive scrapes:
//
//	(a) depthSum > kcmStallDepthSum while adds_total grew by ~0 —
//	    items queued, nothing new arriving, workers not draining; or
//	(b) one queue depth > kcmStallQueueDepth with retries_total up
//	    > kcmStallRetriesDelta and that queue's depth not draining.
//
// Healthy idle (depthSum == 0) NEVER fires — that was the
// kcmLeaderIdle false-positive that restarted k0scontroller hourly.
// A counter reset, a non-leader scrape, or a stale prev snapshot
// makes the comparison inconclusive → false.
func kcmQueueStalled(prev, cur *kcmQueueSnapshot) bool {
	if prev == nil || cur == nil || !cur.Leader {
		return false
	}
	// Consecutive-scrape window only: "no progress" is only proven
	// between adjacent scrapes — a stale baseline (agent restart,
	// missed cycles, metrics outage) is inconclusive.
	gap := cur.At - prev.At
	if gap <= 0 || gap > int64(kcmSnapshotMaxGap.Seconds()) {
		return false
	}
	adds, ok := kcmDeltas(prev.Adds, cur.Adds)
	if !ok {
		return false
	}
	retries, ok := kcmDeltas(prev.Retries, cur.Retries)
	if !ok {
		return false
	}
	// (a) deep backlog with ~zero new enqueues — requires at least
	// one queue giving a real adds comparison: an empty baseline is
	// inconclusive, not "zero progress".
	var addsDelta float64
	for _, d := range adds {
		addsDelta += d
	}
	if cur.DepthSum > kcmStallDepthSum && len(adds) > 0 &&
		addsDelta <= kcmStallAddsEpsilon {
		return true
	}
	// (b) single-queue retry storm with zero depth drain.
	for q, depth := range cur.Depths {
		if depth <= kcmStallQueueDepth {
			continue
		}
		if retries[q] <= kcmStallRetriesDelta {
			continue
		}
		prevDepth, ok := prev.Depths[q]
		if !ok || depth < prevDepth {
			continue // drain observed (or no baseline) — not stalled
		}
		return true
	}
	return false
}

// loadKCMSnapshot returns the previous scrape's snapshot, or nil
// when the file is absent/corrupt — inconclusive, never fires.
func (h *Hygiene) loadKCMSnapshot() *kcmQueueSnapshot {
	data := h.readState(fileKCMQueueSnap)
	if data == "" {
		return nil
	}
	var s kcmQueueSnapshot
	if err := json.Unmarshal([]byte(data), &s); err != nil {
		return nil
	}
	return &s
}

// saveKCMSnapshot persists the scrape atomically (tmp+rename — the
// writeEpochFile contract; a torn JSON just reads as "no baseline"
// next cycle).
func (h *Hygiene) saveKCMSnapshot(s *kcmQueueSnapshot) {
	b, err := json.Marshal(s)
	if err != nil {
		return
	}
	dir := h.cfg.WatchdogStateDir
	tmp := filepath.Join(dir, ".tmp-"+fileKCMQueueSnap)
	if err := os.WriteFile(tmp, b, 0o644); err != nil {
		logger().Warn("controllerhygiene: kcm snapshot write failed",
			"path", tmp, "error", err)
		return
	}
	if err := os.Rename(tmp, filepath.Join(dir, fileKCMQueueSnap)); err != nil {
		logger().Warn("controllerhygiene: kcm snapshot install failed",
			"error", err)
	}
}

// peerHealthy reports whether the OTHER apiserver answers — the W8-CP3
// gate that proves only the controller components froze, not the whole
// control plane. Falls back to the local apiserver when no peer is
// configured (single-hub).
func (h *Hygiene) peerHealthy(ctx context.Context) bool {
	ep := h.cfg.PeerAPI
	if ep == "" {
		ep = h.cfg.SelfEndpoint
	}
	// ANY HTTP code = the apiserver event loop is alive (probeAnyCode
	// parity — a wedged apiserver is the wedge guard's problem, not
	// this check's).
	return h.cfg.probeFn(ctx, "https://"+ep+"/readyz")
}

// checkCPFreeze — W8-CP3. Restart evidence is (a) KCM or scheduler
// healthz dead for CPFreezeCycles consecutive cycles, or (b) a
// stalled KCM workqueue (W10-FIX1 kcmQueueStalled) persisting past
// CPFreezeQuietFor. The restart only fires while the peer apiserver
// stays healthy and honors Sig13Mode.
func (h *Hygiene) checkCPFreeze(ctx context.Context) {
	// W10-CP2/W10-CP5 ride this file's ungated cycle slot: Cycle()
	// dispatch lives in controllerhygiene.go, so the wave-10 checks
	// are invoked from the first W8-CP entry point — same
	// pre-uptime-gate position, every cycle.
	h.checkKineStorageHealth(ctx)
	h.checkKubeconfigCertExpiry(ctx)

	kcmOK := h.cfg.cpHealthFn(ctx, h.cfg.KCMHealthURL)
	schedOK := h.cfg.cpHealthFn(ctx, h.cfg.SchedHealthURL)

	frozen := false
	reason := ""
	switch {
	case !kcmOK || !schedOK:
		n := h.ctrInc(fileCtrCPFreeze)
		if n >= h.cfg.CPFreezeCycles {
			frozen = true
			reason = fmt.Sprintf("healthz dead %dx (kcm=%v sched=%v)",
				n, kcmOK, schedOK)
		} else {
			h.cycles.WithLabelValues(checkCPFreeze, "suspect").Inc()
			return
		}
	default:
		h.ctrReset(fileCtrCPFreeze)
	}

	// Leader-with-a-stalled-workqueue is an OR-condition: even with
	// a healthy healthz a frozen KCM scheduler loop shows up as a
	// leader holding a backlog with zero forward progress (W10-FIX1
	// — the old leader+zero-depth reading fired on every healthy
	// idle cluster). Only evaluated when the fast path didn't
	// already fire; every successful scrape refreshes the snapshot
	// the next scrape compares against.
	if !frozen {
		body, err := h.cfg.kcmMetricsFn(ctx, h.cfg.KCMMetricsURL)
		stalled := false
		if err == nil {
			if snap, parsed := parseKCMQueueSnapshot(
				body, h.cfg.nowFn().Unix()); parsed {
				stalled = kcmQueueStalled(h.loadKCMSnapshot(), snap)
				h.saveKCMSnapshot(snap)
			}
		}
		if stalled {
			if h.kcmQuietSince.IsZero() {
				h.kcmQuietSince = h.cfg.nowFn()
				h.ctrInc(fileCtrKCMQuiet)
			}
			if h.cfg.nowFn().Sub(h.kcmQuietSince) >= h.cfg.CPFreezeQuietFor {
				frozen = true
				reason = fmt.Sprintf("kcm workqueue stalled >%s",
					h.cfg.CPFreezeQuietFor)
			}
		} else {
			h.kcmQuietSince = time.Time{}
			h.ctrReset(fileCtrKCMQuiet)
		}
	}

	if !frozen {
		h.stateExit(stateCPComponentFrozen)
		h.cycles.WithLabelValues(checkCPFreeze, "ok").Inc()
		return
	}
	h.stateEnter(stateCPComponentFrozen, reason)
	// Gate: the peer apiserver must still answer — otherwise the
	// outage is bigger than a frozen component and the wedge guard
	// owns the restart story.
	if !h.peerHealthy(ctx) {
		h.suspectLog(stateCPComponentFrozen, fmt.Sprintf(
			"suspect: cp-component-frozen %s but peer apiserver unhealthy — wedge guard owns this, skip",
			reason))
		h.cycles.WithLabelValues(checkCPFreeze, "gated").Inc()
		return
	}
	if !h.rateOK(h.cfg.WatchdogStateDir, fileRateCPRestart,
		h.cfg.CPFreezeMinRestart) {
		h.suspectLog(stateCPComponentFrozen, fmt.Sprintf(
			"suspect: cp-component-frozen %s but in restart cooldown (<%dm), skip",
			reason, int(h.cfg.CPFreezeMinRestart.Minutes())))
		h.cycles.WithLabelValues(checkCPFreeze, "cooldown").Inc()
		return
	}
	switch h.cfg.Sig13Mode {
	case ModeEnforce:
		h.appendLog(fmt.Sprintf(
			"ACTION: restarting k0scontroller - cp-component-frozen %s",
			reason))
		h.rateSpend(h.cfg.WatchdogStateDir, fileRateCPRestart)
		h.ctrReset(fileCtrCPFreeze)
		h.ctrReset(fileCtrKCMQuiet)
		h.kcmQuietSince = time.Time{}
		if err := h.cfg.restartFn(ctx, h.cfg.RestartUnit); err != nil {
			h.appendLogWarn(fmt.Sprintf(
				"suspect: restart %s failed: %v", h.cfg.RestartUnit, err))
		}
		h.actions.WithLabelValues(checkCPFreeze, "restart_controller").Inc()
	case ModeDryRun:
		h.appendLog(fmt.Sprintf(
			"DRY-RUN: would restart k0scontroller - cp-component-frozen %s",
			reason))
		h.actions.WithLabelValues(checkCPFreeze, "dryrun_restart").Inc()
	}
	h.cycles.WithLabelValues(checkCPFreeze, "ok").Inc()
}

// checkPKIReloadDrift — W8-CP4. For each pair: read the on-disk leaf
// and the socket-presented leaf; drift means the file describes a
// NEWER cert (later NotAfter, or different serial with a not-older
// NotAfter) than the socket serves. Drift held for PKIDriftCycles
// consecutive cycles latches the state and restarts the owning unit
// under the last-cp-cert-restart budget.
func (h *Hygiene) checkPKIReloadDrift(ctx context.Context) {
	anyDrift := false
	for i, pair := range h.cfg.PKIDriftPairs {
		ctr := fileCtrPKIDriftPre + strconv.Itoa(i)
		disk, err := readLeafCert(pair.CertFile)
		if err != nil {
			// Cert absent — not a controller / pair not deployed on
			// this host. Reset rather than carry a stale count.
			h.ctrReset(ctr)
			continue
		}
		sock, err := h.cfg.tlsCertFn(ctx, pair.Addr)
		if err != nil {
			// Socket down is someone else's check — the drift
			// comparison is inconclusive, not evidence.
			h.ctrReset(ctr)
			continue
		}
		if !certNewerThan(disk, sock) {
			h.ctrReset(ctr)
			continue
		}
		anyDrift = true
		n := h.ctrInc(ctr)
		if n < h.cfg.PKIDriftCycles {
			continue
		}
		h.stateEnter(statePKIReloadStale, fmt.Sprintf(
			"%s newer than %s (disk notAfter=%s socket=%s)",
			pair.CertFile, pair.Addr,
			disk.NotAfter.UTC().Format(time.RFC3339),
			sock.NotAfter.UTC().Format(time.RFC3339)))
		if !h.rateOK(h.cfg.WatchdogStateDir, fileRatePKIRestart,
			h.cfg.PKIRestartInterval) {
			h.suspectLog(statePKIReloadStale, fmt.Sprintf(
				"suspect: cp-cert-reload-stale %s but in restart cooldown (<%dm), skip",
				pair.CertFile, int(h.cfg.PKIRestartInterval.Minutes())))
			continue
		}
		switch h.cfg.Sig13Mode {
		case ModeEnforce:
			h.appendLog(fmt.Sprintf(
				"ACTION: restarting %s - cp-cert-reload-stale %s newer than %s",
				pair.Unit, pair.CertFile, pair.Addr))
			h.rateSpend(h.cfg.WatchdogStateDir, fileRatePKIRestart)
			h.ctrReset(ctr)
			if err := h.cfg.restartFn(ctx, pair.Unit); err != nil {
				h.appendLogWarn(fmt.Sprintf(
					"suspect: restart %s failed: %v", pair.Unit, err))
			}
			h.actions.WithLabelValues(checkPKIDrift, "restart_unit").Inc()
		case ModeDryRun:
			h.appendLog(fmt.Sprintf(
				"DRY-RUN: would restart %s - cp-cert-reload-stale %s",
				pair.Unit, pair.CertFile))
			h.actions.WithLabelValues(checkPKIDrift, "dryrun_restart").Inc()
		}
	}
	if !anyDrift {
		h.stateExit(statePKIReloadStale)
	}
	h.cycles.WithLabelValues(checkPKIDrift, "ok").Inc()
}

// certNewerThan reports whether disk is a rotated-newer cert the
// socket has not loaded: a later NotAfter, or a different serial
// while NotAfter is not older (rotation that keeps the same window).
// An OLDER disk cert (rollback, stale file) is not drift.
func certNewerThan(disk, sock *x509.Certificate) bool {
	switch {
	case disk.SerialNumber.Cmp(sock.SerialNumber) == 0 &&
		disk.NotAfter.Equal(sock.NotAfter):
		return false // identical cert — loaded
	case disk.NotAfter.After(sock.NotAfter):
		return true
	case disk.SerialNumber.Cmp(sock.SerialNumber) != 0 &&
		disk.NotAfter.Equal(sock.NotAfter):
		return true
	}
	return false
}

// readLeafCert parses the first PEM cert block of a file.
func readLeafCert(path string) (*x509.Certificate, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	block, _ := pem.Decode(data)
	if block == nil {
		return nil, fmt.Errorf("no PEM block in %s", path)
	}
	return x509.ParseCertificate(block.Bytes)
}

// ---------------------------------------------------------------------------
// W10-CP2 — Kine SQLite WAL / store size guard
// ---------------------------------------------------------------------------

// checkKineStorageHealth measures the Kine backing store on this
// controller and keeps the WAL from growing until it fills the
// root filesystem. SQLite/Kine hosts get state.db + state.db-wal
// sizes; non-SQLite backends (embedded etcd, NATS JetStream
// filestore) get the first existing store dir summed with a bounded
// walk — both land on node_agent_kine_db_bytes /
// node_agent_kine_wal_bytes via the node-exporter textfile channel.
// A WAL over kineWALCheckpointMinBytes triggers `PRAGMA
// wal_checkpoint(TRUNCATE)` through the host sqlite3 under the
// last-kine-wal-checkpoint cooldown.
func (h *Hygiene) checkKineStorageHealth(ctx context.Context) {
	dbBytes, walBytes, ok := h.kineStoreSizes()
	if !ok {
		// No store at all — headers-only file so a vanished store
		// drops the series instead of pinning a stale size.
		h.emitKineStorageTextfile(0, 0, false)
		h.cycles.WithLabelValues(checkKineStorage, "absent").Inc()
		return
	}
	h.emitKineStorageTextfile(dbBytes, walBytes, true)
	if walBytes <= kineWALCheckpointMinBytes {
		h.cycles.WithLabelValues(checkKineStorage, "ok").Inc()
		return
	}
	if !h.rateOK(h.cfg.WatchdogStateDir, fileRateKineCheckpoint,
		kineWALCheckpointCooldown) {
		h.cycles.WithLabelValues(checkKineStorage, "checkpoint_cooldown").Inc()
		return
	}
	err := kineCheckpointFn(ctx, h.kineDBPath())
	switch {
	case errors.Is(err, errKineNoSQLite3):
		// No sqlite3 on the host — skip WITHOUT spending the
		// cooldown so a later install still gets the checkpoint.
		h.cycles.WithLabelValues(checkKineStorage, "no_sqlite3").Inc()
	case err != nil:
		h.rateSpend(h.cfg.WatchdogStateDir, fileRateKineCheckpoint)
		h.appendLogWarn(fmt.Sprintf(
			"suspect: kine wal=%.0fMiB > %dMiB but wal_checkpoint failed: %v",
			float64(walBytes)/(1<<20),
			kineWALCheckpointMinBytes>>20, err))
		h.cycles.WithLabelValues(checkKineStorage, "checkpoint_fail").Inc()
	default:
		h.rateSpend(h.cfg.WatchdogStateDir, fileRateKineCheckpoint)
		h.appendLog(fmt.Sprintf(
			"ACTION: kine wal_checkpoint(TRUNCATE) — state.db-wal %.0fMiB > %dMiB",
			float64(walBytes)/(1<<20), kineWALCheckpointMinBytes>>20))
		h.actions.WithLabelValues(checkKineStorage, "wal_checkpoint").Inc()
		h.cycles.WithLabelValues(checkKineStorage, "ok").Inc()
	}
}

// kineDBPath / kineWALPath — the SQLite/Kine store locations under
// K0sDir (<K0sDir>/db/state.db and its -wal sidecar).
func (h *Hygiene) kineDBPath() string {
	return filepath.Join(h.cfg.K0sDir, "db", "state.db")
}

func (h *Hygiene) kineWALPath() string {
	return h.kineDBPath() + "-wal"
}

// kineStoreSizes reports the store sizes: state.db + state.db-wal
// when the SQLite backend is present, else the summed size of the
// first existing non-SQLite store dir (embedded etcd / NATS
// JetStream filestore — WAL stays 0 there). ok=false when no store
// exists at all.
func (h *Hygiene) kineStoreSizes() (dbBytes, walBytes int64, ok bool) {
	if fi, err := os.Stat(h.kineDBPath()); err == nil && !fi.IsDir() {
		dbBytes = fi.Size()
		if w, werr := os.Stat(h.kineWALPath()); werr == nil && !w.IsDir() {
			walBytes = w.Size()
		}
		return dbBytes, walBytes, true
	}
	for _, dir := range []string{
		filepath.Join(h.cfg.K0sDir, "etcd"),
		filepath.Join(h.cfg.K0sDir, "nats"),
	} {
		if fi, err := os.Stat(dir); err == nil && fi.IsDir() {
			total, _ := dirSizeBounded(dir, kineStoreMaxFiles)
			return total, 0, true
		}
	}
	return 0, 0, false
}

// dirSizeBounded sums regular-file sizes under root, stopping after
// maxFiles entries — etcd member dirs stay small; the cap keeps a
// pathological tree from stalling the cycle. Unreadable entries are
// skipped (best-effort gauge).
func dirSizeBounded(root string, maxFiles int) (int64, error) {
	var total int64
	n := 0
	err := filepath.WalkDir(root, func(_ string, d fs.DirEntry, err error) error {
		if err != nil {
			return nil // skip unreadable entries
		}
		if d.IsDir() {
			return nil
		}
		n++
		if n > maxFiles {
			return fs.SkipAll
		}
		if info, ierr := d.Info(); ierr == nil {
			total += info.Size()
		}
		return nil
	})
	return total, err
}

// sqlite3WALCheckpoint is the default kineCheckpointFn: run
// `PRAGMA wal_checkpoint(TRUNCATE)` through the host sqlite3 CLI.
// busy_timeout=5000 caps lock waits at 5s — effectively
// non-blocking for the agent cycle (a busy WAL just errors out and
// retries after the cooldown). errKineNoSQLite3 when the binary is
// absent so the caller skips without spending the cooldown.
func sqlite3WALCheckpoint(ctx context.Context, dbPath string) error {
	bin, err := exec.LookPath("sqlite3")
	if err != nil {
		return errKineNoSQLite3
	}
	cctx, cancel := context.WithTimeout(ctx, kineCheckpointBudget)
	defer cancel()
	cmd := exec.CommandContext(cctx, bin, dbPath,
		"PRAGMA busy_timeout=5000; PRAGMA wal_checkpoint(TRUNCATE);")
	cmd.Env = scrubSystemdEnv(os.Environ())
	out, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("sqlite3 wal_checkpoint: %w: %s",
			err, strings.TrimSpace(string(out)))
	}
	return nil
}

// emitKineStorageTextfile writes the two kine gauges — present=false
// emits headers only so the series goes absent rather than stale.
func (h *Hygiene) emitKineStorageTextfile(dbBytes, walBytes int64, present bool) {
	var p wave10Prom
	if present {
		p.gauge(kineDBBytesMetric,
			"Size in bytes of the Kine backing store (state.db, or "+
				"the etcd/JetStream filestore total on non-SQLite backends).",
			float64(dbBytes))
		p.gauge(kineWALBytesMetric,
			"Size in bytes of the Kine SQLite WAL (state.db-wal); "+
				"absent on non-SQLite backends.",
			float64(walBytes))
	} else {
		p.header(kineDBBytesMetric,
			"Size in bytes of the Kine backing store (state.db, or "+
				"the etcd/JetStream filestore total on non-SQLite backends).")
		p.header(kineWALBytesMetric,
			"Size in bytes of the Kine SQLite WAL (state.db-wal); "+
				"absent on non-SQLite backends.")
	}
	h.writeWave10Prom("node-agent-kine-storage.prom", p.String())
}

// ---------------------------------------------------------------------------
// W10-CP5 — embedded kubeconfig client certificate expiry
// ---------------------------------------------------------------------------

// kubeconfigCertPaths — the kubeconfigs carrying embedded client
// certs: the k0s admin/ccm/scheduler confs under pki/ plus the
// kubelet's own kubeconfig at the K0sDir root. controller-manager.conf
// is scanned alongside ccm.conf — k0s has shipped both names for the
// KCM identity; missing files are skipped.
func (h *Hygiene) kubeconfigCertPaths() []string {
	k0s := h.cfg.K0sDir
	return []string{
		filepath.Join(k0s, "pki", "admin.conf"),
		filepath.Join(k0s, "pki", "ccm.conf"),
		filepath.Join(k0s, "pki", "controller-manager.conf"),
		filepath.Join(k0s, "pki", "scheduler.conf"),
		filepath.Join(k0s, "kubelet.conf"),
	}
}

// checkKubeconfigCertExpiry parses client-certificate-data (and
// file-referenced client certs) out of the k0s kubeconfigs and
// exports node_agent_kubeconfig_cert_min_days_remaining — the
// minimum NotAfter horizon across every embedded client cert.
// Inside kubeconfigCertMinDays it latches
// state-kubeconfig-cert-expiring (surfaces via
// node_host_agent_watchdog_state) and suspect-logs; absent or
// unparseable files are skipped silently.
func (h *Hygiene) checkKubeconfigCertExpiry(_ context.Context) {
	now := h.cfg.nowFn()
	minDays := math.Inf(1)
	seen := 0
	for _, path := range h.kubeconfigCertPaths() {
		certs, err := kubeconfigClientCerts(path)
		if err != nil {
			continue
		}
		for _, c := range certs {
			seen++
			if d := c.NotAfter.Sub(now).Hours() / 24; d < minDays {
				minDays = d
			}
		}
	}
	var p wave10Prom
	if seen == 0 {
		p.header(certDaysMetric,
			"Minimum days until the soonest-expiring embedded client "+
				"certificate across the k0s kubeconfigs (admin/ccm/"+
				"scheduler/kubelet).")
		h.stateExit(stateKubeCertExpiring) // no certs → nothing to expire
		h.cycles.WithLabelValues(checkKubeCert, "no_certs").Inc()
	} else {
		p.gauge(certDaysMetric,
			"Minimum days until the soonest-expiring embedded client "+
				"certificate across the k0s kubeconfigs (admin/ccm/"+
				"scheduler/kubelet).",
			minDays)
		h.cycles.WithLabelValues(checkKubeCert, "ok").Inc()
		if minDays < kubeconfigCertMinDays {
			h.stateEnter(stateKubeCertExpiring, fmt.Sprintf(
				"client cert expires in %.1fd", minDays))
			h.suspectLog(stateKubeCertExpiring, fmt.Sprintf(
				"kubeconfig-cert-expiring: embedded client cert "+
					"NotAfter in %.1f days (<%d)",
				minDays, int(kubeconfigCertMinDays)))
		} else {
			h.stateExit(stateKubeCertExpiring)
		}
	}
	h.writeWave10Prom("node-agent-kubeconfig-cert.prom", p.String())
}

// kubeconfigClientCerts extracts every embedded client certificate
// from a kubeconfig: client-certificate-data fields (base64 PEM,
// clientcmd-decoded) plus file-referenced client-certificate paths
// resolved relative to the kubeconfig dir (loadCreds parity).
// Unparseable files/certs are skipped, never fatal.
func kubeconfigClientCerts(path string) ([]*x509.Certificate, error) {
	kc, err := clientcmd.LoadFromFile(path)
	if err != nil {
		return nil, err
	}
	var certs []*x509.Certificate
	for _, a := range kc.AuthInfos {
		var pemBytes []byte
		switch {
		case len(a.ClientCertificateData) > 0:
			pemBytes = a.ClientCertificateData
		case a.ClientCertificate != "":
			b, rerr := os.ReadFile(resolveRel(path, a.ClientCertificate))
			if rerr != nil {
				continue
			}
			pemBytes = b
		default:
			continue
		}
		for rest := pemBytes; ; {
			var block *pem.Block
			block, rest = pem.Decode(rest)
			if block == nil {
				break
			}
			if block.Type != "CERTIFICATE" {
				continue
			}
			if c, perr := x509.ParseCertificate(block.Bytes); perr == nil {
				certs = append(certs, c)
			}
		}
	}
	return certs, nil
}

// ---------------------------------------------------------------------------
// W10 metric emission — node-exporter textfile channel
// ---------------------------------------------------------------------------

// wave10TextfileDir resolves the node-exporter textfile drop dir:
// K0sDir is <hostRoot>/var/lib/k0s, so the dir is its sibling
// <hostRoot>/var/lib/node-exporter/textfile (DaemonSet:
// /host/var/lib/..., standalone: /var/lib/...). The override wins
// for tests.
func (h *Hygiene) wave10TextfileDir() string {
	if kineTextfileDirOverride != "" {
		return kineTextfileDirOverride
	}
	return filepath.Join(filepath.Dir(h.cfg.K0sDir),
		"node-exporter", "textfile")
}

// writeWave10Prom atomically installs content as <dir>/<name>
// (tmp+rename — node_exporter only reads complete .prom files; the
// .tmp suffix keeps the staging file out of the *.prom glob).
// Failures go through suspectLog — a broken/missing mount must not
// spam the watchdog tail every cycle.
func (h *Hygiene) writeWave10Prom(name, content string) {
	dir := h.wave10TextfileDir()
	fail := func(err error) {
		h.suspectLog("wave10-textfile", fmt.Sprintf(
			"wave10 textfile %s unwritable (dir=%s): %v", name, dir, err))
	}
	if err := os.MkdirAll(dir, 0o755); err != nil {
		fail(err)
		return
	}
	tmp := filepath.Join(dir, "."+name+".tmp")
	if err := os.WriteFile(tmp, []byte(content), 0o644); err != nil {
		fail(err)
		return
	}
	if err := os.Rename(tmp, filepath.Join(dir, name)); err != nil {
		fail(err)
	}
}

// wave10Prom accumulates HELP/TYPE/sample lines for one textfile —
// headers once per family (the textfile collector rejects duplicate
// HELP/TYPE). kinedb's promBuf parity, kept file-local.
type wave10Prom struct {
	b    strings.Builder
	seen map[string]bool
}

func (p *wave10Prom) header(name, help string) {
	if p.seen == nil {
		p.seen = map[string]bool{}
	}
	if p.seen[name] {
		return
	}
	p.seen[name] = true
	fmt.Fprintf(&p.b, "# HELP %s %s\n# TYPE %s gauge\n", name, help, name)
}

func (p *wave10Prom) gauge(name, help string, v float64) {
	p.header(name, help)
	fmt.Fprintf(&p.b, "%s %s\n", name,
		strconv.FormatFloat(v, 'f', -1, 64))
}

func (p *wave10Prom) String() string { return p.b.String() }
