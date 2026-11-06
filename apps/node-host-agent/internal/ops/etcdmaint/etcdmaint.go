// Package etcdmaint ports scripts/rescue-etcd.sh — rescues a k0s
// controller etcd that hit the backend quota.
//
// Symptom: every write fails with
//
//	Error from server: etcdserver: mvcc: database space exceeded
//
// (no new pods, no deletes, control plane crash-looping). Run as root
// ON the controller host. The flow is the script's:
//
//  1. print `endpoint status` + `alarm list` (before snapshot)
//  2. `compact --physical <head revision>` — drop MVCC history
//  3. try ONLINE `defrag`; re-read status — when it errored or
//     dbSize > dbSizeInUse*2, fall back to OFFLINE defrag (~2min
//     downtime: stop k0scontroller, run the same etcd standalone on
//     the same data-dir, defrag, kill it, restart the service)
//  4. print post-defrag status
//  5. `alarm disarm` — the NOSPACE alarm never self-clears
//  6. write canary (put/del /__rescue_canary) + final status/advice
//
// Field notes carried over from the script (PAS-382, 2026-08-23):
// online defrag can report OK yet reclaim nothing while the apiserver
// is crash-looping writes — hence the dbSize/dbSizeInUse comparison —
// and `alarm disarm` is mandatory because NOSPACE never clears itself.
package etcdmaint

import (
	"context"
	"errors"
	"fmt"
	"io"
	"strconv"
)

// Run executes the six-step rescue flow, printing progress in the
// script's phrasing. Returns an error (→ exit 1) on any fatal step —
// including a failed write canary, matching the script's exit-1 tail.
func Run(ctx context.Context, cfg Config, out io.Writer) error {
	cfg.applyDefaults()
	r := newRescuer(cfg, out)

	// [1/6] Before-snapshot: table for humans, json for the numbers,
	// then the alarm list (|| true in the script).
	_, _ = fmt.Fprintln(out, "[1/6] ===== BEFORE RESCUE =====")
	tbl, err := r.etcdctl(ctx, "", "endpoint", "status", "-w", "table")
	if err != nil {
		return fmt.Errorf("endpoint status: %w", err)
	}
	_, _ = out.Write(tbl)
	st, err := r.status(ctx)
	if err != nil {
		return fmt.Errorf("endpoint status -w json: %w", err)
	}
	_, _ = fmt.Fprintf(out, "dbSize=%d dbSizeInUse=%d revision=%d\n",
		st.DBSize, st.DBSizeInUse, st.Revision)
	r.printAlarmList(ctx, "alarm list: (none)")

	// [2/6] Compact all MVCC history to the head revision. The
	// script's `|| echo` tolerated ANY compact failure — keep that,
	// but print the real error: a timeout/auth/network failure must
	// not masquerade as "already compacted".
	_, _ = fmt.Fprintf(out, "[2/6] >>> compact to revision %d\n", st.Revision)
	if _, err := r.etcdctl(ctx, "", "compact", "--physical",
		strconv.FormatInt(st.Revision, 10)); err != nil {
		_, _ = fmt.Fprintf(out, "(compact error — skipping: %v)\n", err)
	}

	// [3/6] Online defrag first (no downtime). Field-proven caveat:
	// it can report OK yet reclaim nothing while the apiserver is
	// crash-looping writes, so the decision uses dbSize vs
	// dbSizeInUse — and a defrag error also forces offline.
	needOffline := cfg.ForceOffline
	switch {
	case cfg.ForceOffline && cfg.OnlineOnly:
		// Contradictory flags — OnlineOnly is the safety promise
		// (no control-plane stop), so it degrades the flag pair to
		// a plain online attempt.
		_, _ = fmt.Fprintln(out, "[3/6] >>> --force-offline ignored under OnlineOnly")
		needOffline = false
	case cfg.ForceOffline:
		_, _ = fmt.Fprintln(out, "[3/6] >>> --force-offline: skipping online defrag")
	}
	if !needOffline {
		_, _ = fmt.Fprintln(out, "[3/6] >>> trying online defrag...")
		if _, err := r.etcdctl(ctx, onlineDefragTimeout, "defrag"); err != nil {
			_, _ = fmt.Fprintln(out,
				">>> online defrag failed/missing — falling back to offline")
			needOffline = true
		} else if st2, serr := r.status(ctx); serr != nil {
			return fmt.Errorf("endpoint status after defrag: %w", serr)
		} else if st2.DBSize > st2.DBSizeInUse*2 {
			_, _ = fmt.Fprintf(out,
				">>> online defrag reclaimed too little "+
					"(file=%d, in-use=%d) → OFFLINE DEFRAG\n",
				st2.DBSize, st2.DBSizeInUse)
			needOffline = true
		}
	}
	offlinePending := false
	if needOffline {
		if cfg.OnlineOnly {
			// The systemctl-stop + standalone-etcd block is a
			// planned-downtime action — never taken by a background
			// loop. Disarm + canary still run below (they often
			// restore writes already); the tail then reports the
			// remaining bloat as an error.
			_, _ = fmt.Fprintln(out, ">>> ONLINE-ONLY: offline defrag "+
				"required but forbidden — needs a manual rescue-etcd run")
			offlinePending = true
		} else if err := r.offlineDefrag(ctx); err != nil {
			return err // service restart already handled by the defer
		}
	}

	// [4/6] Post-defrag numbers (display only — a flaky read here
	// must not mask the real health check, the canary).
	_, _ = fmt.Fprintln(out, "[4/6] Post-defrag status:")
	if st3, serr := r.status(ctx); serr == nil {
		_, _ = fmt.Fprintf(out, "dbSize=%d dbSizeInUse=%d revision=%d\n",
			st3.DBSize, st3.DBSizeInUse, st3.Revision)
	} else {
		_, _ = fmt.Fprintf(out, "(endpoint status error: %v)\n", serr)
	}

	// [5/6] NOSPACE alarms never self-clear after space is freed —
	// disarm is mandatory. Fatal like the script's `set -e`.
	_, _ = fmt.Fprintln(out, "[5/6] >>> alarm disarm (NOSPACE never self-clears)")
	if _, err := r.etcdctl(ctx, "", "alarm", "disarm"); err != nil {
		return fmt.Errorf("alarm disarm: %w", err)
	}
	r.printAlarmList(ctx, "alarm list: (clean)")

	// [6/6] Write canary — the actual proof etcd accepts writes
	// again. A failure exits 1 like the script.
	_, _ = fmt.Fprintln(out, "[6/6] >>> verifying writes (canary put/del)")
	if _, err := r.etcdctl(ctx, "", "put", canaryKey, "ok"); err != nil {
		return fmt.Errorf(">>> WRITE STILL FAILING — "+
			"check alarm/status manually! (put: %w)", err)
	}
	if _, err := r.etcdctl(ctx, "", "del", canaryKey); err != nil {
		return fmt.Errorf(">>> WRITE STILL FAILING — "+
			"check alarm/status manually! (del: %w)", err)
	}
	_, _ = fmt.Fprintln(out, ">>> WRITE OK — etcd is back")

	_, _ = fmt.Fprintln(out, "===== AFTER RESCUE =====")
	if tbl, err := r.etcdctl(ctx, "",
		"endpoint", "status", "-w", "table"); err == nil {
		_, _ = out.Write(tbl)
	}
	_, _ = fmt.Fprintf(out, `
===== DONE =====
Next steps:
- After TTL GC finishes reaping events (a few hours), re-run this to reclaim more
- Check control-plane crash-loops: systemctl status %s
- If the service keeps restarting: journalctl -u %s and dmesg | grep -i oom
`, r.cfg.Svc, r.cfg.Svc)
	if offlinePending {
		return errors.New("etcd still bloated — offline defrag " +
			"required (rerun rescue-etcd manually, without OnlineOnly)")
	}
	return nil
}
