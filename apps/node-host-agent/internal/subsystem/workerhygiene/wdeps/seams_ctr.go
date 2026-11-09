// seams_ctr — the Ctr containerd exec group of the Seams test-seam surface, split out of
// seams.go (which keeps the Seams aggregate + applyDefaults
// orchestration).
package wdeps

import (
	"context"
	"errors"
	"strings"
	"time"
)

// Ctr holds the ONE containerd content seam — the exec every `k0s
// ctr` mutation (image removal, stale ingest ref GC,
// watermark-gated content prune) shares through the systemd exec
// wrapper. The named methods below build each command's argv, so
// call sites keep their readable names and tests stub exactly one
// func.
type Ctr struct {
	// Exec runs one argv through the systemd exec wrapper — a
	// full-argv passthrough (argv[0] is the binary name, the
	// Systemd.Exec name+args shape). nil → Systemd.Exec default; a
	// nil Systemd client errors the same "no systemd client wired".
	// Seam.
	Exec func(ctx context.Context, argv ...string) error
	// ExecOut is Exec for the `k0s ctr` READS that need stdout back
	// (lease listing) — the same transport, output returned. nil →
	// Systemd.Exec default. Seam.
	ExecOut func(ctx context.Context, argv ...string) (string, error)
}

// RmImage removes one image from the k8s.io containerd namespace —
// the corrupted-layer remedy (37), `k0s ctr --namespace k8s.io
// images rm --sync <image>` over the Exec seam.
func (s *Ctr) RmImage(ctx context.Context, image string) error {
	return s.Exec(ctx,
		"k0s", "ctr", "--namespace", "k8s.io", "images", "rm", "--sync", image)
}

// RmIngest removes one stale ingest ref — `k0s ctr -n k8s.io
// content ingest rm <ref>` over the Exec seam (A3).
func (s *Ctr) RmIngest(ctx context.Context, ref string) error {
	return s.Exec(ctx,
		"k0s", "ctr", "-n", "k8s.io", "content", "ingest", "rm", ref)
}

// PruneContent runs the store-wide content GC — `k0s ctr -n k8s.io
// content prune` over the Exec seam. It only fires while
// /var/lib/k0s sits above the high watermark, on the
// last-content-gc 6h budget.
func (s *Ctr) PruneContent(ctx context.Context) error {
	return s.Exec(ctx,
		"k0s", "ctr", "-n", "k8s.io", "content", "prune")
}

// CtrLease is one `k0s ctr -n k8s.io leases ls` row — the lease id,
// its created-at stamp and whether it carries a gc.expire label
// (containerd's own "may GC after T" annotation — a lease WITHOUT
// the label is orphaned forever unless a caller deletes it).
type CtrLease struct {
	ID       string
	Created  time.Time
	HasGCExp bool
}

// Leases lists the containerd leases — `k0s ctr -n k8s.io leases ls`
// over the ExecOut seam, ParseCtrLeases'd. The orphan-lease reaper's
// derived read: stubbing the one exec covers the parser for real.
func (s *Ctr) Leases(ctx context.Context) ([]CtrLease, error) {
	out, err := s.ExecOut(ctx,
		"k0s", "ctr", "-n", "k8s.io", "leases", "ls")
	if err != nil {
		return nil, err
	}
	return ParseCtrLeases(out), nil
}

// RmLease removes one lease — `k0s ctr -n k8s.io leases rm <id>`
// over the Exec seam (no output needed).
func (s *Ctr) RmLease(ctx context.Context, id string) error {
	return s.Exec(ctx,
		"k0s", "ctr", "-n", "k8s.io", "leases", "rm", id)
}

// ParseCtrLeases parses `ctr leases ls` table output: a header row,
// then one lease per line — "ID CREATED-AT-STAMP LABELS" where the
// stamp is Go's time.String form ("2006-01-02 15:04:05.999999999
// +0000 UTC") and LABELS is the trailing key=value blob (possibly
// empty). Unparseable rows are skipped — a garbled line is never
// lease evidence.
func ParseCtrLeases(out string) []CtrLease {
	var leases []CtrLease
	for _, line := range strings.Split(out, "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "ID") {
			continue
		}
		f := strings.Fields(line)
		if len(f) < 2 {
			continue
		}
		var l CtrLease
		l.ID = f[0]
		l.HasGCExp = strings.Contains(line, "containerd.io/gc.expire")
		// The created-at stamp is the first "YYYY-MM-DD" field plus
		// the time field that follows it; fractional seconds and the
		// trailing zone fields are optional noise.
		for i := 1; i+1 < len(f); i++ {
			if len(f[i]) != 10 || f[i][4] != '-' || f[i][7] != '-' {
				continue
			}
			ts := f[i] + " " + f[i+1]
			if j := strings.Index(ts, "+"); j > 0 {
				ts = strings.TrimSpace(ts[:j])
			}
			if t, err := time.ParseInLocation("2006-01-02 15:04:05", ts, time.UTC); err == nil {
				l.Created = t
			}
			break
		}
		leases = append(leases, l)
	}
	return leases
}

func (s *Ctr) applyDefaults(c *Config) {
	if s.Exec == nil {
		sd := c.Systemd
		s.Exec = func(ctx context.Context, argv ...string) error {
			if sd == nil {
				return errors.New("no systemd client wired")
			}
			_, err := sd.Exec(ctx, argv[0], argv[1:]...)
			return err
		}
	}
	if s.ExecOut == nil {
		sd := c.Systemd
		s.ExecOut = func(ctx context.Context, argv ...string) (string, error) {
			if sd == nil {
				return "", errors.New("no systemd client wired")
			}
			return sd.Exec(ctx, argv[0], argv[1:]...)
		}
	}
}

// applyDefaults fills the Cilium group's production implementation —
// just the UnixGet socket GET now; the WG/service-map reads are the
// derived methods on the group (they read s.UnixGet at CALL time so
// a test re-stub of the socket GET still reaches them).
