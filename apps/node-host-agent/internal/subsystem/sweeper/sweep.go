// sweep.go — one cleanup cycle: the pvc-* candidate walk with every
// fail-closed belt (name check, min-age, MaxDelete cap, Released-PV
// claimRef/finalizer/delete chain, NotFound re-GET and the double
// mount-table guard) before any rm.
package sweeper

import (
	"context"
	"os"

	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
)

// Sweep executes one cleanup cycle. All fail-closed decisions are
// counted under skips{reason} and logged; the cycle result lands on
// cycles{result}.
func (s *Sweeper) Sweep(ctx context.Context) {
	log := logger()
	start := s.cfg.Clock.Now()
	defer func() { s.duration.Set(s.cfg.Clock.Now().Sub(start).Seconds()) }()

	fi, err := os.Stat(s.cfg.BaseDir)
	if err != nil || !fi.IsDir() {
		log.Info("skip cycle: base dir absent", "base", s.cfg.BaseDir)
		s.cycles.WithLabelValues("ok").Inc()
		return
	}

	uStart, err := s.cfg.statfsFn(s.cfg.BaseDir)
	if err == nil {
		log.Info("nodefs used before sweep", "gib", float64(uStart)/(1<<30))
	} else {
		log.Debug("nodefs statfs failed — before/after usage unavailable",
			"base", s.cfg.BaseDir, "error", err)
	}

	// PV list once per cycle. An empty list while pvc-* dirs exist on
	// disk is abnormal → ABORT the whole cycle (fail closed).
	dirs, err := s.listPVDirs()
	if err != nil {
		log.Error("ABORT: cannot list base dir", "error", err)
		s.cycles.WithLabelValues("abort").Inc()
		return
	}
	if len(dirs) == 0 {
		// No pvc-* candidates on disk → nothing can match a PV, so
		// skip the whole-cluster PV list entirely (the common case:
		// orphan dirs are the exception, not the norm).
		s.dirsExamined.Set(0)
		s.cycles.WithLabelValues("ok").Inc()
		log.Info("sweep done", "dirs", 0, "deleted", 0)
		return
	}
	apiCtx, cancel := s.apiCtx(ctx)
	pvList, err := s.cfg.Client.CoreV1().PersistentVolumes().
		List(apiCtx, metav1.ListOptions{})
	cancel()
	if err != nil {
		log.Error("ABORT: cannot list PVs", "error", err)
		s.cycles.WithLabelValues("abort").Inc()
		return
	}
	if len(pvList.Items) == 0 && len(dirs) > 0 {
		log.Error("ABORT: pvlist empty but pvc-* dirs exist — suspected API error",
			"dirs", len(dirs))
		s.cycles.WithLabelValues("abort").Inc()
		return
	}
	pvByName := make(map[string]*corev1.PersistentVolume, len(pvList.Items))
	for i := range pvList.Items {
		pvByName[pvList.Items[i].Name] = &pvList.Items[i]
	}

	// Host mount table parsed once per cycle — the rm
	// --one-file-system guard consulted per candidate below (was:
	// re-read + re-parsed for every dir). An unreadable table fails
	// closed on every candidate. The snapshot is only the first
	// belt: the table is re-read immediately before each rm — a
	// mount created inside a candidate dir mid-sweep is invisible
	// to this once-per-cycle read (see the pre-rm guard below).
	mounts, mountsErr := s.mountPoints()

	ndel := 0
	ndir := 0
	for _, d := range dirs {
		if ctx.Err() != nil {
			// Record the interrupted cycle before bailing — the
			// plain return used to leave the cycle uncounted and
			// the examined gauge stale.
			log.Info("ABORT: context cancelled mid-sweep",
				"examined", ndir, "error", ctx.Err())
			s.dirsExamined.Set(float64(ndir))
			s.cycles.WithLabelValues("abort").Inc()
			return
		}
		ndir++
		name := d.Name()
		// Name must be exactly pvc-<uuid> — the last deletion belt.
		if !pvcNameRe.MatchString(name) {
			log.Info("SKIP: not a pvc-<uuid> name", "dir", name)
			s.skips.WithLabelValues(skipNameMismatch).Inc()
			continue
		}
		pv, pvPresent := pvByName[name]

		// Dir must be older than MinAge — avoids racing PV provisioning.
		info, err := d.Info()
		if err != nil {
			log.Info("SKIP: stat failed", "dir", name, "error", err)
			s.skips.WithLabelValues(skipStatError).Inc()
			continue
		}
		if s.cfg.Clock.Now().Sub(info.ModTime()) <= s.cfg.MinAge {
			log.Info("SKIP: younger than min age", "dir", name,
				"minAge", s.cfg.MinAge.String())
			s.skips.WithLabelValues(skipTooYoung).Inc()
			continue
		}

		// MaxDelete bounds the destructive half of the cycle — EVERY
		// destructive op spends a slot: the Released-PV object
		// delete below AND the dir rm after the re-GET (a
		// Released-PV pair therefore costs 2). Checked before the
		// PV branch and re-checked before the rm, so a PV delete
		// that lands the cap can't get a free dir rm on top.
		if ndel >= s.cfg.MaxDelete {
			log.Info("STOP: cap MAX_DELETE reached", "maxDelete", s.cfg.MaxDelete)
			break
		}

		if pvPresent {
			// PV object still exists — only Released+Delete is an
			// orphan (provisioner died mid-flight, incident 2026-10-29).
			// Bound/Available/Retain → dir in use or owned data, skip.
			if pv.Status.Phase != corev1.VolumeReleased ||
				pv.Spec.PersistentVolumeReclaimPolicy != corev1.PersistentVolumeReclaimDelete {
				// The steady state for every dir bound to a live PV —
				// Debug, not Info, or a healthy node would log every
				// pvc-* dir every cycle.
				log.Debug("SKIP: PV exists, not Released+Delete — dir in use",
					"dir", name, "pv", name,
					"phase", pv.Status.Phase,
					"reclaimPolicy", pv.Spec.PersistentVolumeReclaimPolicy)
				s.skips.WithLabelValues(skipPVInUse).Inc()
				continue
			}
			// Released = PVC deleted — verify claimRef PVC is
			// explicitly NotFound before acting (any API error → skip).
			var cns, cname string
			if pv.Spec.ClaimRef != nil {
				cns = pv.Spec.ClaimRef.Namespace
				cname = pv.Spec.ClaimRef.Name
			}
			if cns != "" && cname != "" {
				apiCtx, cancel := s.apiCtx(ctx)
				_, err := s.cfg.Client.CoreV1().PersistentVolumeClaims(cns).
					Get(apiCtx, cname, metav1.GetOptions{})
				cancel()
				switch {
				case apierrors.IsNotFound(err):
					// claimRef clearly gone — proceed.
				case err == nil:
					log.Info("SKIP: PV Released but claimRef PVC still exists",
						"dir", name, "pvc", cns+"/"+cname)
					s.skips.WithLabelValues(skipClaimRefUnclear).Inc()
					continue
				default:
					log.Info("SKIP: PV Released but claimRef PVC not clearly gone",
						"dir", name, "pvc", cns+"/"+cname, "error", err)
					s.skips.WithLabelValues(skipClaimRefUnclear).Inc()
					continue
				}
			}
			// A Released PV can hold the pv-protection finalizer when
			// the provisioner was evicted at the wrong moment — strip,
			// then delete; the re-GET below returns NotFound → rm dir.
			log.Info("PV Released+Delete, claimRef gone — deleting PV object",
				"pv", name, "pvc", orDash(cns)+"/"+orDash(cname))
			apiCtx, cancel := s.apiCtx(ctx)
			_, err = s.cfg.Client.CoreV1().PersistentVolumes().Patch(apiCtx, name,
				types.MergePatchType,
				[]byte(`{"metadata":{"finalizers":null}}`),
				metav1.PatchOptions{})
			cancel()
			if err != nil {
				log.Info("SKIP: patch finalizers failed", "dir", name, "error", err)
				s.skips.WithLabelValues(skipPVPatchFailed).Inc()
				continue
			}
			apiCtx, cancel = s.apiCtx(ctx)
			err = s.cfg.Client.CoreV1().PersistentVolumes().
				Delete(apiCtx, name, metav1.DeleteOptions{})
			cancel()
			if err != nil {
				log.Info("SKIP: delete pv failed", "dir", name, "error", err)
				s.skips.WithLabelValues(skipPVDeleteFailed).Inc()
				continue
			}
			// The PV object delete is a destructive op too — it
			// spends a MaxDelete slot (the comment at the cap
			// check explains why both ops count).
			ndel++
		}

		// Re-check: delete only on an explicit NotFound — a PV that
		// reappeared or ANY other API error → skip.
		apiCtx, cancel = s.apiCtx(ctx)
		_, err = s.cfg.Client.CoreV1().PersistentVolumes().
			Get(apiCtx, name, metav1.GetOptions{})
		cancel()
		if err == nil {
			log.Info("SKIP: PV still present on re-GET — dir kept",
				"dir", name, "pv", name)
			s.skips.WithLabelValues(skipPVStillPresent).Inc()
			continue
		}
		if !apierrors.IsNotFound(err) {
			log.Info("SKIP: get pv error, not a clear NotFound",
				"dir", name, "error", err)
			s.skips.WithLabelValues(skipPVGetError).Inc()
			continue
		}

		// Mount-boundary guard: any mount point at or inside the dir →
		// never remove. An unreadable mount table fails closed too.
		dirPath := s.cfg.BaseDir + "/" + name
		if mountsErr != nil {
			log.Info("SKIP: cannot read host mount table",
				"dir", name, "error", mountsErr)
			s.skips.WithLabelValues(skipMountsUnread).Inc()
			continue
		}
		if mountedInside(dirPath, mounts) {
			log.Info("SKIP: mount found inside dir", "dir", name)
			s.skips.WithLabelValues(skipMounted).Inc()
			continue
		}

		// Last-belt re-verify: `mounts` is a cycle-start snapshot —
		// a mount created inside this dir mid-sweep (a pod volume
		// attaching between the snapshot and now) is invisible to
		// it. Re-read the table immediately before the destructive
		// rm: one read+parse per delete candidate, cheap against
		// rm -rf'ing a live mount's contents. Unreadable fails
		// closed, same as the snapshot path.
		fresh, ferr := s.mountPoints()
		if ferr != nil {
			log.Info("SKIP: cannot re-read host mount table before rm",
				"dir", name, "error", ferr)
			s.skips.WithLabelValues(skipMountsUnread).Inc()
			continue
		}
		if mountedInside(dirPath, fresh) {
			log.Info("SKIP: mount appeared inside dir mid-sweep",
				"dir", name)
			s.skips.WithLabelValues(skipMounted).Inc()
			continue
		}
		// The PV delete above may have just spent the last
		// MaxDelete slot — re-check so one candidate can't burn
		// two ops past the cap.
		if ndel >= s.cfg.MaxDelete {
			log.Info("STOP: cap MAX_DELETE reached", "maxDelete", s.cfg.MaxDelete)
			break
		}

		u0, _ := s.cfg.statfsFn(s.cfg.BaseDir)
		log.Info("DELETE: PV absent, dir older than min age",
			"dir", dirPath, "pv", name)
		if err := os.RemoveAll(dirPath); err != nil {
			log.Error("rm dir failed", "dir", name, "error", err)
			continue
		}
		ndel++
		s.dirsDeleted.Inc()
		u1, err := s.cfg.statfsFn(s.cfg.BaseDir)
		if err == nil && u1 < u0 {
			freed := u0 - u1
			s.bytesFreed.Add(float64(freed))
			log.Info("dir removed", "dir", name, "freedGiB", float64(freed)/(1<<30))
		}
	}

	s.dirsExamined.Set(float64(ndir))
	s.cycles.WithLabelValues("ok").Inc()
	uEnd, err := s.cfg.statfsFn(s.cfg.BaseDir)
	if err == nil {
		log.Info("sweep done", "dirs", ndir, "deleted", ndel,
			"nodefsGiB_before", float64(uStart)/(1<<30),
			"nodefsGiB_after", float64(uEnd)/(1<<30))
		return
	}
	log.Info("sweep done", "dirs", ndir, "deleted", ndel)
}

func orDash(s string) string {
	if s == "" {
		return "?"
	}
	return s
}
