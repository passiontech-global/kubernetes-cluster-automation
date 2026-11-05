// worker_init.go — `concourse-worker-init`: port of the init-rm half
// of the values.yaml script (btrfs cleanup, selective wipe, shared-
// cache scaffold, runc wrapper install).
//
// Order and error semantics match `bash -ce` exactly:
//   - The btrfs subvolume cleanup is fail-open — every command in the
//     script carries `|| true`, so a missing btrfs binary or a
//     non-btrfs work dir (ext4, openebs-hostpath) degrades to a no-op
//     instead of failing the init.
//   - Everything after it is fail-closed: rm/mkdir/chown/chmod/cp run
//     under `set -e`, so errors here are returned, never swallowed.
package concourseinit

import (
	"context"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"
)

// btrfsCmdTimeout bounds each btrfs invocation — a wedged btrfs
// binary or filesystem must not stall the init for the caller's
// whole ctx budget.
const btrfsCmdTimeout = 60 * time.Second

// Config carries the init knobs — the zero value IS the production
// config (same convention as concoursecache.ConcourseCacheConfig).
//
// OwnerUID/OwnerGID -1 skips chown entirely for unprivileged test
// runs; the zero value is NOT "chown to root" — chown-to-root was
// never a supported mode of the script.
type Config struct {
	WorkDir    string // default DefaultWorkDir
	RuncDir    string // default DefaultRuncDir (emptyDir shared with worker)
	RuncSource string // default DefaultRuncSource
	// WrapperSource is the binary installed at <RuncDir>/runc — the
	// script wrote a shell wrapper here; the port self-copies the
	// agent binary (multi-call dispatch to RunRuncWrapper). Empty →
	// os.Executable().
	WrapperSource string
	OwnerUID      int         // default 4294967294; -1 skips chown
	OwnerGID      int         // default 4294967294; -1 skips chown
	Mode          os.FileMode // default 0o777

	// Test seams — nil selects the production implementation.
	listSubvols  func(ctx context.Context, dir string) ([]string, error)
	deleteSubvol func(ctx context.Context, path string) error
	chown        func(name string, uid, gid int) error
}

func (c *Config) applyDefaults() {
	if c.WorkDir == "" {
		c.WorkDir = DefaultWorkDir
	}
	if c.RuncDir == "" {
		c.RuncDir = DefaultRuncDir
	}
	if c.RuncSource == "" {
		c.RuncSource = DefaultRuncSource
	}
	// OwnerUID/OwnerGID default INDEPENDENTLY — a partial config
	// (OwnerUID=-1 alone, "skip the uid half") must not leave GID 0:
	// uid/gid 0 is root, and chown-to-root was never a supported
	// mode of the script.
	if c.OwnerUID == 0 {
		c.OwnerUID = cacheOwner
	}
	if c.OwnerGID == 0 {
		c.OwnerGID = cacheOwner
	}
	if c.Mode == 0 {
		c.Mode = cachePerm
	}
	if c.listSubvols == nil {
		c.listSubvols = btrfsListSubvols
	}
	if c.deleteSubvol == nil {
		c.deleteSubvol = btrfsDeleteSubvol
	}
	if c.chown == nil {
		c.chown = os.Chown
	}
}

// WorkerInit runs the concourse-worker-init-rm sequence. It returns
// the first fail-closed error; the btrfs phase can never produce one.
func WorkerInit(ctx context.Context, cfg Config) error {
	cfg.applyDefaults()
	// wipeExcept rm -rf's every non-dot top-level entry under
	// WorkDir — refuse to run that against the filesystem root or a
	// relative path resolved at the wrong cwd: a misconfigured
	// WorkDir is catastrophic, not a no-op.
	if !filepath.IsAbs(cfg.WorkDir) ||
		filepath.Clean(cfg.WorkDir) == "/" {
		return fmt.Errorf("unsafe work dir %q", cfg.WorkDir)
	}
	sc := filepath.Join(cfg.WorkDir, sharedCacheName)

	// shared-cache itself needs the same scrutiny the per-entry
	// Lstat below gives its CHILDREN: a symlink planted AT
	// <WorkDir>/shared-cache sails past the top-level wipe (it is
	// the keep-list entry), then wipeExcept(sc, ...) rm -rf's the
	// LINK TARGET's contents and the chmod 0777/chown pass lands on
	// the target — the same privilege gadget, one level up. A real
	// shared-cache is only ever a plain dir the scaffold mkdir'd, so
	// any symlink here is hostile and fails the init.
	if fi, err := os.Lstat(sc); err == nil {
		if fi.Mode()&os.ModeSymlink != 0 {
			return fmt.Errorf("shared-cache %s is a symlink", sc)
		}
	} else if !os.IsNotExist(err) {
		return fmt.Errorf("lstat %s: %w", sc, err)
	}
	// Depth check behind the Lstat: WorkDir may itself ride on a
	// symlink (whatever the chart mounted), so compare RESOLVED
	// paths — a shared-cache whose real path does not sit strictly
	// inside the resolved work dir is refused (this also rejects a
	// WorkDir symlinked at the filesystem root, which would be the
	// same catastrophic wipe the IsAbs check guards).
	if wdReal, err := filepath.EvalSymlinks(cfg.WorkDir); err == nil {
		if scReal, err := filepath.EvalSymlinks(sc); err == nil &&
			!strings.HasPrefix(scReal,
				wdReal+string(os.PathSeparator)) {
			return fmt.Errorf("shared-cache %s resolves outside "+
				"work dir: %s", sc, scReal)
		}
	}
	// Missing work dir / missing shared-cache is fine — EvalSymlinks
	// errors on nonexistent paths and the scaffold mkdir's the whole
	// tree below.

	// btrfs subvolume cleanup — inherited from the chart's built-in
	// init-rm. Fail-open: `btrfs subvolume list || true` yields an
	// empty list on non-btrfs filesystems, and each delete is best-
	// effort (`show && delete --recursive || true`).
	vols, _ := cfg.listSubvols(ctx, cfg.WorkDir)
	for _, v := range vols {
		if err := ctx.Err(); err != nil {
			return err
		}
		_ = cfg.deleteSubvol(ctx, filepath.Join(cfg.WorkDir, v))
	}

	// Soft-reset: rm -rf every top-level entry EXCEPT shared-cache
	// (volumes/, overlays/, ... — all baggageclaim/containerd state),
	// then inside shared-cache everything not on the keep-list. The
	// bash `*` glob never matches dotfiles, so `.foo` entries survive
	// both wipes — keep that (also protects .snapshot-style dirs).
	if err := wipeExcept(ctx, cfg.WorkDir,
		map[string]bool{sharedCacheName: true}); err != nil {
		return err
	}
	if err := wipeExcept(ctx, sc, persistentSet); err != nil {
		return err
	}

	// Scaffold: mkdir -p the 20 shared-cache subdirs. mkdir mode is
	// irrelevant — the chmod below forces it — but pass the final
	// mode anyway for the dirs mkdir itself creates.
	for _, d := range ScaffoldCacheDirs {
		if err := os.MkdirAll(filepath.Join(sc, d), cfg.Mode); err != nil {
			return fmt.Errorf("mkdir %s: %w", d, err)
		}
	}

	// `chown 4294967294:4294967294 $SC $SC/* && chmod 0777 $SC $SC/*`
	// — TOP LEVEL ONLY, never -R: a recursive walk over 500k+ cache
	// files is slow at every worker restart and would flatten real
	// modes (binary 0755 → 0777 breaks exec semantics the other way).
	// Symlinks are skipped — os.Chown/os.Chmod dereference them, and
	// the sweeper port already established that a CI-planted
	// `<entry> -> /etc/...` must not become a privilege gadget.
	targets := []string{sc}
	entries, err := os.ReadDir(sc)
	if err != nil {
		return fmt.Errorf("read shared-cache: %w", err)
	}
	for _, e := range entries {
		if strings.HasPrefix(e.Name(), ".") {
			continue
		}
		p := filepath.Join(sc, e.Name())
		// Lstat each candidate — DirEntry.Type() is zero on
		// filesystems reporting DT_UNKNOWN, so a planted symlink
		// could slip a Type()-based guard and the chown/chmod below
		// would dereference it (a CI-planted `<entry> -> /etc/...`
		// privilege gadget).
		fi, err := os.Lstat(p)
		if err != nil {
			if os.IsNotExist(err) {
				continue // raced away between ReadDir and Lstat
			}
			return fmt.Errorf("lstat %s: %w", p, err)
		}
		if fi.Mode()&os.ModeSymlink != 0 {
			continue
		}
		targets = append(targets, p)
	}
	// Residual TOCTOU window, documented not closed: the Lstat above
	// proved the entry was not a symlink AT CHECK TIME, but
	// chown/chmod re-resolve the path — an actor able to swap a
	// verified entry for a symlink in between could still redirect
	// the dereference. Closing it for real needs openat2/…AT_SYMLINK_
	// NOFOLLOW + fchown/fchmod on the held fd; the init runs as root
	// before task containers start, so the window is accepted (same
	// residual the script's chown/chmod carried).
	for _, t := range targets {
		if cfg.OwnerUID >= 0 || cfg.OwnerGID >= 0 {
			if err := cfg.chown(t, cfg.OwnerUID, cfg.OwnerGID); err != nil {
				return fmt.Errorf("chown %s: %w", t, err)
			}
		}
		if err := os.Chmod(t, cfg.Mode); err != nil {
			return fmt.Errorf("chmod %s: %w", t, err)
		}
	}

	// runc wrapper: the script `cp`ed the image's runc to runc.real
	// and heredoc'd a shell wrapper to runc; the port copies the
	// image's runc identically but installs THIS binary as the
	// wrapper — the worker's subPath mount puts it at RuncSource, and
	// the shim's `runc ...` exec dispatches to RunRuncWrapper. Both
	// writes are tmp+rename so a killed init never leaves a half
	// binary for the worker to exec.
	if err := copyFileAtomic(cfg.RuncSource,
		filepath.Join(cfg.RuncDir, "runc.real"), 0o755); err != nil {
		return fmt.Errorf("install runc.real: %w", err)
	}
	src := cfg.WrapperSource
	if src == "" {
		if src, err = os.Executable(); err != nil {
			return fmt.Errorf("resolve wrapper source: %w", err)
		}
	}
	if err := copyFileAtomic(src,
		filepath.Join(cfg.RuncDir, "runc"), 0o755); err != nil {
		return fmt.Errorf("install runc wrapper: %w", err)
	}
	return nil
}

// wipeExcept is `for d in <dir>/*; keep || rm -rf "$d"`: removes every
// non-dot first-level entry not on the keep set (files AND dirs — the
// script's glob didn't filter on type). A missing dir is the bash
// no-match glob — a no-op, not an error.
func wipeExcept(ctx context.Context, dir string, keep map[string]bool) error {
	entries, err := os.ReadDir(dir)
	if err != nil {
		if os.IsNotExist(err) {
			return nil
		}
		return err
	}
	for _, e := range entries {
		if err := ctx.Err(); err != nil {
			return err
		}
		name := e.Name()
		if strings.HasPrefix(name, ".") || keep[name] {
			continue
		}
		if err := os.RemoveAll(filepath.Join(dir, name)); err != nil {
			return err
		}
	}
	return nil
}

// btrfsListSubvols is `btrfs subvolume list --sort=-ogen <dir> |
// awk '{print $9}'` — subvolume paths relative to dir, newest oGen
// first so nested/younger subvolumes delete before their parents the
// same way the shell got them. ALWAYS fail-open (`|| true`): missing
// binary or a non-btrfs fs returns an empty list, matching the
// script's no-op on ext4.
func btrfsListSubvols(ctx context.Context, dir string) ([]string, error) {
	cctx, cancel := context.WithTimeout(ctx, btrfsCmdTimeout)
	defer cancel()
	cmd := exec.CommandContext(cctx, "btrfs", "subvolume", "list",
		"--sort=-ogen", dir)
	cmd.Stderr = os.Stderr
	out, err := cmd.Output()
	if err != nil {
		return nil, nil
	}
	var vols []string
	for _, line := range strings.Split(string(out), "\n") {
		if f := strings.Fields(line); len(f) >= 9 {
			vols = append(vols, f[8]) // awk $9
		}
	}
	return vols, nil
}

// btrfsDeleteSubvol is `btrfs subvolume show <path> && btrfs
// subvolume delete --recursive <path>` — the show guard keeps the
// delete from running on stale list output (the entry may already be
// gone by the time the loop reaches it). The caller discards the
// error — the script's `|| true`.
func btrfsDeleteSubvol(ctx context.Context, path string) error {
	sctx, cancel := context.WithTimeout(ctx, btrfsCmdTimeout)
	show := exec.CommandContext(sctx, "btrfs", "subvolume", "show", path)
	show.Stdout, show.Stderr = os.Stdout, os.Stderr
	err := show.Run()
	cancel()
	if err != nil {
		return err
	}
	dctx, cancel := context.WithTimeout(ctx, btrfsCmdTimeout)
	defer cancel()
	del := exec.CommandContext(dctx, "btrfs", "subvolume", "delete",
		"--recursive", path)
	del.Stdout, del.Stderr = os.Stdout, os.Stderr
	return del.Run()
}

// copyFileAtomic copies src to dst via a same-dir tmp + rename and
// forces dst to perm — a half-written runc binary must never be what
// the worker's shim execs.
func copyFileAtomic(src, dst string, perm os.FileMode) error {
	in, err := os.Open(src)
	if err != nil {
		return err
	}
	defer in.Close()

	tmp := dst + ".tmp"
	out, err := os.OpenFile(tmp, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, perm)
	if err != nil {
		return err
	}
	_, copyErr := io.Copy(out, in)
	closeErr := out.Close()
	if copyErr != nil {
		_ = os.Remove(tmp)
		return copyErr
	}
	if closeErr != nil {
		_ = os.Remove(tmp)
		return closeErr
	}
	if err := os.Chmod(tmp, perm); err != nil {
		_ = os.Remove(tmp)
		return err
	}
	if err := os.Rename(tmp, dst); err != nil {
		_ = os.Remove(tmp)
		return err
	}
	return nil
}
