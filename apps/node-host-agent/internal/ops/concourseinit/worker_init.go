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
)

// Config carries the init knobs — the zero value IS the production
// config (same convention as sweeper.ConcourseCacheConfig).
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
	if c.OwnerUID == 0 && c.OwnerGID == 0 {
		c.OwnerUID, c.OwnerGID = cacheOwner, cacheOwner
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
	sc := filepath.Join(cfg.WorkDir, sharedCacheName)

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
		if e.Type()&os.ModeSymlink != 0 || strings.HasPrefix(e.Name(), ".") {
			continue
		}
		targets = append(targets, filepath.Join(sc, e.Name()))
	}
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
	cmd := exec.CommandContext(ctx, "btrfs", "subvolume", "list",
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
	show := exec.CommandContext(ctx, "btrfs", "subvolume", "show", path)
	show.Stdout, show.Stderr = os.Stdout, os.Stderr
	if err := show.Run(); err != nil {
		return err
	}
	del := exec.CommandContext(ctx, "btrfs", "subvolume", "delete",
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
