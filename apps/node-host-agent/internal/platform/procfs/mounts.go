// mounts.go — the /proc/*/mounts table parser shared by the two
// mount-table consumers: hostmetrics' fs-readonly evidence scan
// (ro ext4/xfs/btrfs mounts under the PVC provisioner roots) and
// nodereporter's NPD readonly monitor (watched mountpoints mounted
// ro). Mount + ParseMounts stay deliberately generic — the
// ro/fstype/root filters are call-site policy; LastByMountPoint
// captures the "topmost mount wins" reduction the readonly monitor
// needs.
package procfs

import "strings"

// Mount is one parsed mount-table row — "src mp fstype opts dump
// pass". Opts is the raw comma-separated option list; token lookup
// goes through HasOpt (e.g. HasOpt("ro")). Octal escapes in the
// path fields (\040 for space) are left verbatim: mountpoints with
// spaces are rare under the consumers' roots and a missed unescape
// only narrows matching, never widens it.
type Mount struct {
	Source     string
	MountPoint string
	FSType     string
	Opts       string
}

// HasOpt reports whether the mount's comma-separated option list
// contains exactly the token name (e.g. "ro") — whole-token match
// only, never a prefix/suffix hit on a longer name. Zero-alloc:
// scans the raw string without splitting.
func (m Mount) HasOpt(name string) bool {
	for opts := m.Opts; opts != ""; {
		var tok string
		if i := strings.IndexByte(opts, ','); i >= 0 {
			tok, opts = opts[:i], opts[i+1:]
		} else {
			tok, opts = opts, ""
		}
		if tok == name {
			return true
		}
	}
	return false
}

// ParseMounts parses mount-table content into one Mount per row in
// file order — the "unparseable line ignored" verdict both private
// copies used (<4 fields → skip). Stacked binds for the same
// mountpoint all parse; callers wanting the kernel's lookup view
// reduce with LastByMountPoint.
func ParseMounts(data []byte) []Mount {
	var out []Mount
	for _, ln := range strings.Split(string(data), "\n") {
		f := strings.Fields(ln)
		if len(f) < 4 {
			continue
		}
		out = append(out, Mount{
			Source:     f[0],
			MountPoint: f[1],
			FSType:     f[2],
			Opts:       f[3],
		})
	}
	return out
}

// LastByMountPoint indexes mounts by mountpoint — rows sharing one
// (stacked binds) keep the LAST entry, matching the kernel's
// topmost-mount lookup.
func LastByMountPoint(mounts []Mount) map[string]Mount {
	out := make(map[string]Mount, len(mounts))
	for _, m := range mounts {
		out[m.MountPoint] = m
	}
	return out
}
