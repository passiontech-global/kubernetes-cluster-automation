// Package hostutil holds small host-level helpers shared by the
// subsystems: atomic file writes (the .tmp-<name> + rename contract
// every watchdog state file relies on), /proc uptime parsing, JSON
// key scans and interface MTU reads. Anything here must stay
// dependency-free and safe to call from scrape-time collectors.
package hostutil

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"sync"

	"golang.org/x/sys/unix"
)

// RenameFile is the rename(2) seam — tests stub it to force the
// EBUSY/EXDEV bind-mount fallback without a real mount.
var RenameFile = os.Rename

// renameFallbackLogged remembers which paths already warned about the
// direct-write fallback — one line per path per process (a
// bind-mounted hosts file takes the fallback on every render and
// would spam the log).
var renameFallbackLogged sync.Map

// WriteFileAtomic writes content via a tmp file in the same dir +
// rename — the atomic-copy contract the watchdog state/prom files
// rely on (no torn reads mid-write). The tmp name deliberately uses
// the ".tmp-<base>" convention: a leading dot keeps it out of
// hostmetrics' state-* scan — a "state-foo.tmp" file would surface as
// a phantom watchdog_state series that then sits at 0 forever.
//
// rename(2) has one blind spot that matters here: the TARGET of a
// file-level bind mount cannot be renamed over — the kernel returns
// EBUSY — and that is exactly how the DaemonSet mounts
// /host/etc/hosts. EXDEV (tmp and target ever landing on different
// filesystems) shares the fallback. Both degrade to a direct
// write+fsync on the target: the crash-atomicity is lost but the
// write actually lands — strictly better than never writing at all.
func WriteFileAtomic(path, content string) error {
	tmp := filepath.Join(filepath.Dir(path), ".tmp-"+filepath.Base(path))
	if err := os.WriteFile(tmp, []byte(content), 0o644); err != nil {
		return err
	}
	err := RenameFile(tmp, path)
	if err == nil {
		return nil
	}
	defer func() { _ = os.Remove(tmp) }()
	if !errors.Is(err, unix.EBUSY) && !errors.Is(err, unix.EXDEV) {
		return err
	}
	if _, logged := renameFallbackLogged.LoadOrStore(path, true); !logged {
		logger().Warn("atomic rename refused (bind-mounted "+
			"target?) — falling back to direct fsync'd write",
			"path", path, "error", err)
	}
	return WriteFileDirect(path, content)
}

// WriteFileDirect writes content straight onto path with an fsync —
// the WriteFileAtomic fallback when rename(2) is refused. Truncates
// in place, so a crash can leave a partial file; only used where
// rename is provably impossible.
func WriteFileDirect(path, content string) error {
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0o644)
	if err != nil {
		return err
	}
	var werr error
	if _, err := f.WriteString(content); err != nil {
		werr = err
	} else if err := f.Sync(); err != nil {
		werr = err
	}
	if cerr := f.Close(); werr == nil {
		werr = cerr
	}
	return werr
}

// WriteFileAtomicBytes is WriteFileAtomic for callers holding []byte.
func WriteFileAtomicBytes(path string, data []byte) error {
	return WriteFileAtomic(path, string(data))
}

// UptimeSeconds parses the first field of a /proc/uptime-format file
// (seconds since boot, fractional part ignored by callers that cast).
func UptimeSeconds(path string) (float64, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return 0, err
	}
	fields := strings.Fields(string(data))
	if len(fields) == 0 {
		return 0, fmt.Errorf("empty uptime file %s", path)
	}
	return strconv.ParseFloat(fields[0], 64)
}

// ReadTrimmed returns the file's trimmed content, "" on any error.
func ReadTrimmed(path string) string {
	data, err := os.ReadFile(path)
	if err != nil {
		return ""
	}
	return strings.TrimSpace(string(data))
}

// ReadUintFile parses a file holding a single unsigned integer —
// "" ok=false on absent/unparseable content.
func ReadUintFile(path string) (uint64, bool) {
	v, err := strconv.ParseUint(strings.TrimSpace(
		ReadTrimmed(path)), 10, 64)
	if err != nil {
		return 0, false
	}
	return v, true
}

// JSONFindInts collects EVERY numeric value of a key named in keys
// (case-insensitive) under decoded JSON — maps AND arrays are
// descended. The cilium runtime config nests its MTU differently
// across agent versions and may carry several `mtu` keys; a
// "first match" walk is nondeterministic because Go map iteration
// order is random.
func JSONFindInts(v any, out *[]int64, keys ...string) {
	want := make(map[string]bool, len(keys))
	for _, k := range keys {
		want[strings.ToLower(k)] = true
	}
	var walk func(n any)
	walk = func(n any) {
		switch t := n.(type) {
		case map[string]any:
			for k, val := range t {
				if want[strings.ToLower(k)] {
					if f, ok := val.(float64); ok {
						*out = append(*out, int64(f))
					}
				}
				walk(val)
			}
		case []any:
			for _, val := range t {
				walk(val)
			}
		}
	}
	walk(v)
}

// MTUOfIface reads <sysnet>/<iface>/mtu — the sysfs MTU of one
// interface.
func MTUOfIface(sysnet, iface string) (int64, bool) {
	data, err := os.ReadFile(filepath.Join(sysnet, iface, "mtu"))
	if err != nil {
		return 0, false
	}
	v, err := strconv.ParseInt(strings.TrimSpace(string(data)), 10, 64)
	if err != nil {
		return 0, false
	}
	return v, true
}

// RuntimeConfigMTU reads the cilium MTU out of
// agent-runtime-config.json — the fallback when the datapath iface
// has no sysfs entry. With several `mtu` keys the MAX wins —
// deterministic (Go map order makes a "first match" walk unstable),
// and the drift checks want the worst-case datapath MTU anyway.
func RuntimeConfigMTU(path string) (int64, bool) {
	data, err := os.ReadFile(path)
	if err != nil {
		return 0, false
	}
	var v any
	if json.Unmarshal(data, &v) != nil {
		return 0, false
	}
	var vals []int64
	JSONFindInts(v, &vals, "mtu")
	if len(vals) == 0 {
		return 0, false
	}
	return slices.Max(vals), true
}
