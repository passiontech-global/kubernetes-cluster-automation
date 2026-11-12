// sysinfo.go — the host-level /proc + sysfs readers ported verbatim
// from platform/hostutil when that package was retired onto
// libs/hostkit/fsx: uptime parsing, per-interface sysfs MTU, the
// cilium agent-runtime-config MTU fallback, the recursive JSON key
// scan, the pod lxc* MTU census and the all-digits predicate.
// Package-level (path-argument) forms live here; the FS-rooted
// /proc view keeps its own methods in procfs.go.
package procfs

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strconv"
	"strings"
)

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

// lxcIfaceRe matches the Cilium host-side pod veth names —
// "lxc" + hex. lxc_health (the health-probe endpoint) is not a pod
// veth and must not vote on pod MTU drift; it is excluded by the
// explicit name check below.
var lxcIfaceRe = regexp.MustCompile(`^lxc[0-9a-f]+$`)

// MaxPodLxcMTU scans <sysClassNet> for pod lxc* interfaces and
// returns the MAX MTU among them — worst-case pod MTU, the same
// MAX-wins convention as RuntimeConfigMTU. ok=false when no lxc*
// interface (or none with a readable mtu file) exists: absent pods
// must not vote. lxc_health is skipped.
func MaxPodLxcMTU(sysClassNet string) (max int64, ok bool) {
	entries, err := os.ReadDir(sysClassNet)
	if err != nil {
		return 0, false
	}
	for _, e := range entries {
		name := e.Name()
		if name == "lxc_health" || !lxcIfaceRe.MatchString(name) {
			continue
		}
		v, read := MTUOfIface(sysClassNet, name)
		if !read {
			continue
		}
		if !ok || v > max {
			max, ok = v, true
		}
	}
	return max, ok
}

// IsDigits reports whether s is non-empty and all ASCII digits —
// the cheap scan replacing a ^[0-9]+$ regex on hot paths.
func IsDigits(s string) bool {
	if s == "" {
		return false
	}
	for i := range len(s) {
		if s[i] < '0' || s[i] > '9' {
			return false
		}
	}
	return true
}
