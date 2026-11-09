// lxc_mtu.go — lxc-mtu-drift: pod lxc* interface MTU scan. A pod created
// before the overlay MTU change keeps its old MTU on its host-side
// veth (named lxc<hex> by Cilium) and dies silently on FRAG_NEEDED
// even when every cilium_* datapath interface is aligned. The drift
// checks (workerhygiene CiliumMTUCheck + hostmetrics collectMTUDrift)
// fold this MAX into the same verdict as the datapath MTUs.
package hostutil

import (
	"os"
	"regexp"
)

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
