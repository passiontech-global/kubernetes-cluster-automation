// nld_notrack.go — #12A NodeLocalDNS raw NOTRACK iptables/nft drift guard.
//
// On clusters running NodeLocalDNS in legacy hostNetwork/iptables mode
// (interface `nodelocaldns` carrying 169.254.20.10, without Cilium LRP
// bypass), node-local-dns installs `raw` table PREROUTING + OUTPUT
// NOTRACK rules for 169.254.20.10:53 so link-local DNS packets bypass
// nf_conntrack. Firewall reloads or `iptables -F -t raw` silently drop
// those rules and flood nf_conntrack with DNS entries.
//
// Detect-only: two consecutive missing cycles raise
// latchdefs.LatchNodeLocalDNSNoTrackDrift (surfaced as NodeCondition
// NodeLocalDNSNoTrackDrift + Warning Event via nodereporter). Never
// mutates iptables/nft or restarts node-local-dns.
package nethealth

import (
	"context"
	json "encoding/json/v2"
	"errors"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strings"

	"github.com/vishvananda/netlink"
	"golang.org/x/sys/unix"

	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-host-agent/internal/latchdefs"
	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-host-agent/internal/platform/checkkit"
	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-host-agent/internal/platform/netlinkx"
	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-host-agent/internal/platform/probee"
)

const (
	nldIface = "nodelocaldns"
	nldPort  = "53"
)

func (n *NetHealth) checkNodeLocalDNSNoTrack(ctx context.Context) {
	targetIP := n.cfg.nodeLocalDNSIP
	if targetIP == "" {
		targetIP = defaultNodeLocalDNSIP
	}

	// Step 1: Gate on NodeLocalDNS iptables mode (`nodelocaldns` link
	// carrying targetIP in host netns).
	linkAddrsFn := n.cfg.linkAddrsFn
	if linkAddrsFn == nil {
		linkAddrsFn = netlinkx.LinkAddrs
	}
	addrs, err := linkAddrsFn(1, nldIface)
	if err != nil {
		if isMissingLinkErr(err) {
			n.nldNoTrackFails = 0
			n.stateExit(latchdefs.LatchNodeLocalDNSNoTrackDrift)
			n.cycles.WithLabelValues(checkNLDNoTrack, "gated").Inc()
			return
		}
		n.state.SuspectLog("nld-notrack-netlink",
			fmt.Sprintf("nodelocaldns-notrack: linkAddrs(%s) failed: %v", nldIface, err),
			suspectLogCadence)
		n.cycles.WithLabelValues(checkNLDNoTrack, "abort").Inc()
		return
	}
	if !hasIPv4(addrs, targetIP) {
		n.nldNoTrackFails = 0
		n.stateExit(latchdefs.LatchNodeLocalDNSNoTrackDrift)
		n.cycles.WithLabelValues(checkNLDNoTrack, "gated").Inc()
		return
	}

	// Step 2: Gate out nodes where Cilium LocalRedirectPolicy handles
	// DNS locally (cilium_host present AND /v1/service reports an active
	// LocalRedirect DNS service). A Cilium node without DNS LRP still
	// proceeds to inspect the raw table.
	sysClassNet := n.cfg.sysClassNet
	if sysClassNet == "" {
		sysClassNet = defaultSysClassNet
	}
	if _, err := os.Stat(filepath.Join(sysClassNet, "cilium_host")); err != nil {
		if !os.IsNotExist(err) {
			n.state.SuspectLog("nld-notrack-sysfs",
				fmt.Sprintf("nodelocaldns-notrack: stat %s/cilium_host failed: %v", sysClassNet, err),
				suspectLogCadence)
			n.cycles.WithLabelValues(checkNLDNoTrack, "abort").Inc()
			return
		}
	} else {
		ciliumSocket := n.cfg.ciliumSocket
		if ciliumSocket == "" {
			ciliumSocket = defaultCiliumSocket
		}
		if _, sockErr := os.Stat(ciliumSocket); sockErr != nil {
			if !os.IsNotExist(sockErr) {
				n.state.SuspectLog("nld-notrack-cilium-stat",
					fmt.Sprintf("nodelocaldns-notrack: stat %s failed: %v", ciliumSocket, sockErr),
					suspectLogCadence)
				n.cycles.WithLabelValues(checkNLDNoTrack, "abort").Inc()
				return
			}
		} else {
			unixGet := n.cfg.unixGet
			if unixGet == nil {
				unixGet = probee.UnixGet
			}
			body, apiErr := unixGet(ctx, ciliumSocket, "/v1/service")
			if apiErr != nil {
				n.state.SuspectLog("nld-notrack-cilium-api",
					fmt.Sprintf("nodelocaldns-notrack: cilium /v1/service failed: %v", apiErr),
					suspectLogCadence)
				n.cycles.WithLabelValues(checkNLDNoTrack, "abort").Inc()
				return
			}
			lrpActive, parseErr := hasCiliumDNSLRPService(body, targetIP)
			if parseErr != nil {
				n.state.SuspectLog("nld-notrack-cilium-parse",
					fmt.Sprintf("nodelocaldns-notrack: parse cilium /v1/service failed: %v", parseErr),
					suspectLogCadence)
				n.cycles.WithLabelValues(checkNLDNoTrack, "abort").Inc()
				return
			}
			if lrpActive {
				n.nldNoTrackFails = 0
				n.stateExit(latchdefs.LatchNodeLocalDNSNoTrackDrift)
				n.cycles.WithLabelValues(checkNLDNoTrack, "gated").Inc()
				return
			}
		}
	}

	// Step 3: Probe host raw table via runMountCmd (host mount + net ns,
	// because iptables-save/nft are host binaries absent from the container).
	if n.cfg.runMountCmd == nil {
		n.state.SuspectLog("nld-notrack-probe",
			"nodelocaldns-notrack: runMountCmd seam is nil",
			suspectLogCadence)
		n.cycles.WithLabelValues(checkNLDNoTrack, "abort").Inc()
		return
	}
	preOK, outOK, ok := n.probeRawNoTrack(ctx, targetIP)
	if !ok {
		n.cycles.WithLabelValues(checkNLDNoTrack, "abort").Inc()
		return
	}

	// Step 4: Evaluate health, hysteresis, and detect-only latch.
	if preOK && outOK {
		n.nldNoTrackFails = 0
		n.stateExit(latchdefs.LatchNodeLocalDNSNoTrackDrift)
		n.cycles.WithLabelValues(checkNLDNoTrack, "ok").Inc()
		return
	}

	var missing []string
	if !preOK {
		missing = append(missing, "PREROUTING")
	}
	if !outOK {
		missing = append(missing, "OUTPUT")
	}
	detail := "missing=" + strings.Join(missing, ",")

	if checkkit.Pending(n.cfg.ConsecNeeded, &n.nldNoTrackFails,
		"suspect: nodelocaldns-notrack "+detail, n.state.AppendLog) {
		n.cycles.WithLabelValues(checkNLDNoTrack, "ok").Inc()
		return
	}
	n.state.SuspectLog(latchdefs.LatchNodeLocalDNSNoTrackDrift,
		"suspect: nodelocaldns-notrack "+detail, suspectLogCadence)
	n.state.Enter(latchdefs.LatchNodeLocalDNSNoTrackDrift, detail)
	n.cycles.WithLabelValues(checkNLDNoTrack, "ok").Inc()
}

func (n *NetHealth) probeRawNoTrack(ctx context.Context, targetIP string) (preOK, outOK, probeOK bool) {
	iptOut, iptErr := n.cfg.runMountCmd(ctx, []string{"iptables-save", "-t", "raw"})
	if iptErr == nil {
		preOK, outOK = parseIPTablesRawNoTrack(iptOut, targetIP)
		if preOK && outOK {
			return true, true, true
		}
		if strings.Contains(iptOut, "*raw") {
			return preOK, outOK, true
		}
	}

	nftOut, nftErr := n.cfg.runMountCmd(ctx, []string{"nft", "list", "table", "ip", "raw"})
	if nftErr == nil {
		preOK, outOK = parseNFTRawNoTrack(nftOut, targetIP)
		return preOK, outOK, true
	}
	if isMissingNFTTable(nftOut, nftErr) {
		return false, false, true
	}
	if iptErr == nil && strings.TrimSpace(iptOut) == "" {
		return false, false, true
	}

	n.state.SuspectLog("nld-notrack-probe",
		fmt.Sprintf("nodelocaldns-notrack: raw table probe failed: iptables-save=%v (%s); nft=%v (%s)",
			iptErr, trimRunErr(iptOut), nftErr, trimRunErr(nftOut)),
		suspectLogCadence)
	return false, false, false
}

func isMissingLinkErr(err error) bool {
	if err == nil {
		return false
	}
	var lnf netlink.LinkNotFoundError
	var lnfPtr *netlink.LinkNotFoundError
	return errors.As(err, &lnf) || errors.As(err, &lnfPtr) ||
		os.IsNotExist(err) || errors.Is(err, unix.ENODEV)
}

func hasIPv4(addrs []netlink.Addr, want string) bool {
	wantIP := net.ParseIP(want)
	if wantIP == nil {
		return false
	}
	want4 := wantIP.To4()
	if want4 == nil {
		return false
	}
	for _, a := range addrs {
		if a.IPNet == nil {
			continue
		}
		if ip4 := a.IPNet.IP.To4(); ip4 != nil && ip4.Equal(want4) {
			return true
		}
	}
	return false
}

func isMissingNFTTable(out string, err error) bool {
	hasMsg := func(s string) bool {
		lower := strings.ToLower(s)
		return strings.Contains(lower, "no such file or directory") ||
			strings.Contains(lower, "does not exist")
	}
	return hasMsg(out) || (err != nil && hasMsg(err.Error()))
}

func hasCiliumDNSLRPService(body []byte, targetIP string) (bool, error) {
	var list []struct {
		Spec struct {
			Name  string `json:"name"`
			Type  string `json:"type"`
			Flags struct {
				Name string `json:"name"`
				Type string `json:"type"`
			} `json:"flags"`
			FrontendAddress struct {
				IP   string `json:"ip"`
				Port uint16 `json:"port"`
			} `json:"frontend-address"`
		} `json:"spec"`
	}
	if err := json.Unmarshal(body, &list); err != nil {
		return false, err
	}
	for _, svc := range list {
		svcType := svc.Spec.Flags.Type
		if svcType == "" {
			svcType = svc.Spec.Type
		}
		if !strings.EqualFold(svcType, "LocalRedirect") &&
			!strings.EqualFold(svcType, "local-redirect") {
			continue
		}
		name := svc.Spec.Name
		if name == "" {
			name = svc.Spec.Flags.Name
		}
		if svc.Spec.FrontendAddress.IP == targetIP {
			return true, nil
		}
		if (svc.Spec.FrontendAddress.Port == 53 || svc.Spec.FrontendAddress.Port == 0) &&
			isDNSLRPName(name) {
			return true, nil
		}
	}
	return false, nil
}

func isDNSLRPName(name string) bool {
	lower := strings.ToLower(name)
	return strings.Contains(lower, "kube-dns") ||
		strings.Contains(lower, "nodelocaldns") ||
		strings.Contains(lower, "node-local-dns")
}
