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

type ruleToken struct {
	val    string
	quoted bool
}

// parseIPTablesRawNoTrack checks `iptables-save -t raw` output for matching
// NOTRACK / CT --notrack rules covering targetIP port 53 in both PREROUTING
// and OUTPUT chains.
func parseIPTablesRawNoTrack(out, targetIP string) (preOK, outOK bool) {
	inRaw := false
	for line := range strings.SplitSeq(out, "\n") {
		tokens := tokenizeIPTablesLine(line)
		if len(tokens) == 0 {
			continue
		}
		first := tokens[0]
		if !first.quoted && strings.HasPrefix(first.val, "*") {
			inRaw = first.val == "*raw"
			continue
		}
		if !first.quoted && first.val == "COMMIT" {
			inRaw = false
			continue
		}
		if !inRaw {
			continue
		}
		if first.quoted || (first.val != "-A" && first.val != "-I") || len(tokens) < 3 {
			continue
		}
		chain := tokens[1].val
		if chain != "PREROUTING" && chain != "OUTPUT" {
			continue
		}
		if iptablesRuleMatches(tokens[2:], targetIP) {
			if chain == "PREROUTING" {
				preOK = true
			} else {
				outOK = true
			}
		}
	}
	return preOK, outOK
}

func tokenizeIPTablesLine(line string) []ruleToken {
	var tokens []ruleToken
	var cur strings.Builder
	inToken := false
	quoted := false
	var quoteChar byte

	flush := func() {
		if inToken || quoted {
			tokens = append(tokens, ruleToken{val: cur.String(), quoted: quoted})
			cur.Reset()
			inToken = false
			quoted = false
		}
	}

	for i := 0; i < len(line); i++ {
		c := line[i]
		if quoteChar != 0 {
			if c == '\\' && quoteChar == '"' && i+1 < len(line) {
				i++
				cur.WriteByte(line[i])
				continue
			}
			if c == quoteChar {
				quoteChar = 0
				continue
			}
			cur.WriteByte(c)
			continue
		}
		if c == '#' {
			break
		}
		if c == ' ' || c == '\t' || c == '\r' {
			flush()
			continue
		}
		if c == '"' || c == '\'' {
			quoteChar = c
			quoted = true
			inToken = true
			continue
		}
		inToken = true
		cur.WriteByte(c)
	}
	flush()
	return tokens
}

func iptablesRuleMatches(tokens []ruleToken, targetIP string) bool {
	var (
		hasDstIP, hasSrcIP     bool
		hasDPort, hasSPort     bool
		hasNoTrack, hasCT      bool
		hasCTNoTrack           bool
		protoBad, protoNegated bool
	)
	negated := false
	for i := 0; i < len(tokens); i++ {
		tok := tokens[i]
		if tok.quoted {
			negated = false
			continue
		}
		if tok.val == "!" {
			negated = true
			continue
		}
		switch tok.val {
		case "--comment":
			// Skip the comment text argument completely so words inside
			// `--comment "..."` never satisfy IP, port, or target checks.
			if i+1 < len(tokens) {
				i++
			}
			negated = false
		case "-d", "--dst", "--destination":
			val, neg, next := consumeFlagValue(tokens, i, negated)
			i = next
			if !neg && matchTargetIP(val, targetIP) {
				hasDstIP = true
			}
			negated = false
		case "-s", "--src", "--source":
			val, neg, next := consumeFlagValue(tokens, i, negated)
			i = next
			if !neg && matchTargetIP(val, targetIP) {
				hasSrcIP = true
			}
			negated = false
		case "--dport", "--destination-port":
			val, neg, next := consumeFlagValue(tokens, i, negated)
			i = next
			if !neg && val == nldPort {
				hasDPort = true
			}
			negated = false
		case "--dports":
			val, neg, next := consumeFlagValue(tokens, i, negated)
			i = next
			if !neg && portListContains(val, nldPort) {
				hasDPort = true
			}
			negated = false
		case "--sport", "--source-port":
			val, neg, next := consumeFlagValue(tokens, i, negated)
			i = next
			if !neg && val == nldPort {
				hasSPort = true
			}
			negated = false
		case "--sports":
			val, neg, next := consumeFlagValue(tokens, i, negated)
			i = next
			if !neg && portListContains(val, nldPort) {
				hasSPort = true
			}
			negated = false
		case "-p", "--protocol":
			val, neg, next := consumeFlagValue(tokens, i, negated)
			i = next
			if neg {
				protoNegated = true
			} else if val != "udp" && val != "tcp" && val != "all" {
				protoBad = true
			}
			negated = false
		case "-j", "--jump":
			val, neg, next := consumeFlagValue(tokens, i, negated)
			i = next
			if !neg {
				switch val {
				case "NOTRACK":
					hasNoTrack = true
				case "CT":
					hasCT = true
				}
			}
			negated = false
		case "--notrack":
			if !negated {
				hasCTNoTrack = true
			}
			negated = false
		default:
			negated = false
		}
	}
	if protoBad || protoNegated {
		return false
	}
	targetOK := hasNoTrack || (hasCT && hasCTNoTrack)
	addrPortOK := (hasDstIP && hasDPort) || (hasSrcIP && hasSPort)
	return targetOK && addrPortOK
}

func consumeFlagValue(tokens []ruleToken, i int, negated bool) (val string, neg bool, next int) {
	if i+1 >= len(tokens) {
		return "", negated, i
	}
	if !tokens[i+1].quoted && tokens[i+1].val == "!" {
		if i+2 < len(tokens) {
			return tokens[i+2].val, true, i + 2
		}
		return "", true, i + 1
	}
	return tokens[i+1].val, negated, i + 1
}

// parseNFTRawNoTrack checks `nft list table ip raw` output for matching
// `notrack` rules covering targetIP port 53 in both prerouting and output
// chains (matched by chain name or hook declaration, case-insensitively).
func parseNFTRawNoTrack(out, targetIP string) (preOK, outOK bool) {
	depth := 0
	chainDepth := 0
	currentChain := ""

	for line := range strings.SplitSeq(out, "\n") {
		tokens := tokenizeNFTLine(line)
		if len(tokens) == 0 {
			continue
		}
		if !tokens[0].quoted && tokens[0].val == "chain" && len(tokens) >= 2 {
			currentChain = normalizeNFTChain(tokens[1].val)
			chainDepth = depth + 1
		}
		if chainDepth > 0 {
			for i := 0; i+1 < len(tokens); i++ {
				if !tokens[i].quoted && tokens[i].val == "hook" {
					if c := normalizeNFTChain(tokens[i+1].val); c != "" {
						currentChain = c
					}
				}
			}
			if currentChain != "" && nftRuleMatches(tokens, targetIP) {
				if currentChain == "PREROUTING" {
					preOK = true
				} else {
					outOK = true
				}
			}
		}
		for _, tok := range tokens {
			if tok.quoted {
				continue
			}
			switch tok.val {
			case "{":
				depth++
			case "}":
				if depth > 0 {
					depth--
				}
				if chainDepth > 0 && depth < chainDepth {
					currentChain = ""
					chainDepth = 0
				}
			}
		}
	}
	return preOK, outOK
}

func normalizeNFTChain(name string) string {
	switch {
	case strings.EqualFold(name, "prerouting"):
		return "PREROUTING"
	case strings.EqualFold(name, "output"):
		return "OUTPUT"
	default:
		return ""
	}
}

func tokenizeNFTLine(line string) []ruleToken {
	var tokens []ruleToken
	var cur strings.Builder
	inToken := false
	quoted := false
	var quoteChar byte

	flush := func() {
		if inToken || quoted {
			tokens = append(tokens, ruleToken{val: cur.String(), quoted: quoted})
			cur.Reset()
			inToken = false
			quoted = false
		}
	}

	for i := 0; i < len(line); i++ {
		c := line[i]
		if quoteChar != 0 {
			if c == '\\' && quoteChar == '"' && i+1 < len(line) {
				i++
				cur.WriteByte(line[i])
				continue
			}
			if c == quoteChar {
				quoteChar = 0
				continue
			}
			cur.WriteByte(c)
			continue
		}
		if c == '#' {
			break
		}
		if c == ' ' || c == '\t' || c == '\r' {
			flush()
			continue
		}
		if c == '{' || c == '}' || c == ',' || c == ';' {
			flush()
			tokens = append(tokens, ruleToken{val: string(c)})
			continue
		}
		if c == '"' || c == '\'' {
			quoteChar = c
			quoted = true
			inToken = true
			continue
		}
		inToken = true
		cur.WriteByte(c)
	}
	flush()
	return tokens
}

func nftRuleMatches(tokens []ruleToken, targetIP string) bool {
	var (
		hasDAddr, hasSAddr     bool
		hasDPort, hasSPort     bool
		hasNoTrack, hasCT      bool
		hasCTNoTrack           bool
		protoBad, protoNegated bool
	)
	for i := 0; i < len(tokens); i++ {
		tok := tokens[i]
		if tok.quoted {
			continue
		}
		switch tok.val {
		case "comment":
			if i+1 < len(tokens) {
				i++
			}
		case "notrack":
			hasNoTrack = true
		case "--notrack":
			hasCTNoTrack = true
		case "xt":
			if i+2 < len(tokens) && !tokens[i+1].quoted && tokens[i+1].val == "target" {
				target := tokens[i+2].val
				switch target {
				case "NOTRACK":
					hasNoTrack = true
				case "CT":
					hasCT = true
				}
				i += 2
			}
		case "ip":
			if i+2 < len(tokens) && !tokens[i+1].quoted &&
				(tokens[i+1].val == "daddr" || tokens[i+1].val == "saddr") {
				isDst := tokens[i+1].val == "daddr"
				matched, next := matchNFTExprOrSet(tokens, i+2, func(v string) bool {
					return matchTargetIP(v, targetIP)
				})
				i = next
				if matched {
					if isDst {
						hasDAddr = true
					} else {
						hasSAddr = true
					}
				}
			}
		case "dport", "sport":
			isDst := tok.val == "dport"
			if i > 0 && !tokens[i-1].quoted && tokens[i-1].val == "!" {
				continue
			}
			matched, next := matchNFTExprOrSet(tokens, i+1, func(v string) bool {
				return v == nldPort
			})
			i = next
			if matched {
				if isDst {
					hasDPort = true
				} else {
					hasSPort = true
				}
			}
		case "l4proto":
			if i+1 < len(tokens) && !tokens[i+1].quoted &&
				(tokens[i+1].val == "!=" || tokens[i+1].val == "!") {
				protoNegated = true
				continue
			}
			matched, next := matchNFTExprOrSet(tokens, i+1, func(v string) bool {
				return v == "udp" || v == "tcp"
			})
			i = next
			if !matched {
				protoBad = true
			}
		}
	}
	if protoBad || protoNegated {
		return false
	}
	targetOK := hasNoTrack || (hasCT && hasCTNoTrack)
	addrPortOK := (hasDAddr && hasDPort) || (hasSAddr && hasSPort)
	return targetOK && addrPortOK
}

// matchNFTExprOrSet inspects either a single value token or a `{ ... }` set
// starting at startIdx, returning false if preceded by `!=` or `!`.
func matchNFTExprOrSet(tokens []ruleToken, startIdx int, pred func(string) bool) (matched bool, lastIdx int) {
	if startIdx >= len(tokens) {
		return false, len(tokens) - 1
	}
	tok := tokens[startIdx]
	if !tok.quoted && (tok.val == "!=" || tok.val == "!") {
		return false, startIdx
	}
	if !tok.quoted && tok.val == "{" {
		for j := startIdx + 1; j < len(tokens); j++ {
			if !tokens[j].quoted && tokens[j].val == "}" {
				return matched, j
			}
			if !tokens[j].quoted && tokens[j].val == "," {
				continue
			}
			if pred(tokens[j].val) {
				matched = true
			}
		}
		return false, len(tokens) - 1
	}
	return pred(tok.val), startIdx
}

func matchTargetIP(val, targetIP string) bool {
	if val == targetIP || val == targetIP+"/32" {
		return true
	}
	return false
}

func portListContains(val, want string) bool {
	for p := range strings.SplitSeq(val, ",") {
		if strings.TrimSpace(p) == want {
			return true
		}
	}
	return false
}
