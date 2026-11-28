// nld_notrack_parse.go — iptables-save and nft raw-table NOTRACK rule parsers
// for checkNodeLocalDNSNoTrack. Split out of nld_notrack.go.
package nethealth

import "strings"

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
