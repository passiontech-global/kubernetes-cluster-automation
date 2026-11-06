// shell.go — `sh -c` interpolation gates.
//
// Convergers build `sh -c`/`bash -c` command strings with
// vars-derived values (mesh tables/dev, IPs, ports). Many of those
// values land inside sed/grep patterns where shell-quoting would
// corrupt the match — so the gate is a strict charset/shape check
// applied BEFORE any command is built, not quoting at the
// interpolation site. The predicates are pure: the caller decides
// whether a refusal is a cycle error, a skip, or a hard abort.
package converge

import (
	"net/netip"
	"regexp"
	"strconv"
)

// SHTokenRe is the safe-charset gate for values interpolated into
// host shell commands: IPs, CIDRs, netdev/table names and paths all
// fit; space, quote, $, `, ; & | < > never do.
var SHTokenRe = regexp.MustCompile(`^[A-Za-z0-9_.,:/@%+=-]+$`)

// SHToken reports whether a value may be interpolated into a host
// shell command. Empty stays allowed (an empty value cannot inject)
// — but see the *Req variants: at slots where the value is REQUIRED
// an empty pass still emits a malformed command.
func SHToken(s string) bool {
	return s == "" || SHTokenRe.MatchString(s)
}

// SHIPCIDR is SHToken for IP/prefix values — netip parse enforces
// real IP/CIDR shape on top of the charset (a malformed value would
// only produce a failing ip/nft invocation; better the caller
// surfaces it than a silent shell failure).
func SHIPCIDR(s string) bool {
	if s == "" {
		return true
	}
	if _, err := netip.ParseAddr(s); err == nil {
		return true
	}
	if _, err := netip.ParsePrefix(s); err == nil {
		return true
	}
	return false
}

// SHMarkerBase validates a marker subnet base (e.g. "172.29.0") —
// rules use it as <base>.0/24, so <base>.0 must be a valid IPv4
// addr (a 3-octet base, NOT a full IP).
func SHMarkerBase(s string) bool {
	if s == "" {
		return true
	}
	_, err := netip.ParseAddr(s + ".0")
	return err == nil
}

// SHPort is SHToken for TCP/UDP ports destined for --dport or
// /dev/tcp interpolation: digits only, 1-65535.
func SHPort(s string) bool {
	if s == "" {
		return true
	}
	n, err := strconv.Atoi(s)
	return err == nil && n >= 1 && n <= 65535
}

// The *Req variants are the same gates for slots where the value is
// REQUIRED: an empty value there cannot inject, but it still emits
// a malformed command (`ip route replace default dev neb1 src
// <blank>`, `--dport <blank>`) that only fails inside `sh -c`.

func SHIPCIDRReq(s string) bool { return s != "" && SHIPCIDR(s) }

func SHPortReq(s string) bool { return s != "" && SHPort(s) }
