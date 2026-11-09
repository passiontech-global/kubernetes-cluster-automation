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
	"strings"
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

// ---------- rendered-config gates ----------
//
// A second class of vars-derived scalars never reaches a shell: it is
// rendered verbatim into config FILES (kubelet KubeletConfiguration
// YAML, containerd toml, systemd drop-in LimitNOFILE=, /etc/sysctl.d
// pairs). The injection shape is the same minus the shell — a newline
// in a var turns one scalar into extra keys/lines the consuming
// daemon parses wholesale. Like the SH* predicates these are pure;
// the caller owns the error attribution and the skip scope.

var (
	// sysctl keys are dotted procfs knob paths (net.ipv4.tcp_tw_reuse,
	// fs.aio-max-nr, kernel.pid_max) — anything outside the namespace
	// cannot address a sysctl and would render as garbage or an
	// injected directive.
	sysctlKeyRe = regexp.MustCompile(`^[a-zA-Z0-9._/-]+$`)

	// systemd LimitNOFILE= accepts digits, soft:hard digit pairs, or
	// the unit's own specials; anything else systemd drops at
	// daemon-reload with a parse warning and the unit silently keeps
	// stock fd limits.
	limitNOFILERe = regexp.MustCompile(`^(?:[0-9]+|infinity|max|unset)(?::(?:[0-9]+|infinity|max|unset))?$`)
)

// CfgScalar reports whether s may be rendered as a plain scalar into
// a config file (YAML mapping value, toml assignment): printable
// ASCII only — a control byte, first of all '\n', would splice an
// extra key/line into the file — and no ':' or '#', the mapping /
// comment separators that re-open the file's syntax.
func CfgScalar(s string) bool {
	return printableASCII(s) && !strings.ContainsAny(s, ":#")
}

// CfgSysctlKey validates a sysctl key for the /etc/sysctl.d render.
func CfgSysctlKey(s string) bool {
	return sysctlKeyRe.MatchString(s)
}

// CfgSysctlVal validates a sysctl VALUE: printable ASCII. That covers
// the no-newline contract — a newline in a var would render further
// `key = value` lines the next `sysctl --system` applies verbatim —
// while keeping every legitimate shape (numbers, ranges, space lists).
func CfgSysctlVal(s string) bool {
	return printableASCII(s)
}

// CfgLimitNOFILE validates a systemd LimitNOFILE= assignment.
func CfgLimitNOFILE(s string) bool {
	return limitNOFILERe.MatchString(s)
}

// printableASCII — non-empty, every byte 0x20-0x7e. No control bytes
// means no newline, tab, or NUL anywhere in the rendered scalar.
func printableASCII(s string) bool {
	if s == "" {
		return false
	}
	for i := range s {
		if s[i] < 0x20 || s[i] > 0x7e {
			return false
		}
	}
	return true
}
