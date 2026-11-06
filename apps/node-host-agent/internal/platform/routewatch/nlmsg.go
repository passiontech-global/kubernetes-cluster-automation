// nlmsg.go — the generic NETLINK_ROUTE wire decode: the nlmsg
// datagram walk (ScanMessages), the rtattr extractor (Attrs) and
// the alignment helpers both need. Fail-open is the contract a
// route guard runs on: a message too torn to classify still counts
// as relevant — a missed real delete strands the node for minutes
// while a spurious trigger costs one idempotent reconcile.
package routewatch

import (
	"encoding/binary"

	"golang.org/x/sys/unix"
)

// FibRuleHdrLen is sizeof(struct fib_rule_hdr) — the fixed header a
// DELRULE payload carries before its rtattr list (x/sys exports no
// constant for it).
const FibRuleHdrLen = 12

// ScanMessages walks the nlmsg datagram in buf and reports whether
// isRelevant claims at least one message — the caller's callback
// owns which message types and payload fields count (the nebula
// dataplane identity in nethealth's routeEventFilter). Netlink
// headers are host byte order — binary.NativeEndian matches the
// kernel layout without unsafe. Fail-open: a torn header or tail
// can't be proven NOT to be a relevant delete, so it counts.
func ScanMessages(buf []byte, isRelevant func(msgType uint16, payload []byte) bool) bool {
	for len(buf) > 0 {
		if len(buf) < unix.NLMSG_HDRLEN {
			return true
		}
		ln := int(binary.NativeEndian.Uint32(buf[0:4]))
		typ := binary.NativeEndian.Uint16(buf[4:6])
		if ln < unix.NLMSG_HDRLEN || ln > len(buf) {
			return true
		}
		if isRelevant(typ, buf[unix.NLMSG_HDRLEN:ln]) {
			return true
		}
		// The next message sits at the aligned offset — but the
		// kernel may not pad the LAST message to alignment, so the
		// offset can land exactly at or past the buffer end.
		if next := Align(ln); next < len(buf) {
			buf = buf[next:]
		} else {
			return false
		}
	}
	return false
}

// Attrs walks a rtattr list and extracts the wanted u32-valued
// attributes. clean=false means the walk hit a torn attribute
// (rta_len shorter than the header or running past the buffer end)
// — the wanted values may sit in the unread tail, so callers treat
// !clean as undecodable. A last attribute whose ALIGNMENT padding
// overruns the buffer is a clean end: the kernel need not pad the
// final attribute of a message.
func Attrs(buf []byte, wants ...uint16) (map[uint16]uint32, bool) {
	found := map[uint16]uint32{}
	want := map[uint16]bool{}
	for _, w := range wants {
		want[w] = true
	}
	for len(buf) >= unix.SizeofRtAttr {
		ln := int(binary.NativeEndian.Uint16(buf[0:2]))
		typ := binary.NativeEndian.Uint16(buf[2:4])
		if ln < unix.SizeofRtAttr || ln > len(buf) {
			return found, false
		}
		if want[typ] && ln >= unix.SizeofRtAttr+4 {
			found[typ] = binary.NativeEndian.Uint32(buf[4:8])
		}
		if next := RTAAlign(ln); next < len(buf) {
			buf = buf[next:]
		} else {
			return found, next == len(buf) || ln == len(buf)
		}
	}
	// A <4B residue can't hold an attribute (min rta_len is the
	// header) — treat it as undecodable rather than silently exact.
	return found, len(buf) == 0
}

// Align rounds an nlmsg length up to the NLMSG_ALIGNTO boundary —
// the offset where the next message in the datagram would sit.
func Align(ln int) int {
	return (ln + int(unix.NLMSG_ALIGNTO) - 1) &^ (int(unix.NLMSG_ALIGNTO) - 1)
}

// RTAAlign rounds an rtattr length up to the RTA_ALIGNTO boundary —
// the offset where the next attribute in the list would sit.
func RTAAlign(ln int) int {
	return (ln + int(unix.RTA_ALIGNTO) - 1) &^ (int(unix.RTA_ALIGNTO) - 1)
}
