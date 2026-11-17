//go:build linux

// sockdiag_linux.go — the NETLINK_SOCK_DIAG half: the 1-pass TCP
// census (TCPTables — per-state histogram + per-tuple hot-spot
// table) and the SOCK_DESTROY listener kill
// (DestroyListenersOnPort — the in-process `ss -K` replacement).
// Both run for pid's netns through the InNetNS setns scope.
// Split out of sockstat_linux.go so each file stays under the
// ~500-LOC bar; the cheap /proc sockstat{,6} aggregate reader
// stays there.
package netlinkx

import (
	"encoding/binary"
	"errors"
	"fmt"
	"net"
	"strconv"
	"sync"
	"time"

	"golang.org/x/sys/unix"
)

// --- NETLINK_SOCK_DIAG TCP census: the one binary read --------------------
//
// inet_diag_req_v2 (64 bytes) / inet_diag_msg (72 bytes) wire
// layouts, linux/include/uapi/linux/inet_diag.h. Each dump reply
// message already carries everything the per-cycle connection-table
// evidence needs — idiag_state at byte offset 1 (the per-state
// histogram) and the idiag_sockid's daddr/dport (the per-tuple
// hot-spot table) — so ONE session serving the AF_INET + AF_INET6
// dumps replaces the old two-socket-per-family histogram AND the
// /proc/net/tcp{,6} text scan that fed CLOSE_WAIT + the hot tuples.

const (
	nlmsgDone  = 3  // NLMSG_DONE
	nlmsgError = 2  // NLMSG_ERROR
	diagReqV2  = 64 // sizeof(struct inet_diag_req_v2)
	diagMsg    = 72 // sizeof(struct inet_diag_msg)
)

// diagBufPool recycles the 64 KiB receive buffer across cycles —
// the dump reply batches churn megabytes per scrape on a busy node,
// and a fresh 1<<16 allocation per family per cycle is pure GC load.
var diagBufPool = sync.Pool{
	New: func() any { b := make([]byte, 1<<16); return &b },
}

// TCPTables is the 1-pass NETLINK_SOCK_DIAG census for pid's netns:
// one bound socket, both address families dumped through it (seq
// 10/11), every inet_diag_msg folded once. Runs inside InNetNS so a
// non-hostNetwork pod sees the host table.
func TCPTables(pid int) (TCPCensus, error) {
	var c TCPCensus
	err := InNetNS(pid, func() error { return tcpCensusDump(&c) })
	return c, err
}

// tcpCensusDump sends the AF_INET + AF_INET6 SOCK_DIAG_BY_FAMILY
// dumps over ONE socket and folds the replies until each family's
// NLMSG_DONE arrives. Netlink serializes NLM_F_DUMP requests per
// socket — a second dump sent while the first still streams answers
// EBUSY — so the two families drain sequentially; the merge still
// saves one full socket+bind+rcvtimeo setup per cycle. A failed dump
// leaves out zeroed — the caller treats an error as "inconclusive,
// emit nothing".
func diagRecvLoop(fd int, buf []byte, op string, onBatch func([]byte) (bool, error)) error {
	for {
		n, _, rerr := unix.Recvfrom(fd, buf, 0)
		if errors.Is(rerr, unix.EINTR) {
			continue // signal interruption is not a dump failure
		}
		if rerr != nil {
			return fmt.Errorf("%s: %w", op, rerr)
		}
		done, err := onBatch(buf[:n])
		if err != nil {
			return err
		}
		if done {
			return nil
		}
	}
}

// tcpCensusDump opens one NETLINK_SOCK_DIAG socket and dumps AF_INET
// + AF_INET6 TCP tables into out. Pre-sized out + pooled 64 KiB recv
// buffer keep per-cycle allocations to the map growth alone.
func tcpCensusDump(out *TCPCensus) error {
	out.States = map[uint8]int{}
	out.PerTuple = map[string]int{}
	fd, err := diagSock()
	if err != nil {
		return err
	}
	defer func() { _ = unix.Close(fd) }()
	sa := &unix.SockaddrNetlink{Family: unix.AF_NETLINK}

	bufp := diagBufPool.Get().(*[]byte)
	defer diagBufPool.Put(bufp)
	buf := *bufp

	// idiag_states=0xFFF dumps every state; no extensions requested,
	// so the reply payload is the fixed 72-byte inet_diag_msg.
	for _, family := range []uint8{unix.AF_INET, unix.AF_INET6} {
		if err := unix.Sendto(fd, diagRequest(1, family, 0xFFF, nil,
			unix.SOCK_DIAG_BY_FAMILY, unix.NLM_F_REQUEST|unix.NLM_F_DUMP),
			0, sa); err != nil {
			return fmt.Errorf("sock_diag send %d: %w", family, err)
		}
		if err := diagRecvLoop(fd, buf, fmt.Sprintf("sock_diag recv %d", family), func(b []byte) (bool, error) {
			endSeq, ferr := parseDiagCensus(b, out)
			return endSeq != 0, ferr
		}); err != nil {
			if family == unix.AF_INET6 && noInet6Family(err) {
				continue // kernel has no IPv6 — not an error
			}
			return err
		}
	}
	return nil
}

// noInet6Family reports whether err is the kernel's "no such
// protocol family" answer for an AF_INET6 dump — ipv6.disable=1 /
// a kernel without IPv6 returns EAFNOSUPPORT (older kernels
// EOPNOTSUPP, containers EINVAL-adjacent ENOENT variants). The
// AF_INET half already succeeded; the census just has no v6 rows.
func noInet6Family(err error) bool {
	return errors.Is(err, unix.EAFNOSUPPORT) ||
		errors.Is(err, unix.EOPNOTSUPP) ||
		errors.Is(err, unix.ENOENT)
}

// parseDiagCensus folds every inet_diag_msg in one recv batch into
// out — idiag_state into States, the sockid daddr+dport into
// PerTuple — and returns the nlmsg seq of the terminating
// NLMSG_DONE/NLMSG_ERROR (0 when the batch was mid-dump).
// NLMSG_ERROR payloads carry a negative errno — a positive/zero
// error is an ACK and ends the dump silently (kernel sent nothing
// more).
// walkNLMsgs iterates 4-byte-aligned netlink messages in buf, handling
// NLMSG_DONE and NLMSG_ERROR (returning non-nil error on negative errno,
// or seq + done=true on ACK/DONE) and passing data payloads to onPayload.
func walkNLMsgs(buf []byte, destroyCtx bool, onPayload func(payload []byte)) (seq uint32, done bool, err error) {
	for len(buf) >= 16 {
		length := int(binary.LittleEndian.Uint32(buf[0:4]))
		mtype := binary.LittleEndian.Uint16(buf[4:6])
		msgSeq := binary.LittleEndian.Uint32(buf[8:12])
		if length < 16 || length > len(buf) {
			return 0, false, fmt.Errorf("sock_diag: bad nlmsg len %d", length)
		}
		switch mtype {
		case nlmsgDone:
			return msgSeq, true, nil
		case nlmsgError:
			if length >= 20 {
				errno := int32(binary.LittleEndian.Uint32(buf[16:20]))
				if errno < 0 {
					if destroyCtx {
						return 0, false, fmt.Errorf("sock_diag destroy: %w", unix.Errno(-errno))
					}
					return 0, false, fmt.Errorf("sock_diag: %w", unix.Errno(-errno))
				}
			}
			return msgSeq, true, nil
		default:
			if onPayload != nil {
				onPayload(buf[16:length])
			}
		}
		// NLMSG_ALIGN(4): headers and payloads are 4-byte aligned.
		// A short tail batch can round the aligned length past the
		// buffer — clamp instead of trusting the kernel's padding.
		advance := (length + 3) &^ 3
		if advance > len(buf) {
			advance = len(buf)
		}
		buf = buf[advance:]
	}
	return 0, false, nil
}

func parseDiagCensus(buf []byte, out *TCPCensus) (uint32, error) {
	seq, _, err := walkNLMsgs(buf, false, func(payload []byte) {
		// inet_diag_msg: family@0, state@1, sockid@4 —
		// dport (BE) at sockid+2, daddr at sockid+20 (4 bytes
		// for AF_INET, the full 16 for AF_INET6; the kernel
		// stores __be32s verbatim, so the bytes are already
		// network order).
		if len(payload) < diagMsg {
			return
		}
		if payload[0] == unix.AF_INET || payload[0] == unix.AF_INET6 {
			out.States[payload[1]]++
			var kb [18]byte
			k := kb[:6]
			if payload[0] == unix.AF_INET6 {
				k = kb[:18]
				copy(kb[:16], payload[24:40])
			} else {
				copy(kb[:4], payload[24:28])
			}
			copy(k[len(k)-2:], payload[6:8])
			out.PerTuple[string(k)]++
		}
	})
	return seq, err
}

// DiagEndpoint renders a census PerTuple key (raw daddr bytes +
// big-endian dport) as "a.b.c.d:port" / "[v6]:port" — byte-for-byte
// the string the old /proc/net/tcp rem_address column decode
// produced (hexSockAddr): the 4-byte path reverses nothing because
// idiag_dst already carries network order, and net.IP's 16-byte
// String() applies the same v4-mapped unpadding the /proc word
// unshuffle fed. A malformed key stays raw — never a fabricated
// endpoint.
func DiagEndpoint(key string) string {
	port := 0
	switch len(key) {
	case 6:
		port = int(binary.BigEndian.Uint16([]byte(key[4:6])))
		return net.IP(key[:4]).String() + ":" + strconv.Itoa(port)
	case 18:
		port = int(binary.BigEndian.Uint16([]byte(key[16:18])))
		// net.IP.String's v4-mapped unpadding is the pinned output
		// contract here (filefd sockstat consumers match the bare
		// quad inside brackets) — v6String's preserved ::ffff:
		// prefix is only for parseListenAddrs, whose output feeds
		// address parsing that needs the real family marker.
		return "[" + net.IP(key[:16]).String() + "]:" + strconv.Itoa(port)
	}
	return key
}

// v6String renders a 16-byte IPv6 endpoint preserving the v4-mapped
// prefix — net.IP.String unmaps ::ffff:a.b.c.d to the bare dotted
// quad, which inside "[...]" brackets produces the malformed
// "[127.0.0.53]:53" instead of "[::ffff:127.0.0.53]:53". To4 on a
// 16-byte IP is non-nil exactly for the mapped form, so the check
// doubles as the discriminator.
func v6String(b []byte) string {
	if ip4 := net.IP(b).To4(); ip4 != nil {
		return "::ffff:" + ip4.String()
	}
	return net.IP(b).String()
}

// --- SOCK_DESTROY: the `ss -K` replacement --------------------
//
// inet_diag_req_v2 wire layout (linux/include/uapi/linux/
// inet_diag.h): sdiag_family/protocol/ext/pad (4) + idiag_states
// (4) + idiag_sockid (48) = 56, sent inside the 64-byte request
// buffer the dump path already uses. inet_diag_msg carries the same
// 48-byte sockid at payload offset 4; idiag_state sits at offset 1,
// idiag_sport (big-endian) at sockid+0 and idiag_dport (always 0
// for listeners) at sockid+2.
//
// The kill sequence mirrors iproute2's `ss -K`: dump the table
// (NLM_F_REQUEST|NLM_F_DUMP, LISTEN state only), keep the sockets
// matching the port filter, then send ONE SOCK_DESTROY request per
// socket with its sockid copied verbatim — the kernel's
// inet_diag_destroy walks the matching sockets and drops them.

const (
	tcpStateListen  = 10 // TCP_LISTEN in include/net/tcp_states.h
	tcpStateSynSent = 2  // TCP_SYN_SENT — the stuck-connect state P0.3 reaps
	sockidLen       = 48 // sizeof(struct inet_diag_sockid)
)

// sockMatch is one socket the destroy phase will kill: the address
// family, the idiag_retrans counter (SYN_SENT retransmit count —
// the wedge evidence), and the 48-byte idiag_sockid copied out of
// the dump.
type sockMatch struct {
	family  uint8
	retrans uint8
	id      [sockidLen]byte
}

// DestroyListenersOnPort kills every TCP LISTEN socket bound to
// port in pid's netns — the in-process `ss -K sport = :<port>`
// replacement (no ss binary, no fork). Returns the number of
// sockets destroyed; a socket that vanished between dump and
// destroy is not an error (the kernel simply matches nothing).
func DestroyListenersOnPort(pid int, port uint16) (int, error) {
	var killed int
	err := InNetNS(pid, func() error {
		var err error
		killed, err = destroyListeners(port)
		return err
	})
	return killed, err
}

// DestroyStuckSynSent kills TCP sockets wedged in SYN_SENT in pid's
// netns — the ephemeral-port guard's half of P0.3. Only sockets
// whose idiag_retrans (byte offset 3 of inet_diag_msg) reaches
// minRetrans count as wedged: a fresh SYN_SENT is a normal
// in-flight connect the kernel's own retransmit timer will resolve,
// while retrans >= 4 means the peer is unreachable and the socket
// pins an ephemeral port for minutes. maxKills bounds the destroy
// storm per call. Same dump→sockid→SOCK_DESTROY sequence as
// destroyListeners, filtered to TCP_SYN_SENT on both families.
// Returns the number of sockets destroyed.
func DestroyStuckSynSent(pid int, minRetrans uint8, maxKills int) (int, error) {
	var killed int
	err := InNetNS(pid, func() error {
		var err error
		killed, err = destroyByState(pid, tcpStateSynSent, minRetrans, maxKills)
		return err
	})
	return killed, err
}

// destroyByState dumps the TCP table filtered to one idiag state
// and SOCK_DESTROYs every sockid it finds whose idiag_retrans
// reaches minRetrans — the generalized form of destroyListeners
// (which is the LISTEN special case with a port filter). Runs
// inside the caller's (already-scoped) netns.
func destroyByState(pid int, state uint8, minRetrans uint8,
	maxKills int) (int, error) {
	fd, err := diagSock()
	if err != nil {
		return 0, err
	}
	defer func() { _ = unix.Close(fd) }()
	sa := &unix.SockaddrNetlink{Family: unix.AF_NETLINK}

	bufp := diagBufPool.Get().(*[]byte)
	defer diagBufPool.Put(bufp)
	buf := *bufp

	var matches []sockMatch
	stateMask := uint32(1) << state
	for _, family := range []uint8{unix.AF_INET, unix.AF_INET6} {
		if err := unix.Sendto(fd, diagRequest(1, family, stateMask, nil,
			unix.SOCK_DIAG_BY_FAMILY, unix.NLM_F_REQUEST|unix.NLM_F_DUMP),
			0, sa); err != nil {
			return 0, fmt.Errorf("sock_diag send %d: %w", family, err)
		}
		if err := diagRecvLoop(fd, buf, fmt.Sprintf("sock_diag recv %d", family), func(b []byte) (bool, error) {
			return collectStateSockets(b, family, state, &matches)
		}); err != nil {
			if family == unix.AF_INET6 && noInet6Family(err) {
				continue
			}
			return 0, err
		}
	}

	// Only wedged sockets die: idiag_retrans >= minRetrans, capped
	// at maxKills per call so one cycle cannot storm the kernel.
	killed := 0
	for i, m := range wedgedSynSent(matches, minRetrans, maxKills) {
		req := diagRequest(uint32(100+i), m.family, 0xFFF, &m.id,
			unix.SOCK_DESTROY, unix.NLM_F_REQUEST|unix.NLM_F_ACK)
		if err := unix.Sendto(fd, req, 0, sa); err != nil {
			return killed, fmt.Errorf("sock_diag destroy send: %w", err)
		}
		if err := diagRecvLoop(fd, buf, "sock_diag destroy recv", func(b []byte) (bool, error) {
			return true, parseDiagAck(b)
		}); err != nil {
			return killed, err
		}
		killed++
	}
	return killed, nil
}

// wedgedSynSent selects the sockids eligible for SOCK_DESTROY:
// idiag_retrans >= minRetrans (fresh in-flight connects stay
// alive — the kernel's own retransmit timer resolves them) and at
// most maxKills picks so one cycle cannot storm the kernel.
func wedgedSynSent(matches []sockMatch, minRetrans uint8,
	maxKills int) []sockMatch {
	var out []sockMatch
	for _, m := range matches {
		if m.retrans < minRetrans || len(out) >= maxKills {
			continue
		}
		out = append(out, m)
	}
	return out
}

// collectStateSockets folds one dump batch into matches — every
// socket whose idiag_state equals state (the kernel-side
// idiag_states filter already narrowed the reply, so this is a
// belt-and-suspenders recheck). done=true on NLMSG_DONE.
func collectStateSockets(buf []byte, family uint8, state uint8,
	matches *[]sockMatch) (bool, error) {
	_, done, err := walkNLMsgs(buf, false, func(payload []byte) {
		if len(payload) < 4+sockidLen {
			return
		}
		if payload[0] == family && payload[1] == state {
			var m sockMatch
			m.family = payload[0]
			// idiag_retrans sits at inet_diag_msg offset 3 —
			// the SYN_SENT retransmit counter the wedge filter
			// keys on.
			m.retrans = payload[3]
			copy(m.id[:], payload[4:4+sockidLen])
			*matches = append(*matches, m)
		}
	})
	return done, err
}

// diagSock opens a bound NETLINK_SOCK_DIAG socket with the same
// 5s receive budget the dump path uses.
func diagSock() (int, error) {
	fd, err := unix.Socket(unix.AF_NETLINK, unix.SOCK_RAW|unix.SOCK_CLOEXEC, unix.NETLINK_SOCK_DIAG)
	if err != nil {
		return -1, fmt.Errorf("sock_diag socket: %w", err)
	}
	if err := unix.Bind(fd, &unix.SockaddrNetlink{Family: unix.AF_NETLINK}); err != nil {
		_ = unix.Close(fd)
		return -1, fmt.Errorf("sock_diag bind: %w", err)
	}
	tv := unix.NsecToTimeval(5 * time.Second.Nanoseconds())
	if err := unix.SetsockoptTimeval(fd, unix.SOL_SOCKET, unix.SO_RCVTIMEO, &tv); err != nil {
		_ = unix.Close(fd)
		return -1, fmt.Errorf("sock_diag rcvtimeo: %w", err)
	}
	return fd, nil
}

// diagRequest builds the nlmsghdr+inet_diag_req_v2 dump/destroy
// payload shared by both phases: 16-byte header + 64-byte request.
// msgType selects the operation — SOCK_DIAG_BY_FAMILY for dumps,
// SOCK_DESTROY for kills; flags carry NLM_F_DUMP on dumps (a bare
// request is a single-socket lookup by sockid, which answers
// ENOENT for an all-zero id) and NLM_F_ACK on destroys.
func diagRequest(seq uint32, family uint8, states uint32,
	id *[sockidLen]byte, msgType, flags uint16) []byte {
	return diagRequestProto(seq, family, unix.IPPROTO_TCP, states,
		id, msgType, flags)
}

func diagRequestProto(seq uint32, family uint8, proto uint8, states uint32,
	id *[sockidLen]byte, msgType, flags uint16) []byte {
	req := make([]byte, 16+diagReqV2)
	binary.LittleEndian.PutUint32(req[0:], uint32(16+diagReqV2)) // nlmsg_len
	binary.LittleEndian.PutUint16(req[4:], msgType)
	binary.LittleEndian.PutUint16(req[6:], flags)
	binary.LittleEndian.PutUint32(req[8:], seq)
	req[16] = family
	req[17] = proto
	binary.LittleEndian.PutUint32(req[20:], states) // idiag_states
	if id != nil {
		copy(req[24:24+sockidLen], id[:]) // idiag_sockid
	}
	return req
}

// destroyListeners runs the dump+destroy sequence inside the
// caller's (already-scoped) netns.
func destroyListeners(port uint16) (int, error) {
	fd, err := diagSock()
	if err != nil {
		return 0, err
	}
	defer func() { _ = unix.Close(fd) }()
	sa := &unix.SockaddrNetlink{Family: unix.AF_NETLINK}

	bufp := diagBufPool.Get().(*[]byte)
	defer diagBufPool.Put(bufp)
	buf := *bufp

	// Phase 1 — dump both families, collecting LISTEN sockets on
	// the target port. The dump REQUIRES NLM_F_REQUEST|NLM_F_DUMP
	// and idiag_states=1<<TCP_LISTEN: kernel-side filtering keeps
	// the reply table down to listeners, so the port filter below
	// never sees an established socket that happens to reuse a
	// dport matching the target.
	var matches []sockMatch
	for _, family := range []uint8{unix.AF_INET, unix.AF_INET6} {
		if err := unix.Sendto(fd, diagRequest(1, family, 1<<tcpStateListen, nil,
			unix.SOCK_DIAG_BY_FAMILY, unix.NLM_F_REQUEST|unix.NLM_F_DUMP),
			0, sa); err != nil {
			return 0, fmt.Errorf("sock_diag send %d: %w", family, err)
		}
		if err := diagRecvLoop(fd, buf, fmt.Sprintf("sock_diag recv %d", family), func(b []byte) (bool, error) {
			return collectPortListeners(b, family, port, &matches)
		}); err != nil {
			if family == unix.AF_INET6 && noInet6Family(err) {
				continue // kernel has no IPv6 — nothing v6 to kill
			}
			return 0, err
		}
	}

	// Phase 2 — one destroy request per matched socket id. The
	// kill op lives on SOCK_DESTROY (21), NOT SOCK_DIAG_BY_FAMILY
	// (20) — a type-20 request without NLM_F_DUMP is a lookup of
	// the all-zero sockid, never a kill. NLM_F_ACK so a hard
	// failure surfaces instead of silently dropping the request.
	killed := 0
	for i, m := range matches {
		req := diagRequest(uint32(100+i), m.family, 0xFFF, &m.id,
			unix.SOCK_DESTROY, unix.NLM_F_REQUEST|unix.NLM_F_ACK)
		if err := unix.Sendto(fd, req, 0, sa); err != nil {
			return killed, fmt.Errorf("sock_diag destroy send: %w", err)
		}
		// Drain the ACK/error reply so the socket buffer cannot
		// fill across a large listener table.
		if err := diagRecvLoop(fd, buf, "sock_diag destroy recv", func(b []byte) (bool, error) {
			return true, parseDiagAck(b)
		}); err != nil {
			return killed, err
		}
		killed++
	}
	return killed, nil
}

// collectPortListeners folds one recv batch of the dump into
// matches — LISTEN-state TCP sockets whose idiag_sport equals port.
// Returns done=true on NLMSG_DONE (same contract as parseDiagMsgs).
func collectPortListeners(buf []byte, family uint8, port uint16, matches *[]sockMatch) (bool, error) {
	_, done, err := walkNLMsgs(buf, false, func(payload []byte) {
		// inet_diag_msg: family@0 state@1, sockid@4 (48B) —
		// idiag_sport is sockid+0, big-endian (payload[4:6]);
		// idiag_dport (sockid+2) is always 0 for listeners.
		if len(payload) < 4+sockidLen {
			return
		}
		if payload[0] == family && payload[1] == tcpStateListen &&
			binary.BigEndian.Uint16(payload[4:6]) == port {
			var m sockMatch
			m.family = payload[0]
			copy(m.id[:], payload[4:4+sockidLen])
			*matches = append(*matches, m)
		}
	})
	return done, err
}

// parseDiagAck reads one destroy-phase reply: NLMSG_ERROR with a
// negative errno is a real failure EXCEPT ENOENT — the kernel
// answers ENOENT for a sockid that no longer exists, which is the
// desired idempotent outcome of a destroy (the listener already
// exited between the dump and the kill). Anything else (ACK,
// DONE) is success.
func parseDiagAck(buf []byte) error {
	_, _, err := walkNLMsgs(buf, true, nil)
	if errors.Is(err, unix.ENOENT) {
		return nil
	}
	return err
}

// --- listener census: the `ss -lntu` replacement --------------------------
//
// ListenAddrs returns the set of local endpoints ("ip:port",
// "[v6]:port") holding a socket a `ss -l` row would print for pid's
// netns: TCP sockets in TCP_LISTEN plus every bound UDP socket —
// UDP has no listen state, and ss -lun's UNCONN rows are exactly
// the sockets carrying a bound local port, so the UDP half keeps
// every state and lets the sport!=0 + caller's addr match do the
// filtering (a connected UDP client's ephemeral local port never
// collides with a service address). One SOCK_DIAG socket serves
// the TCP and UDP dumps for both address families, drained
// sequentially like the census path; a family the kernel lacks
// (ipv6.disable) is skipped, not an error.

// ListenAddrs is the in-process `ss -lntu` for checks that only
// need "is this endpoint bound here" — no ss binary, no fork.
func ListenAddrs(pid int) (map[string]struct{}, error) {
	out := map[string]struct{}{}
	err := InNetNS(pid, func() error { return listenAddrsDump(out) })
	return out, err
}

func listenAddrsDump(out map[string]struct{}) error {
	fd, err := diagSock()
	if err != nil {
		return err
	}
	defer func() { _ = unix.Close(fd) }()
	sa := &unix.SockaddrNetlink{Family: unix.AF_NETLINK}

	bufp := diagBufPool.Get().(*[]byte)
	defer diagBufPool.Put(bufp)
	buf := *bufp

	seq := uint32(30)
	for _, spec := range []struct {
		family uint8
		proto  uint8
	}{
		{unix.AF_INET, unix.IPPROTO_TCP},
		{unix.AF_INET, unix.IPPROTO_UDP},
		{unix.AF_INET6, unix.IPPROTO_TCP},
		{unix.AF_INET6, unix.IPPROTO_UDP},
	} {
		seq++
		if err := unix.Sendto(fd, diagRequestProto(seq, spec.family,
			spec.proto, 0xFFF, nil,
			unix.SOCK_DIAG_BY_FAMILY, unix.NLM_F_REQUEST|unix.NLM_F_DUMP),
			0, sa); err != nil {
			return fmt.Errorf("sock_diag send %d/%d: %w",
				spec.family, spec.proto, err)
		}
		if err := diagRecvLoop(fd, buf,
			fmt.Sprintf("sock_diag recv %d/%d", spec.family, spec.proto),
			func(b []byte) (bool, error) {
				endSeq, ferr := parseListenAddrs(b, spec.proto, out)
				return endSeq != 0, ferr
			}); err != nil {
			if spec.family == unix.AF_INET6 && noInet6Family(err) {
				continue // kernel has no IPv6 — not an error
			}
			return err
		}
	}
	return nil
}

// parseListenAddrs folds one dump batch into out — TCP rows only
// in TCP_LISTEN, UDP rows any state with a bound local port —
// and returns the terminating dump seq like parseDiagCensus.
func parseListenAddrs(buf []byte, proto uint8,
	out map[string]struct{}) (uint32, error) {
	seq, _, err := walkNLMsgs(buf, false, func(payload []byte) {
		if len(payload) < diagMsg {
			return
		}
		family := payload[0]
		if family != unix.AF_INET && family != unix.AF_INET6 {
			return
		}
		if proto == unix.IPPROTO_TCP && payload[1] != tcpStateListen {
			return
		}
		// idiag_sockid at payload+4: idiag_sport (BE u16) at +0,
		// idiag_src at +4 — 4 bytes AF_INET, 16 AF_INET6.
		sport := binary.BigEndian.Uint16(payload[4:6])
		if sport == 0 {
			return
		}
		port := strconv.Itoa(int(sport))
		switch family {
		case unix.AF_INET:
			out[net.IP(payload[8:12]).String()+":"+port] = struct{}{}
		case unix.AF_INET6:
			out["["+v6String(payload[8:24])+"]:"+port] = struct{}{}
		}
	})
	return seq, err
}
