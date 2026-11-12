//go:build linux

// sockstat_linux.go — the cheap aggregate reader and the
// NETLINK_SOCK_DIAG state histogram. /proc/<pid>/net/sockstat{,6}
// answers "how many sockets, how many TIME_WAIT" without a single
// syscall; TCPStates is the full per-state histogram `ss -tan`
// state counts come from, for pid's netns (InNetNS setns scope).
package netlinkx

import (
	"encoding/binary"
	"errors"
	"fmt"
	"os"
	"strconv"
	"strings"
	"time"

	"golang.org/x/sys/unix"
)

// Sockstat reads both sockstat files for pid's netns view
// (/proc/<pid>/net is already namespaced by the target pid — no
// setns needed for the file-based half).
func Sockstat(pid int) (SockstatV4, SockstatV6, error) {
	v4raw, err := os.ReadFile(fmt.Sprintf("/proc/%d/net/sockstat", pid))
	if err != nil {
		return SockstatV4{}, SockstatV6{}, fmt.Errorf("read sockstat: %w", err)
	}
	v6raw, err := os.ReadFile(fmt.Sprintf("/proc/%d/net/sockstat6", pid))
	if err != nil {
		return SockstatV4{}, SockstatV6{}, fmt.Errorf("read sockstat6: %w", err)
	}
	v4, err := parseSockstatV4(string(v4raw))
	if err != nil {
		return SockstatV4{}, SockstatV6{}, err
	}
	v6, err := parseSockstatV6(string(v6raw))
	if err != nil {
		return SockstatV4{}, SockstatV6{}, err
	}
	return v4, v6, nil
}

// parseKVLine splits "LABEL: k v k v ..." into its label and a
// k->v map. Malformed pairs are skipped — the kernel format is
// stable but a partial read must not zero the whole table.
func parseKVLine(line string) (string, map[string]int) {
	fields := strings.Fields(line)
	if len(fields) < 2 {
		return "", nil
	}
	label := strings.TrimSuffix(fields[0], ":")
	kv := map[string]int{}
	for i := 1; i+1 < len(fields); i += 2 {
		n, err := strconv.Atoi(fields[i+1])
		if err != nil {
			continue
		}
		kv[fields[i]] = n
	}
	return label, kv
}

func parseSockstatV4(raw string) (SockstatV4, error) {
	var s SockstatV4
	for _, line := range strings.Split(raw, "\n") {
		label, kv := parseKVLine(line)
		switch label {
		case "sockets":
			s.SocketsUsed = kv["used"]
		case "TCP":
			s.TCP = ProtoCounters{Inuse: kv["inuse"], Orphan: kv["orphan"], TimeWait: kv["tw"], Alloc: kv["alloc"], Mem: kv["mem"]}
		case "UDP":
			s.UDP = ProtoCounters{Inuse: kv["inuse"], Mem: kv["mem"]}
		case "RAW":
			s.RawInuse = kv["inuse"]
		case "FRAG":
			s.FragInuse = kv["inuse"]
			s.FragMem = kv["memory"]
		}
	}
	return s, nil
}

func parseSockstatV6(raw string) (SockstatV6, error) {
	var s SockstatV6
	for _, line := range strings.Split(raw, "\n") {
		label, kv := parseKVLine(line)
		switch label {
		case "TCP6":
			s.TCPInuse = kv["inuse"]
		case "UDP6":
			s.UDPInuse = kv["inuse"]
		case "RAW6":
			s.RawInuse = kv["inuse"]
		case "FRAG6":
			s.FragInuse = kv["inuse"]
			s.FragMem = kv["memory"]
		}
	}
	return s, nil
}

// --- NETLINK_SOCK_DIAG TCP state histogram --------------------
//
// inet_diag_req_v2 (64 bytes) / inet_diag_msg (72 bytes) wire
// layouts, linux/include/uapi/linux/inet_diag.h. Only idiag_state
// (byte offset 1 of the message) is consumed — the dump gives
// every socket's state without parsing addresses/cookies.

const (
	nlmsgDone  = 3  // NLMSG_DONE
	nlmsgError = 2  // NLMSG_ERROR
	diagReqV2  = 64 // sizeof(struct inet_diag_req_v2)
	diagMsg    = 72 // sizeof(struct inet_diag_msg)
)

// TCPStates returns a TCP socket-state histogram for pid's netns
// — key is the kernel idiag_state (1=ESTABLISHED .. 12=TIME_WAIT,
// see include/net/tcp_states.h), value the socket count across
// IPv4+IPv6. Runs inside InNetNS so a non-hostNetwork pod sees the
// host table.
func TCPStates(pid int) (map[uint8]int, error) {
	var states map[uint8]int
	err := InNetNS(pid, func() error {
		var err error
		states, err = tcpStatesDump()
		return err
	})
	return states, err
}

func tcpStatesDump() (map[uint8]int, error) {
	out := map[uint8]int{}
	for _, family := range []uint8{unix.AF_INET, unix.AF_INET6} {
		if err := diagDumpFamily(family, out); err != nil {
			return nil, err
		}
	}
	return out, nil
}

// diagDumpFamily issues one SOCK_DIAG_BY_FAMILY dump for TCP
// sockets of the given address family and folds idiag_state
// counts into out.
func diagDumpFamily(family uint8, out map[uint8]int) error {
	fd, err := unix.Socket(unix.AF_NETLINK, unix.SOCK_RAW|unix.SOCK_CLOEXEC, unix.NETLINK_SOCK_DIAG)
	if err != nil {
		return fmt.Errorf("sock_diag socket: %w", err)
	}
	defer func() { _ = unix.Close(fd) }()

	if err := unix.Bind(fd, &unix.SockaddrNetlink{Family: unix.AF_NETLINK}); err != nil {
		return fmt.Errorf("sock_diag bind: %w", err)
	}
	// A wedged dump must not hang the subsystem cycle forever.
	tv := unix.NsecToTimeval(5 * time.Second.Nanoseconds())
	if err := unix.SetsockoptTimeval(fd, unix.SOL_SOCKET, unix.SO_RCVTIMEO, &tv); err != nil {
		return fmt.Errorf("sock_diag rcvtimeo: %w", err)
	}

	// inet_diag_req_v2: family/protocol/ext/pad + states + 48-byte
	// zeroed idiag_sockid. idiag_states=0xFFF dumps every state.
	req := make([]byte, 16+diagReqV2)
	binary.LittleEndian.PutUint32(req[0:], uint32(16+diagReqV2)) // nlmsg_len
	binary.LittleEndian.PutUint16(req[4:], unix.SOCK_DIAG_BY_FAMILY)
	binary.LittleEndian.PutUint16(req[6:], unix.NLM_F_REQUEST|unix.NLM_F_DUMP)
	binary.LittleEndian.PutUint32(req[8:], 1) // seq
	req[16] = family
	req[17] = unix.IPPROTO_TCP
	binary.LittleEndian.PutUint32(req[20:], 0xFFF) // idiag_states

	sa := &unix.SockaddrNetlink{Family: unix.AF_NETLINK}
	if err := unix.Sendto(fd, req, 0, sa); err != nil {
		return fmt.Errorf("sock_diag send %d: %w", family, err)
	}

	buf := make([]byte, 1<<16)
	for {
		n, _, err := unix.Recvfrom(fd, buf, 0)
		if errors.Is(err, unix.EINTR) {
			continue // signal interruption is not a dump failure
		}
		if err != nil {
			return fmt.Errorf("sock_diag recv %d: %w", family, err)
		}
		done, derr := parseDiagMsgs(buf[:n], out)
		if derr != nil {
			return derr
		}
		if done {
			return nil
		}
	}
}

// parseDiagMsgs folds every inet_diag_msg in one recv batch into
// out; returns done=true on NLMSG_DONE. NLMSG_ERROR payloads carry
// a negative errno — a positive/zero error is an ACK and ends the
// dump silently (kernel sent nothing more).
func parseDiagMsgs(buf []byte, out map[uint8]int) (bool, error) {
	for len(buf) >= 16 {
		length := int(binary.LittleEndian.Uint32(buf[0:4]))
		mtype := binary.LittleEndian.Uint16(buf[4:6])
		if length < 16 || length > len(buf) {
			return false, fmt.Errorf("sock_diag: bad nlmsg len %d", length)
		}
		switch mtype {
		case nlmsgDone:
			return true, nil
		case nlmsgError:
			if length >= 20 {
				errno := int32(binary.LittleEndian.Uint32(buf[16:20]))
				if errno < 0 {
					return false, fmt.Errorf("sock_diag: %w", unix.Errno(-errno))
				}
			}
			return true, nil
		default:
			// inet_diag_msg: family@0 state@1 — only state needed.
			if length >= 16+diagMsg {
				payload := buf[16:length]
				if payload[0] == unix.AF_INET || payload[0] == unix.AF_INET6 {
					out[payload[1]]++
				}
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
	return false, nil
}

// --- SOCK_DESTROY: the `ss -K` replacement --------------------
//
// inet_diag_req_v2 wire layout (linux/include/uapi/linux/
// inet_diag.h): sdiag_family/protocol/ext/pad (4) + idiag_states
// (4) + idiag_sockid (48) = 56, sent inside the 64-byte request
// buffer the dump path already uses. inet_diag_msg carries the same
// 48-byte sockid at payload offset 4; idiag_state sits at offset 1
// and idiag_dport (big-endian) at sockid+2.
//
// The kill sequence mirrors iproute2's `ss -K`: dump the table,
// keep the sockets matching the filter, then send ONE non-dump
// SOCK_DIAG_BY_FAMILY request per socket with its sockid copied
// verbatim — the kernel's inet_diag_destroy walks the matching
// sockets and drops them.

const (
	tcpStateListen = 10 // TCP_LISTEN in include/net/tcp_states.h
	sockidLen      = 48 // sizeof(struct inet_diag_sockid)
)

// sockMatch is one socket the destroy phase will kill: the address
// family plus the 48-byte idiag_sockid copied out of the dump.
type sockMatch struct {
	family uint8
	id     [sockidLen]byte
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
func diagRequest(seq uint32, family uint8, states uint32, id *[sockidLen]byte) []byte {
	req := make([]byte, 16+diagReqV2)
	binary.LittleEndian.PutUint32(req[0:], uint32(16+diagReqV2)) // nlmsg_len
	binary.LittleEndian.PutUint16(req[4:], unix.SOCK_DIAG_BY_FAMILY)
	binary.LittleEndian.PutUint16(req[6:], unix.NLM_F_REQUEST)
	binary.LittleEndian.PutUint32(req[8:], seq)
	req[16] = family
	req[17] = unix.IPPROTO_TCP
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

	// Phase 1 — dump both families, collecting LISTEN sockets on
	// the target port.
	var matches []sockMatch
	for _, family := range []uint8{unix.AF_INET, unix.AF_INET6} {
		if err := unix.Sendto(fd, diagRequest(1, family, 0xFFF, nil), 0, sa); err != nil {
			return 0, fmt.Errorf("sock_diag send %d: %w", family, err)
		}
		buf := make([]byte, 1<<16)
		for {
			n, _, rerr := unix.Recvfrom(fd, buf, 0)
			if errors.Is(rerr, unix.EINTR) {
				continue
			}
			if rerr != nil {
				return 0, fmt.Errorf("sock_diag recv %d: %w", family, rerr)
			}
			done, merr := collectPortListeners(buf[:n], family, port, &matches)
			if merr != nil {
				return 0, merr
			}
			if done {
				break
			}
		}
	}

	// Phase 2 — one destroy request per matched socket id.
	killed := 0
	for i, m := range matches {
		req := diagRequest(uint32(100+i), m.family, 0xFFF, &m.id)
		// NLM_F_ACK so a hard failure surfaces instead of silently
		// dropping the request.
		binary.LittleEndian.PutUint16(req[6:], unix.NLM_F_REQUEST|unix.NLM_F_ACK)
		if err := unix.Sendto(fd, req, 0, sa); err != nil {
			return killed, fmt.Errorf("sock_diag destroy send: %w", err)
		}
		// Drain the ACK/error reply so the socket buffer cannot
		// fill across a large listener table.
		buf := make([]byte, 4096)
		for {
			n, _, rerr := unix.Recvfrom(fd, buf, 0)
			if errors.Is(rerr, unix.EINTR) {
				continue
			}
			if rerr != nil {
				return killed, fmt.Errorf("sock_diag destroy recv: %w", rerr)
			}
			if ackErr := parseDiagAck(buf[:n]); ackErr != nil {
				return killed, ackErr
			}
			break
		}
		killed++
	}
	return killed, nil
}

// collectPortListeners folds one recv batch of the dump into
// matches — LISTEN-state TCP sockets whose idiag_dport equals port.
// Returns done=true on NLMSG_DONE (same contract as parseDiagMsgs).
func collectPortListeners(buf []byte, family uint8, port uint16, matches *[]sockMatch) (bool, error) {
	for len(buf) >= 16 {
		length := int(binary.LittleEndian.Uint32(buf[0:4]))
		mtype := binary.LittleEndian.Uint16(buf[4:6])
		if length < 16 || length > len(buf) {
			return false, fmt.Errorf("sock_diag: bad nlmsg len %d", length)
		}
		switch mtype {
		case nlmsgDone:
			return true, nil
		case nlmsgError:
			if length >= 20 {
				errno := int32(binary.LittleEndian.Uint32(buf[16:20]))
				if errno < 0 {
					return false, fmt.Errorf("sock_diag: %w", unix.Errno(-errno))
				}
			}
			return true, nil
		default:
			// inet_diag_msg: family@0 state@1, sockid@4 (48B) —
			// dport is sockid+2 big-endian.
			if length >= 16+4+sockidLen {
				payload := buf[16:]
				if payload[0] == family && payload[1] == tcpStateListen &&
					binary.BigEndian.Uint16(payload[6:8]) == port {
					var m sockMatch
					m.family = payload[0]
					copy(m.id[:], payload[4:4+sockidLen])
					*matches = append(*matches, m)
				}
			}
		}
		advance := (length + 3) &^ 3
		if advance > len(buf) {
			advance = len(buf)
		}
		buf = buf[advance:]
	}
	return false, nil
}

// parseDiagAck reads one destroy-phase reply: NLMSG_ERROR with a
// negative errno is a real failure; anything else (ACK, DONE) is
// success — the kernel may also answer DONE for an id that no
// longer exists, which is the desired idempotent outcome.
func parseDiagAck(buf []byte) error {
	for len(buf) >= 16 {
		length := int(binary.LittleEndian.Uint32(buf[0:4]))
		mtype := binary.LittleEndian.Uint16(buf[4:6])
		if length < 16 || length > len(buf) {
			return fmt.Errorf("sock_diag: bad nlmsg len %d", length)
		}
		if mtype == nlmsgError && length >= 20 {
			errno := int32(binary.LittleEndian.Uint32(buf[16:20]))
			if errno < 0 {
				return fmt.Errorf("sock_diag destroy: %w", unix.Errno(-errno))
			}
		}
		advance := (length + 3) &^ 3
		if advance > len(buf) {
			advance = len(buf)
		}
		buf = buf[advance:]
	}
	return nil
}
