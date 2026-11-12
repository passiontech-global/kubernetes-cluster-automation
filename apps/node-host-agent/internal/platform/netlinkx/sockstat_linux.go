//go:build linux

// sockstat_linux.go — the cheap aggregate reader and the
// NETLINK_SOCK_DIAG state histogram. /proc/<pid>/net/sockstat{,6}
// answers "how many sockets, how many TIME_WAIT" without a single
// syscall; TCPStates is the full per-state histogram `ss -tan`
// state counts come from, for pid's netns (InNetNS setns scope).
package netlinkx

import (
	"encoding/binary"
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
		advance := (length + 3) &^ 3
		if advance >= len(buf) {
			break // aligned length can round past the batch end
		}
		buf = buf[advance:]
	}
	return false, nil
}
