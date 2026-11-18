//go:build linux

// udp_destroy_linux.go — Wave-3 #3: pure-Go NETLINK_SOCK_DIAG dump +
// SOCK_DESTROY for connected UDP sockets (IPPROTO_UDP, idiag_dport != 0).
package netlinkx

import (
	"encoding/binary"
	"errors"
	"fmt"
	"net"

	"golang.org/x/sys/unix"
)

const tcpStateEstablished = 1

// DumpConnectedUDP dumps every connected UDP socket (TCP_ESTABLISHED state
// with idiag_dport != 0) inside pid's network namespace.
func DumpConnectedUDP(pid int) ([]ConnectedUDPSocket, error) {
	var out []ConnectedUDPSocket
	err := InNetNS(pid, func() error {
		var derr error
		out, derr = dumpConnectedUDPInNS()
		return derr
	})
	return out, err
}

func dumpConnectedUDPInNS() ([]ConnectedUDPSocket, error) {
	fd, err := diagSock()
	if err != nil {
		return nil, err
	}
	defer func() { _ = unix.Close(fd) }()
	sa := &unix.SockaddrNetlink{Family: unix.AF_NETLINK}

	bufp := diagBufPool.Get().(*[]byte)
	defer diagBufPool.Put(bufp)
	buf := *bufp

	var out []ConnectedUDPSocket
	seq := uint32(200)
	for _, family := range []uint8{unix.AF_INET, unix.AF_INET6} {
		seq++
		req := diagRequestProto(seq, family, unix.IPPROTO_UDP,
			1<<tcpStateEstablished, nil,
			unix.SOCK_DIAG_BY_FAMILY, unix.NLM_F_REQUEST|unix.NLM_F_DUMP)
		if err := unix.Sendto(fd, req, 0, sa); err != nil {
			return nil, fmt.Errorf("udp sock_diag send %d: %w", family, err)
		}
		if err := diagRecvLoop(fd, buf,
			fmt.Sprintf("udp sock_diag recv %d", family),
			func(b []byte) (bool, error) {
				return parseConnectedUDP(b, family, &out)
			}); err != nil {
			if family == unix.AF_INET6 && noInet6Family(err) {
				continue
			}
			return nil, err
		}
	}
	return out, nil
}

// UDPBoundPorts returns the UDP ports with a socket bound in pid's
// netns — the `ss -lun` UNCONN rows (UDP has no LISTEN state, so every
// UDP socket with sport != 0 counts). This is the "is this port a
// local server" evidence the stale-socket check needs: a connected
// UDP socket whose SrcPort is bound here is a server replying to a
// client, never a blackhole to a dead Service backend.
func UDPBoundPorts(pid int) (map[uint16]bool, error) {
	out := map[uint16]bool{}
	err := InNetNS(pid, func() error { return udpBoundPortsDump(out) })
	return out, err
}

func udpBoundPortsDump(out map[uint16]bool) error {
	fd, err := diagSock()
	if err != nil {
		return err
	}
	defer func() { _ = unix.Close(fd) }()
	sa := &unix.SockaddrNetlink{Family: unix.AF_NETLINK}

	bufp := diagBufPool.Get().(*[]byte)
	defer diagBufPool.Put(bufp)
	buf := *bufp

	seq := uint32(300)
	for _, family := range []uint8{unix.AF_INET, unix.AF_INET6} {
		seq++
		req := diagRequestProto(seq, family, unix.IPPROTO_UDP,
			0xFFF, nil, unix.SOCK_DIAG_BY_FAMILY,
			unix.NLM_F_REQUEST|unix.NLM_F_DUMP)
		if err := unix.Sendto(fd, req, 0, sa); err != nil {
			return fmt.Errorf("udp bound-port sock_diag send %d: %w", family, err)
		}
		if err := diagRecvLoop(fd, buf,
			fmt.Sprintf("udp bound-port sock_diag recv %d", family),
			func(b []byte) (bool, error) {
				return parseUDPBoundPorts(b, family, out)
			}); err != nil {
			if family == unix.AF_INET6 && noInet6Family(err) {
				continue // kernel has no IPv6 — not an error
			}
			return err
		}
	}
	return nil
}

func parseUDPBoundPorts(buf []byte, family uint8, out map[uint16]bool) (bool, error) {
	_, done, err := walkNLMsgs(buf, false, func(payload []byte) {
		if len(payload) < diagMsg || payload[0] != family {
			return
		}
		// inet_diag_msg's sockid starts at payload+4; idiag_sport
		// is its first 2 bytes, big-endian. sport==0 is unbound.
		if sport := binary.BigEndian.Uint16(payload[4:6]); sport != 0 {
			out[sport] = true
		}
	})
	return done, err
}

func parseConnectedUDP(buf []byte, family uint8, out *[]ConnectedUDPSocket) (bool, error) {
	_, done, err := walkNLMsgs(buf, false, func(payload []byte) {
		if len(payload) < diagMsg {
			return
		}
		if payload[0] != family || payload[1] != tcpStateEstablished {
			return
		}
		sport := binary.BigEndian.Uint16(payload[4:6])
		dport := binary.BigEndian.Uint16(payload[6:8])
		if dport == 0 {
			return
		}
		var sock ConnectedUDPSocket
		sock.Family = family
		sock.SrcPort = sport
		sock.DstPort = dport
		copy(sock.ID[:], payload[4:4+sockidLen])
		switch family {
		case unix.AF_INET:
			sock.SrcIP = net.IP(append([]byte(nil), payload[8:12]...))
			sock.DstIP = net.IP(append([]byte(nil), payload[24:28]...))
		case unix.AF_INET6:
			sock.SrcIP = net.IP(append([]byte(nil), payload[8:24]...))
			sock.DstIP = net.IP(append([]byte(nil), payload[24:40]...))
		default:
			return
		}
		*out = append(*out, sock)
	})
	return done, err
}

// DestroyUDPSocket sends NETLINK_SOCK_DIAG SOCK_DESTROY for one connected
// UDP socket identified by family + verbatim idiag_sockid inside pid's
// netns. destroyed reports whether the kernel actually accepted the
// kill: ENOENT (the socket vanished between dump and destroy) is
// idempotent success with destroyed=false — the caller must NOT count
// that as a real SOCK_DESTROY (Wave-5 P0).
func DestroyUDPSocket(pid int, family uint8, id [48]byte) (bool, error) {
	var destroyed bool
	err := InNetNS(pid, func() error {
		var derr error
		destroyed, derr = destroyUDPSocketInNS(family, id)
		return derr
	})
	return destroyed, err
}

func destroyUDPSocketInNS(family uint8, id [48]byte) (bool, error) {
	fd, err := diagSock()
	if err != nil {
		return false, err
	}
	defer func() { _ = unix.Close(fd) }()
	sa := &unix.SockaddrNetlink{Family: unix.AF_NETLINK}

	bufp := diagBufPool.Get().(*[]byte)
	defer diagBufPool.Put(bufp)
	buf := *bufp

	var sid [sockidLen]byte
	copy(sid[:], id[:])
	req := diagRequestProto(1, family, unix.IPPROTO_UDP,
		1<<tcpStateEstablished, &sid,
		unix.SOCK_DESTROY, unix.NLM_F_REQUEST|unix.NLM_F_ACK)
	if err := unix.Sendto(fd, req, 0, sa); err != nil {
		return false, fmt.Errorf("udp sock_diag destroy send: %w", err)
	}
	// Use walkNLMsgs' done flag directly instead of parseDiagAck's
	// "ENOENT == success" fold: a positive ACK / NLMSG_DONE means the
	// kernel destroyed the socket and set done=true; ENOENT means the
	// id was already gone (idempotent, but NOT a kill we performed).
	var destroyed bool
	if err := diagRecvLoop(fd, buf, "udp sock_diag destroy recv", func(b []byte) (bool, error) {
		_, done, err := walkNLMsgs(b, true, nil)
		if err != nil {
			if errors.Is(err, unix.ENOENT) {
				return true, nil // already gone — no real destroy
			}
			return true, err
		}
		destroyed = done
		return true, nil
	}); err != nil {
		return false, err
	}
	return destroyed, nil
}
