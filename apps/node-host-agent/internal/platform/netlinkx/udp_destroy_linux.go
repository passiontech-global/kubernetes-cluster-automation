//go:build linux

// udp_destroy_linux.go — Wave-3 #3: pure-Go NETLINK_SOCK_DIAG dump +
// SOCK_DESTROY for connected UDP sockets (IPPROTO_UDP, idiag_dport != 0).
package netlinkx

import (
	"encoding/binary"
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
// netns. ENOENT is treated as idempotent success.
func DestroyUDPSocket(pid int, family uint8, id [48]byte) error {
	return InNetNS(pid, func() error {
		return destroyUDPSocketInNS(family, id)
	})
}

func destroyUDPSocketInNS(family uint8, id [48]byte) error {
	fd, err := diagSock()
	if err != nil {
		return err
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
		return fmt.Errorf("udp sock_diag destroy send: %w", err)
	}
	return diagRecvLoop(fd, buf, "udp sock_diag destroy recv", func(b []byte) (bool, error) {
		return true, parseDiagAck(b)
	})
}
