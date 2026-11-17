//go:build linux

package netlinkx

import (
	"bytes"
	"encoding/binary"
	"net"
	"testing"

	"golang.org/x/sys/unix"
)

func buildFakeDiagReply(seq uint32, family, state uint8, sport, dport uint16, src, dst []byte) []byte {
	msgLen := 16 + diagMsg
	buf := make([]byte, msgLen+16) // data msg + NLMSG_DONE
	// First message: SOCK_DIAG_BY_FAMILY reply.
	binary.LittleEndian.PutUint32(buf[0:4], uint32(msgLen))
	binary.LittleEndian.PutUint16(buf[4:6], unix.SOCK_DIAG_BY_FAMILY)
	binary.LittleEndian.PutUint32(buf[8:12], seq)

	payload := buf[16:msgLen]
	payload[0] = family
	payload[1] = state
	binary.BigEndian.PutUint16(payload[4:6], sport)
	binary.BigEndian.PutUint16(payload[6:8], dport)
	copy(payload[8:], src)
	copy(payload[24:], dst)

	// Second message: NLMSG_DONE.
	done := buf[msgLen:]
	binary.LittleEndian.PutUint32(done[0:4], 16)
	binary.LittleEndian.PutUint16(done[4:6], nlmsgDone)
	binary.LittleEndian.PutUint32(done[8:12], seq)
	return buf
}

func TestParseConnectedUDPWireFormat(t *testing.T) {
	src4 := net.ParseIP("10.244.1.5").To4()
	dst4 := net.ParseIP("10.244.2.99").To4()
	msgV4 := buildFakeDiagReply(201, unix.AF_INET, tcpStateEstablished, 43210, 53, src4, dst4)
	// Unconnected UDP (dport == 0) must be skipped.
	unconn := buildFakeDiagReply(201, unix.AF_INET, tcpStateEstablished, 53, 0, src4, dst4)
	combined := append(unconn[:len(unconn)-16], msgV4...)

	var out []ConnectedUDPSocket
	done, err := parseConnectedUDP(combined, unix.AF_INET, &out)
	if err != nil {
		t.Fatalf("parseConnectedUDP v4 err=%v", err)
	}
	if !done {
		t.Fatal("done=false want true")
	}
	if len(out) != 1 {
		t.Fatalf("got %d sockets, want 1", len(out))
	}
	if out[0].Family != unix.AF_INET || out[0].SrcPort != 43210 || out[0].DstPort != 53 ||
		!out[0].SrcIP.Equal(src4) || !out[0].DstIP.Equal(dst4) {
		t.Fatalf("unexpected v4 socket: %+v", out[0])
	}

	// Verify destroy request wire bytes carry IPPROTO_UDP, SOCK_DESTROY, and verbatim sockid.
	var sid [sockidLen]byte
	copy(sid[:], out[0].ID[:])
	req := diagRequestProto(1, out[0].Family, unix.IPPROTO_UDP, 1<<tcpStateEstablished, &sid,
		unix.SOCK_DESTROY, unix.NLM_F_REQUEST|unix.NLM_F_ACK)
	if binary.LittleEndian.Uint16(req[4:6]) != unix.SOCK_DESTROY || req[17] != unix.IPPROTO_UDP {
		t.Fatalf("bad destroy wire header: type=%d proto=%d", binary.LittleEndian.Uint16(req[4:6]), req[17])
	}
	if !bytes.Equal(req[24:24+sockidLen], out[0].ID[:]) {
		t.Fatal("destroy wire payload did not preserve verbatim idiag_sockid")
	}

	// IPv6 check.
	src6 := net.ParseIP("fd00::1").To16()
	dst6 := net.ParseIP("fd00::2").To16()
	msgV6 := buildFakeDiagReply(202, unix.AF_INET6, tcpStateEstablished, 51234, 8080, src6, dst6)
	var out6 []ConnectedUDPSocket
	if _, err := parseConnectedUDP(msgV6, unix.AF_INET6, &out6); err != nil {
		t.Fatalf("parseConnectedUDP v6 err=%v", err)
	}
	if len(out6) != 1 || !out6[0].DstIP.Equal(dst6) || out6[0].DstPort != 8080 {
		t.Fatalf("unexpected v6 socket: %+v", out6)
	}
}
