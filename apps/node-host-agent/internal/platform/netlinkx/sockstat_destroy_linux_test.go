//go:build linux

// sockstat_destroy_linux_test.go — binary wire-format pins for the
// SOCK_DESTROY kill path. The nlmsghdr/inet_diag_req_v2 fields and
// the inet_diag_sockid offsets carry no compiler-checked contract:
// a byte at the wrong offset reads as ENOENT (no dump flag), zero
// matches (sport read off the dport slot) or a silent no-kill
// (destroy sent on the wrong message type). The fixtures
// hand-assemble the kernel layouts from include/uapi/linux/
// {netlink,inet_diag}.h and assert the exact bytes.
package netlinkx

import (
	"bytes"
	"encoding/binary"
	"testing"

	"golang.org/x/sys/unix"
)

func TestDumpRequestWireFormat(t *testing.T) {
	req := diagRequest(7, unix.AF_INET6, 1<<tcpStateListen, nil,
		unix.SOCK_DIAG_BY_FAMILY, unix.NLM_F_REQUEST|unix.NLM_F_DUMP)

	if got := binary.LittleEndian.Uint32(req[0:4]); got != uint32(16+diagReqV2) {
		t.Fatalf("nlmsg_len=%d want %d", got, 16+diagReqV2)
	}
	if got := binary.LittleEndian.Uint16(req[4:6]); got != unix.SOCK_DIAG_BY_FAMILY {
		t.Fatalf("dump type=%d want SOCK_DIAG_BY_FAMILY(%d)", got, unix.SOCK_DIAG_BY_FAMILY)
	}
	// The NLM_F_DUMP flag is the whole dump: without it the kernel
	// reads the all-zero idiag_sockid as a single-socket lookup and
	// answers ENOENT.
	if got := binary.LittleEndian.Uint16(req[6:8]); got != unix.NLM_F_REQUEST|unix.NLM_F_DUMP {
		t.Fatalf("dump flags=%#x want REQUEST|DUMP", got)
	}
	if got := binary.LittleEndian.Uint32(req[8:12]); got != 7 {
		t.Fatalf("nlmsg_seq=%d want 7", got)
	}
	if req[16] != unix.AF_INET6 {
		t.Fatalf("sdiag_family=%d want AF_INET6", req[16])
	}
	if req[17] != unix.IPPROTO_TCP {
		t.Fatalf("sdiag_protocol=%d want IPPROTO_TCP(%d)", req[17], unix.IPPROTO_TCP)
	}
	// Kernel-side state filter: LISTEN only, not the 0xFFF
	// all-states mask.
	if got := binary.LittleEndian.Uint32(req[20:24]); got != 1<<tcpStateListen {
		t.Fatalf("idiag_states=%#x want 1<<TCP_LISTEN(%#x)", got, 1<<tcpStateListen)
	}
	// A dump carries no idiag_sockid — the 48-byte field stays zero.
	if !bytes.Equal(req[24:24+sockidLen], make([]byte, sockidLen)) {
		t.Fatal("idiag_sockid must be zeroed on a dump request")
	}
}

func TestDestroyRequestCarriesSockDestroy(t *testing.T) {
	var id [sockidLen]byte
	for i := range id {
		id[i] = byte(i)
	}
	req := diagRequest(101, unix.AF_INET, 0xFFF, &id,
		unix.SOCK_DESTROY, unix.NLM_F_REQUEST|unix.NLM_F_ACK)

	// SOCK_DESTROY (21), not SOCK_DIAG_BY_FAMILY (20): the destroy
	// operation lives on its own netlink message type — a type-20
	// request without NLM_F_DUMP is a lookup, never a kill.
	if got := binary.LittleEndian.Uint16(req[4:6]); got != unix.SOCK_DESTROY {
		t.Fatalf("destroy type=%d want SOCK_DESTROY(%d)", got, unix.SOCK_DESTROY)
	}
	if got := binary.LittleEndian.Uint16(req[6:8]); got != unix.NLM_F_REQUEST|unix.NLM_F_ACK {
		t.Fatalf("destroy flags=%#x want REQUEST|ACK", got)
	}
	if req[16] != unix.AF_INET {
		t.Fatalf("sdiag_family=%d want AF_INET", req[16])
	}
	if req[17] != unix.IPPROTO_TCP {
		t.Fatalf("sdiag_protocol=%d want IPPROTO_TCP(%d)", req[17], unix.IPPROTO_TCP)
	}
	if got := binary.LittleEndian.Uint32(req[20:24]); got != 0xFFF {
		t.Fatalf("idiag_states=%#x want 0xFFF (the sockid identifies the socket)", got)
	}
	if !bytes.Equal(req[24:24+sockidLen], id[:]) {
		t.Fatal("destroy request must carry the dumped sockid verbatim")
	}
}

// inetDiagMsg hand-assembles one inet_diag_msg reply (nlmsghdr +
// 72-byte body) for a socket in the given state — the exact layout
// collectPortListeners must parse: family@16, state@17,
// idiag_sockid@20 (sport big-endian at +0, dport at +2).
func inetDiagMsg(family uint8, state uint8, sport, dport uint16) []byte {
	msg := make([]byte, 16+diagMsg)
	binary.LittleEndian.PutUint32(msg[0:], uint32(len(msg)))
	binary.LittleEndian.PutUint16(msg[4:], unix.SOCK_DIAG_BY_FAMILY) // reply type
	msg[16] = family
	msg[17] = state
	sockid := msg[16+4:] // idiag_sockid
	binary.BigEndian.PutUint16(sockid[0:2], sport)
	binary.BigEndian.PutUint16(sockid[2:4], dport)
	return msg
}

func TestCollectPortListenersReadsSport(t *testing.T) {
	const port = 32001
	var matches []sockMatch

	// A real listener bound to port: sport=port, dport=0.
	done, err := collectPortListeners(
		inetDiagMsg(unix.AF_INET, tcpStateListen, port, 0),
		unix.AF_INET, port, &matches)
	if err != nil {
		t.Fatalf("collectPortListeners: %v", err)
	}
	if done {
		t.Fatal("a single-message batch must not report DONE")
	}
	if len(matches) != 1 {
		t.Fatalf("matches=%d want 1 — the port filter must read "+
			"idiag_sport (sockid+0), not idiag_dport (sockid+2, "+
			"always 0 for listeners)", len(matches))
	}
	if matches[0].family != unix.AF_INET {
		t.Fatalf("family=%d want AF_INET", matches[0].family)
	}

	// The dumped sockid must be copied verbatim for the destroy
	// request to identify the same socket.
	want := inetDiagMsg(unix.AF_INET, tcpStateListen, port, 0)[16+4 : 16+4+sockidLen]
	if !bytes.Equal(matches[0].id[:], want) {
		t.Fatal("sockid not copied verbatim from the dump reply")
	}

	// The historical bug: a socket whose DPORT slot carries the
	// target (sport=0) must NOT match.
	matches = nil
	done, err = collectPortListeners(
		inetDiagMsg(unix.AF_INET, tcpStateListen, 0, port),
		unix.AF_INET, port, &matches)
	if err != nil || done || len(matches) != 0 {
		t.Fatalf("dport-only socket matched: done=%v err=%v matches=%d",
			done, err, len(matches))
	}

	// Non-LISTEN states and other ports don't match either.
	for _, tc := range []struct {
		name         string
		state        uint8
		sport        uint16
		wantMatching bool
	}{
		{"established on port", 1 /* TCP_ESTABLISHED */, port, false},
		{"listen other port", tcpStateListen, port + 1, false},
	} {
		matches = nil
		_, _ = collectPortListeners(
			inetDiagMsg(unix.AF_INET, tc.state, tc.sport, 0),
			unix.AF_INET, port, &matches)
		if got := len(matches); (got == 1) != tc.wantMatching {
			t.Fatalf("%s: matches=%d wantMatching=%v", tc.name, got, tc.wantMatching)
		}
	}
}

func TestCollectPortListenersDoneAndError(t *testing.T) {
	// NLMSG_DONE ends the batch — the recv loop breaks on it.
	done := make([]byte, 16)
	binary.LittleEndian.PutUint32(done[0:], 16)
	binary.LittleEndian.PutUint16(done[4:], nlmsgDone)

	listener := inetDiagMsg(unix.AF_INET6, tcpStateListen, 9115, 0)
	var matches []sockMatch
	got, err := collectPortListeners(append(listener, done...),
		unix.AF_INET6, 9115, &matches)
	if err != nil {
		t.Fatalf("collectPortListeners: %v", err)
	}
	if !got || len(matches) != 1 {
		t.Fatalf("done=%v matches=%d want true/1", got, len(matches))
	}

	// NLMSG_ERROR with a negative errno surfaces the kernel error.
	nlerr := make([]byte, 20)
	binary.LittleEndian.PutUint32(nlerr[0:], 20)
	binary.LittleEndian.PutUint16(nlerr[4:], nlmsgError)
	errno := -int32(unix.ENOENT)
	binary.LittleEndian.PutUint32(nlerr[16:], uint32(errno))
	matches = nil
	if _, err := collectPortListeners(nlerr, unix.AF_INET, 9115, &matches); err == nil {
		t.Fatal("NLMSG_ERROR with negative errno must surface as an error")
	}

	// A zero/positive errno is an ACK: end silently, no error.
	binary.LittleEndian.PutUint32(nlerr[16:], 0)
	if got, err := collectPortListeners(nlerr, unix.AF_INET, 9115, &matches); err != nil || !got {
		t.Fatalf("ACK batch: done=%v err=%v want true/nil", got, err)
	}
}

func TestParseDiagAck(t *testing.T) {
	// Empty / trailing short bytes return nil.
	if err := parseDiagAck(nil); err != nil {
		t.Fatalf("parseDiagAck(nil) = %v, want nil", err)
	}

	// ACK (NLMSG_ERROR with errno=0) succeeds.
	ack := make([]byte, 20)
	binary.LittleEndian.PutUint32(ack[0:], 20)
	binary.LittleEndian.PutUint16(ack[4:], nlmsgError)
	if err := parseDiagAck(ack); err != nil {
		t.Fatalf("parseDiagAck(ACK) = %v, want nil", err)
	}

	// NLMSG_DONE followed by ACK succeeds.
	done := make([]byte, 16)
	binary.LittleEndian.PutUint32(done[0:], 16)
	binary.LittleEndian.PutUint16(done[4:], unix.NLMSG_DONE)
	if err := parseDiagAck(append(done, ack...)); err != nil {
		t.Fatalf("parseDiagAck(DONE+ACK) = %v, want nil", err)
	}

	// Negative errno surfaces as an error.
	nack := make([]byte, 20)
	binary.LittleEndian.PutUint32(nack[0:], 20)
	binary.LittleEndian.PutUint16(nack[4:], nlmsgError)
	errno := -int32(unix.EPERM)
	binary.LittleEndian.PutUint32(nack[16:], uint32(errno))
	if err := parseDiagAck(nack); err == nil {
		t.Fatal("parseDiagAck(negative errno) = nil, want error")
	}

	// Bad nlmsg length (<16 or >len(buf)) returns error.
	bad := make([]byte, 16)
	binary.LittleEndian.PutUint32(bad[0:], 8)
	if err := parseDiagAck(bad); err == nil {
		t.Fatal("parseDiagAck(len=8) = nil, want error")
	}
	binary.LittleEndian.PutUint32(bad[0:], 32)
	if err := parseDiagAck(bad); err == nil {
		t.Fatal("parseDiagAck(len>buf) = nil, want error")
	}
}
