package routewatch

import (
	"encoding/binary"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"golang.org/x/sys/unix"

	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-host-agent/internal/testutil"
)

// --- netlink message decoding ---

// nlmsgBody serializes a full nlmsg: header + payload (nlmsg_len
// covers exactly both — no trailing pad, like the kernel's last
// message in a datagram).
func nlmsgBody(typ uint16, payload []byte) []byte {
	b := make([]byte, unix.NLMSG_HDRLEN+len(payload))
	binary.NativeEndian.PutUint32(b[0:4], uint32(len(b)))
	binary.NativeEndian.PutUint16(b[4:6], typ)
	copy(b[unix.NLMSG_HDRLEN:], payload)
	return b
}

// rtattrU32 serializes one u32-valued rtattr (rta_len 8).
func rtattrU32(typ uint16, v uint32) []byte {
	b := make([]byte, unix.SizeofRtAttr+4)
	binary.NativeEndian.PutUint16(b[0:2], uint16(len(b)))
	binary.NativeEndian.PutUint16(b[2:4], typ)
	binary.NativeEndian.PutUint32(b[4:8], v)
	return b
}

// ScanMessages walks the datagram, hands each type+payload to the
// callback and fails open on anything too torn to classify.
func TestScanMessages(t *testing.T) {
	// The callback sees every decoded message in order, with the
	// payload slice it was sent.
	var seen []uint16
	interesting := func(typ uint16, payload []byte) bool {
		seen = append(seen, typ)
		return typ == 42
	}
	for name, tc := range map[string]struct {
		buf       []byte
		want      bool
		wantTypes int // -1 = callback never invoked (torn head)
	}{
		"empty":            {nil, false, 0},
		"single match":     {nlmsgBody(42, nil), true, 1},
		"single nonmatch":  {nlmsgBody(1, nil), false, 1},
		"burst with match": {append(nlmsgBody(1, nil), nlmsgBody(42, nil)...), true, 2},
		"burst all noise":  {append(nlmsgBody(1, nil), nlmsgBody(2, nil)...), false, 2},
		// Fail-open: a torn header or an impossible nlmsg_len can't
		// be proven irrelevant, so it counts — without asking.
		"torn header":        {[]byte{1, 2, 3}, true, -1},
		"truncated datagram": {nlmsgBody(1, nil)[:8], true, -1},
		"bad nlmsg length": {
			append([]byte{0xff, 0xff, 0xff, 0xff},
				nlmsgBody(1, nil)[4:]...), true, -1},
		"undersize nlmsg": {
			[]byte{8, 0, 0, 0, 0x19, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0},
			true, -1},
	} {
		seen = nil
		if got := ScanMessages(tc.buf, interesting); got != tc.want {
			t.Fatalf("%s: ScanMessages=%v want %v", name, got, tc.want)
		}
		if tc.wantTypes >= 0 && len(seen) != tc.wantTypes {
			t.Fatalf("%s: callback saw %d messages want %d",
				name, len(seen), tc.wantTypes)
		}
	}
}

// The callback gets the payload slice between the nlmsghdr and
// nlmsg_len — the bytes its own decoder parses.
func TestScanMessagesPassesPayload(t *testing.T) {
	want := []byte{0xaa, 0xbb, 0xcc}
	var got []byte
	ScanMessages(nlmsgBody(7, want), func(_ uint16, payload []byte) bool {
		got = append([]byte(nil), payload...)
		return true
	})
	if string(got) != string(want) {
		t.Fatalf("payload=%v want %v", got, want)
	}
}

// Attrs extracts wanted u32s and reports torn attribute lists via
// clean=false — the undecodable case callers must fail open on.
func TestAttrs(t *testing.T) {
	got, clean := Attrs(rtattrU32(5, 9), 5)
	if !clean || got[5] != 9 {
		t.Fatalf("attrs=%v clean=%v want {5:9} clean", got, clean)
	}
	// Unwanted attributes are skipped, not collected.
	got, clean = Attrs(append(rtattrU32(7, 1), rtattrU32(5, 9)...), 5)
	if !clean || len(got) != 1 || got[5] != 9 {
		t.Fatalf("attrs=%v clean=%v want {5:9} clean", got, clean)
	}
	// tornAttr claims rta_len 32 but only 6 bytes follow.
	torn := []byte{0x20, 0x00, 0x0f, 0x00, 0xaa, 0xbb}
	if _, clean := Attrs(torn, 5); clean {
		t.Fatal("torn attribute list reported clean")
	}
	// A <4B residue can't hold an attribute → undecodable.
	if _, clean := Attrs(append(rtattrU32(5, 9), 0x01), 5); clean {
		t.Fatal("sub-header residue reported clean")
	}
	// An attribute whose rta_len is short but whose ALIGNMENT
	// padding overruns the buffer is a clean end — the kernel
	// need not pad the final attribute.
	if _, clean := Attrs(rtattrU32(5, 9)[:6], 5); clean {
		t.Fatal("short rta_len reported clean")
	}
}

// --- host-netns bind selection ---

func TestSameNetnsSelfIsSelf(t *testing.T) {
	if !SameNetns(threadSelfNetns(), threadSelfNetns()) {
		t.Fatal("the thread's own ns/net link does not SameFile itself")
	}
}

// The thread-self resolver prefers /proc/thread-self (kernel ≥3.17)
// and falls back to /proc/self/task/<tid> — either way the resolved
// link must exist and name the calling thread's netns.
func TestThreadSelfNetnsResolves(t *testing.T) {
	p := threadSelfNetns()
	if _, err := os.Stat(p); err != nil {
		t.Fatalf("resolved self netns %s unreadable: %v", p, err)
	}
	if p != "/proc/thread-self/ns/net" &&
		!strings.HasPrefix(p, "/proc/self/task/") {
		t.Fatalf("unexpected self netns path %s", p)
	}
}

// hostNetwork deployment (the DaemonSet case): pod netns IS the host
// netns → direct bind, hostRoot never consulted. Skips when the test
// env runs pid 1 in a different netns (unusual containers).
func TestBindDirectBindWhenHostNet(t *testing.T) {
	if !SameNetns(threadSelfNetns(), InitNetns) {
		t.Skip("test env: pid 1 lives in a different netns")
	}
	// A bogus hostRoot proves the mounted-/proc path isn't touched —
	// on the DS <hostRoot>/proc doesn't exist at all.
	fd, err := Bind(filepath.Join(t.TempDir(), "no-such-root"))
	if err != nil {
		t.Fatalf("direct bind failed: %v", err)
	}
	if fd < 0 {
		t.Fatalf("fd=%d", fd)
	}
	defer func() { _ = unix.Close(fd) }()
	sa, err := unix.Getsockname(fd)
	if err != nil {
		t.Fatalf("Getsockname: %v", err)
	}
	if _, ok := sa.(*unix.SockaddrNetlink); !ok {
		t.Fatalf("bound fd is not netlink: %T", sa)
	}
}

// hostPID deployment without hostNetwork: setns into /proc/1/ns/net;
// a mounted host /proc under hostRoot is only the last fallback.
// A regular file stands in for the ns magic link — setns() on it
// fails deterministically (EINVAL, no privilege needed).
func TestBindSetnsAndHostRootFallback(t *testing.T) {
	old := InitNetns
	defer func() { InitNetns = old }()
	init := filepath.Join(t.TempDir(), "net")
	testutil.WriteFile(t, init, "")
	InitNetns = init

	// No mounted host /proc → the setns error propagates.
	if fd, err := Bind("/"); err == nil ||
		!strings.Contains(err.Error(), "setns") {
		if fd >= 0 {
			_ = unix.Close(fd)
		}
		t.Fatalf("want setns failure, got fd=%d err=%v", fd, err)
	}

	// Mounted host /proc under hostRoot → attempted as last resort.
	root := t.TempDir()
	fake := filepath.Join(root, "proc/1/ns/net")
	testutil.WriteFile(t, fake, "")
	fd, err := Bind(root)
	if fd >= 0 {
		_ = unix.Close(fd)
	}
	if err == nil || !strings.Contains(err.Error(), fake) {
		t.Fatalf("host-root fallback not attempted: %v", err)
	}
}
