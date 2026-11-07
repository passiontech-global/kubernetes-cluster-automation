// sdnotify_test.go — the shared unixgram sender: '@'-abstract name
// translation and the SendOnce one-shot wire format.
package sdnotify

import (
	"net"
	"path/filepath"
	"testing"
	"time"
)

// notifySink binds a unixgram listener pretending to be PID 1's
// notify socket and returns its path plus a channel of received
// datagrams.
func notifySink(t *testing.T) (string, <-chan string) {
	t.Helper()
	path := filepath.Join(t.TempDir(), "notify.sock")
	conn, err := net.ListenUnixgram("unixgram",
		&net.UnixAddr{Name: path, Net: "unixgram"})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = conn.Close() })
	msgs := make(chan string, 4)
	go func() {
		buf := make([]byte, 4096)
		for {
			_ = conn.SetReadDeadline(time.Now().Add(2 * time.Second))
			n, err := conn.Read(buf)
			if err != nil {
				return
			}
			msgs <- string(buf[:n])
		}
	}()
	return path, msgs
}

func TestSendOnceDeliversDatagram(t *testing.T) {
	path, msgs := notifySink(t)
	if err := SendOnce(path, "READY=1\n"); err != nil {
		t.Fatalf("SendOnce: %v", err)
	}
	select {
	case got := <-msgs:
		if got != "READY=1\n" {
			t.Fatalf("datagram=%q want READY=1\\n", got)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("no datagram within 3s")
	}
}

func TestDialTranslatesAbstractSocket(t *testing.T) {
	// '@name' is systemd's abstract-socket spelling — Dial must
	// hand the kernel the NUL-prefixed name, not a literal '@'
	// path. Bind a real abstract listener and drive the whole
	// '@'-spelled path: dial, send, receive.
	name := "\x00sdnotify-test-" + t.Name()
	sink, err := net.ListenUnixgram("unixgram",
		&net.UnixAddr{Name: name, Net: "unixgram"})
	if err != nil {
		t.Skipf("abstract unixgram unsupported: %v", err)
	}
	defer func() { _ = sink.Close() }()

	conn, err := Dial("@" + name[1:])
	if err != nil {
		t.Fatalf("Dial: %v", err)
	}
	defer func() { _ = conn.Close() }()
	// Go canonicalizes the NUL leader back to '@' in UnixAddr.Name —
	// the '\x00' byte is the wire form at the syscall boundary.
	if got := conn.RemoteAddr().(*net.UnixAddr).Name; got != "@"+name[1:] {
		t.Fatalf("remote addr=%q want %q", got, "@"+name[1:])
	}
	if err := Send(conn, "WATCHDOG=1\n"); err != nil {
		t.Fatalf("Send: %v", err)
	}
	_ = sink.SetReadDeadline(time.Now().Add(3 * time.Second))
	buf := make([]byte, 64)
	n, err := sink.Read(buf)
	if err != nil {
		t.Fatal(err)
	}
	if got := string(buf[:n]); got != "WATCHDOG=1\n" {
		t.Fatalf("datagram=%q want WATCHDOG=1\\n", got)
	}
}

func TestSendOnceBadPathErrors(t *testing.T) {
	if err := SendOnce(filepath.Join(t.TempDir(), "no/such/dir/n.sock"),
		"WATCHDOG=1\n"); err == nil {
		t.Fatal("SendOnce to unresolvable path succeeded")
	}
}
