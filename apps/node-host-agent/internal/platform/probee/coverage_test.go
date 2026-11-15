package probee

import (
	"context"
	"net"
	"testing"
	"time"
)

func TestListResourceVersion(t *testing.T) {
	if rv, ok := ListResourceVersion([]byte(`{"metadata":{"resourceVersion":"12345"}}`)); !ok || rv != 12345 {
		t.Fatalf("valid RV = (%d,%v), want (12345,true)", rv, ok)
	}
	if _, ok := ListResourceVersion([]byte(`not-json`)); ok {
		t.Fatal("invalid JSON should return false")
	}
	if _, ok := ListResourceVersion([]byte(`{"metadata":{"resourceVersion":"abc"}}`)); ok {
		t.Fatal("non-numeric RV should return false")
	}
	if _, ok := ListResourceVersion([]byte(`{}`)); ok {
		t.Fatal("missing RV should return false")
	}
}

func TestPGWireProbe(t *testing.T) {
	msg := PGStartupMessage("postgres", "postgres")
	if len(msg) < 8 || msg[4] != 0 || msg[5] != 3 {
		t.Fatalf("unexpected PGStartupMessage: %x", msg)
	}

	for _, b := range []byte{'R', 'S', 'N', 'K'} {
		if !PGFirstByteOK(b) {
			t.Fatalf("PGFirstByteOK(%q) = false, want true", b)
		}
	}
	if PGFirstByteOK('E') {
		t.Fatal("PGFirstByteOK('E') = true, want false")
	}

	// Start a local TCP listener that responds 'R' (healthy) then 'E' (error).
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()

	replies := make(chan byte, 2)
	replies <- 'R'
	replies <- 'E'
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			buf := make([]byte, 256)
			_, _ = c.Read(buf)
			select {
			case b := <-replies:
				_, _ = c.Write([]byte{b})
			default:
			}
			_ = c.Close()
		}
	}()

	if !PGWireProbe(context.Background(), ln.Addr().String()) {
		t.Fatal("expected PGWireProbe('R') to return true")
	}
	if PGWireProbeWithTimeout(context.Background(), ln.Addr().String(), time.Second) {
		t.Fatal("expected PGWireProbeWithTimeout('E') to return false")
	}
	// Closed/unreachable port returns false.
	if PGWireProbeWithTimeout(context.Background(), "127.0.0.1:1", 50*time.Millisecond) {
		t.Fatal("expected closed port probe to return false")
	}
}
