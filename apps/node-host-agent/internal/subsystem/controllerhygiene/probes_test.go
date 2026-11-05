// probes_test.go — pgWireOK postgres wire probe.

package controllerhygiene

import (
	"context"
	"net"
	"testing"
)

func TestPGWire(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Skip("no loopback")
	}
	defer func() { _ = ln.Close() }()
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go func(c net.Conn) {
				defer func() { _ = c.Close() }()
				buf := make([]byte, 64)
				_, _ = c.Read(buf)
				_, _ = c.Write([]byte("R")) // auth request = healthy
			}(c)
		}
	}()
	if !pgWireOK(context.Background(), ln.Addr().String()) {
		t.Fatal("pgWireOK rejected an R response")
	}
	ln2, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Skip("no loopback")
	}
	defer func() { _ = ln2.Close() }()
	go func() {
		for {
			c, err := ln2.Accept()
			if err != nil {
				return
			}
			go func(c net.Conn) {
				defer func() { _ = c.Close() }()
				buf := make([]byte, 64)
				_, _ = c.Read(buf)
				_, _ = c.Write([]byte("E")) // ErrorResponse = broken
			}(c)
		}
	}()
	if pgWireOK(context.Background(), ln2.Addr().String()) {
		t.Fatal("pgWireOK accepted an E response")
	}
}
