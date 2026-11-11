package probee

import (
	"context"
	"errors"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"testing"
	"time"
)

func TestHTTP2xx(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/ok":
			w.WriteHeader(http.StatusOK)
		default:
			w.WriteHeader(http.StatusInternalServerError)
		}
	}))
	defer srv.Close()

	if !HTTP2xx(context.Background(), srv.URL+"/ok", 5*time.Second) {
		t.Fatal("HTTP2xx: 200 endpoint reported false")
	}
	if HTTP2xx(context.Background(), srv.URL+"/wedged", 5*time.Second) {
		t.Fatal("HTTP2xx: 500 endpoint reported true")
	}
	if HTTP2xx(context.Background(), "://bogus", 5*time.Second) {
		t.Fatal("HTTP2xx: malformed URL reported true")
	}
}

func TestHTTP2xxTLSSelfSigned(t *testing.T) {
	// KCM/scheduler parity: a self-signed cert must not fail the probe.
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	if !HTTP2xx(context.Background(), srv.URL, 5*time.Second) {
		t.Fatal("HTTP2xx: self-signed TLS endpoint reported false")
	}
}

func TestHTTPAnyCode(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer srv.Close()

	// A 500 still proves the event loop is alive — the
	// probeAnyCode contract.
	if !HTTPAnyCode(context.Background(), srv.URL, 5*time.Second) {
		t.Fatal("HTTPAnyCode: 500 endpoint reported false")
	}
	if HTTPAnyCode(context.Background(), "http://127.0.0.1:1/", 2*time.Second) {
		t.Fatal("HTTPAnyCode: unreachable endpoint reported true")
	}
}

func TestHTTPGet(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/ok" {
			w.WriteHeader(http.StatusOK)
			return
		}
		w.WriteHeader(http.StatusServiceUnavailable)
	}))
	defer srv.Close()

	if err := HTTPGet(context.Background(), srv.URL+"/ok", 5*time.Second); err != nil {
		t.Fatalf("HTTPGet: 200 endpoint errored: %v", err)
	}
	if err := HTTPGet(context.Background(), srv.URL+"/wedged", 5*time.Second); err == nil {
		t.Fatal("HTTPGet: 503 endpoint reported nil error")
	}
	if err := HTTPGet(context.Background(), "http://127.0.0.1:1/", 2*time.Second); err == nil {
		t.Fatal("HTTPGet: unreachable endpoint reported nil error")
	}
}

func TestHTTPStatus(t *testing.T) {
	var gotAuth string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotAuth = r.Header.Get("Authorization")
		w.WriteHeader(http.StatusServiceUnavailable)
	}))
	defer srv.Close()

	code, err := HTTPStatus(context.Background(), srv.URL, "", 5*time.Second)
	if err != nil || code != http.StatusServiceUnavailable {
		t.Fatalf("HTTPStatus: got code=%d err=%v, want 503/nil", code, err)
	}
	if gotAuth != "" {
		t.Fatalf("HTTPStatus: Authorization sent with empty bearer: %q", gotAuth)
	}

	code, err = HTTPStatus(context.Background(), srv.URL, "tok123", 5*time.Second)
	if err != nil || code != http.StatusServiceUnavailable {
		t.Fatalf("HTTPStatus: got code=%d err=%v, want 503/nil", code, err)
	}
	if gotAuth != "Bearer tok123" {
		t.Fatalf("HTTPStatus: Authorization = %q, want %q", gotAuth, "Bearer tok123")
	}
}

func TestHTTPBody(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/ok" {
			_, _ = w.Write([]byte("the body"))
			return
		}
		w.WriteHeader(http.StatusNotFound)
	}))
	defer srv.Close()

	b, err := HTTPBody(context.Background(), srv.URL+"/ok", 5*time.Second)
	if err != nil || string(b) != "the body" {
		t.Fatalf("HTTPBody: got %q err=%v", b, err)
	}
	if _, err := HTTPBody(context.Background(), srv.URL+"/missing", 5*time.Second); err == nil {
		t.Fatal("HTTPBody: 404 endpoint reported nil error")
	}
}

func TestHTTPBodyInsecure(t *testing.T) {
	// The KCM /metrics scrape keeps the body even on a 500 — no
	// status check — and accepts self-signed certs.
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
		_, _ = w.Write([]byte("partial metrics"))
	}))
	defer srv.Close()

	b, err := HTTPBodyInsecure(context.Background(), srv.URL, 5*time.Second)
	if err != nil || b != "partial metrics" {
		t.Fatalf("HTTPBodyInsecure: got %q err=%v, want body/nil", b, err)
	}
}

func TestBodyOK(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/ok":
			_, _ = w.Write([]byte("ok"))
		case "/padded":
			_, _ = w.Write([]byte("  ok\n"))
		case "/wedged-body":
			// A wedged service answering 500 with body "ok" still
			// reads as ok — the status code is deliberately not
			// checked (probeBodyOK parity).
			w.WriteHeader(http.StatusInternalServerError)
			_, _ = w.Write([]byte("ok"))
		default:
			_, _ = w.Write([]byte("degraded"))
		}
	}))
	defer srv.Close()

	if !BodyOK(context.Background(), srv.URL+"/ok", 5*time.Second) {
		t.Fatal("BodyOK: \"ok\" body reported false")
	}
	if !BodyOK(context.Background(), srv.URL+"/padded", 5*time.Second) {
		t.Fatal("BodyOK: padded \"ok\" body reported false")
	}
	if BodyOK(context.Background(), srv.URL+"/bad", 5*time.Second) {
		t.Fatal("BodyOK: non-ok body reported true")
	}
	if !BodyOK(context.Background(), srv.URL+"/wedged-body", 5*time.Second) {
		t.Fatal("BodyOK: 500-with-ok-body reported false (status must not gate)")
	}
	if BodyOK(context.Background(), "http://127.0.0.1:1/", 2*time.Second) {
		t.Fatal("BodyOK: unreachable endpoint reported true")
	}
}

// unixServer starts an http.Server on a unix socket under t.TempDir.
func unixServer(t *testing.T, h http.Handler) (socket string) {
	t.Helper()
	socket = filepath.Join(t.TempDir(), "test.sock")
	ln, err := net.Listen("unix", socket)
	if err != nil {
		t.Fatalf("unix listen: %v", err)
	}
	srv := &http.Server{Handler: h}
	go func() { _ = srv.Serve(ln) }()
	t.Cleanup(func() { _ = srv.Close() })
	return socket
}

func TestUnixGet(t *testing.T) {
	socket := unixServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/v1/healthz" {
			_, _ = w.Write([]byte(`{"ok":true}`))
			return
		}
		w.WriteHeader(http.StatusInternalServerError)
	}))

	b, err := UnixGet(context.Background(), socket, "/v1/healthz")
	if err != nil || string(b) != `{"ok":true}` {
		t.Fatalf("UnixGet: got %q err=%v", b, err)
	}
	if _, err := UnixGet(context.Background(), socket, "/bad"); err == nil {
		t.Fatal("UnixGet: 500 endpoint reported nil error")
	}
	if _, err := UnixGet(context.Background(),
		filepath.Join(t.TempDir(), "missing.sock"), "/x"); err == nil {
		t.Fatal("UnixGet: missing socket reported nil error")
	}
}

func TestUnixDial(t *testing.T) {
	socket := unixServer(t, http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	if err := UnixDial(context.Background(), socket, 5*time.Second); err != nil {
		t.Fatalf("UnixDial: live socket errored: %v", err)
	}
	if err := UnixDial(context.Background(),
		filepath.Join(t.TempDir(), "missing.sock"), 2*time.Second); err == nil {
		t.Fatal("UnixDial: missing socket reported nil error")
	}
}

// udpDNSFake answers UDP datagrams with a minimal well-formed DNS
// response: same id, QR bit set. qr=false echoes the datagram back
// unchanged (a response WITHOUT the QR bit — must not pass).
func udpDNSFake(t *testing.T, qr bool) (addr string) {
	t.Helper()
	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("udp listen: %v", err)
	}
	t.Cleanup(func() { _ = pc.Close() })
	go func() {
		buf := make([]byte, 512)
		for {
			n, src, err := pc.ReadFrom(buf)
			if err != nil {
				return
			}
			resp := make([]byte, n)
			copy(resp, buf[:n])
			if qr && n >= 3 {
				resp[2] |= 0x80
			}
			_, _ = pc.WriteTo(resp, src)
		}
	}()
	return pc.LocalAddr().String()
}

func TestDNSQuery(t *testing.T) {
	if !DNSQuery(udpDNSFake(t, true), "kubernetes.default.svc.cluster.local",
		2*time.Second) {
		t.Fatal("DNSQuery: responding listener reported false")
	}
	// A datagram echo without the QR bit is a query, not a response.
	if DNSQuery(udpDNSFake(t, false), "example.test", 2*time.Second) {
		t.Fatal("DNSQuery: QR-less echo reported true")
	}
	// Silence (nothing answering) must fail — the wedge verdict.
	if DNSQuery("127.0.0.1:1", "example.test", 300*time.Millisecond) {
		t.Fatal("DNSQuery: dead listener reported true")
	}
}

// tcpDNSFake is the TCP twin of udpDNSFake: it accepts connections,
// reads the 2-byte length-prefixed query and answers with the same
// frame carrying the query back — QR bit set when qr=true, echoed
// unchanged otherwise. mode steers the broken-server cases:
// "" is the healthy echo, "badlen" sends an out-of-range length
// prefix, "short" truncates the frame mid-message, "wrongid"
// rewrites the echoed id, "silent" never replies.
func tcpDNSFake(t *testing.T, qr bool, mode string) (addr string) {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("tcp listen: %v", err)
	}
	t.Cleanup(func() { _ = ln.Close() })
	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			go func(c net.Conn) {
				defer func() { _ = c.Close() }()
				_ = c.SetDeadline(time.Now().Add(10 * time.Second))
				hdr := make([]byte, 2)
				if _, err := io.ReadFull(c, hdr); err != nil {
					return
				}
				if mode == "badlen" {
					// n=4097 — one past the probe's frame cap, so the
					// length check rejects before any body read.
					_, _ = c.Write([]byte{0x10, 0x01})
					return
				}
				n := int(hdr[0])<<8 | int(hdr[1])
				q := make([]byte, n)
				if _, err := io.ReadFull(c, q); err != nil {
					return
				}
				switch mode {
				case "silent":
					return
				case "short":
					// Declared length honest, body cut short — the
					// client's ReadFull must fail.
					_, _ = c.Write([]byte{hdr[0], byte(n >> 8 & 0xff)})
					return
				case "wrongid":
					if len(q) >= 2 {
						q[0] ^= 0xff
						q[1] ^= 0xff
					}
				}
				if qr && len(q) >= 3 {
					q[2] |= 0x80
				}
				resp := []byte{byte(len(q) >> 8), byte(len(q))}
				resp = append(resp, q...)
				_, _ = c.Write(resp)
			}(conn)
		}
	}()
	return ln.Addr().String()
}

func TestDNSQueryTCP(t *testing.T) {
	name := "kubernetes.default.svc.cluster.local"
	if !DNSQueryTCP(tcpDNSFake(t, true, ""), name, 2*time.Second) {
		t.Fatal("DNSQueryTCP: responding listener reported false")
	}
	// A length-prefixed echo without the QR bit is a query, not a
	// response — same contract as the UDP probe.
	if DNSQueryTCP(tcpDNSFake(t, false, ""), name, 2*time.Second) {
		t.Fatal("DNSQueryTCP: QR-less echo reported true")
	}
	// An echoed frame with a different id is a stray datagram.
	if DNSQueryTCP(tcpDNSFake(t, true, "wrongid"), name, 2*time.Second) {
		t.Fatal("DNSQueryTCP: wrong-id reply reported true")
	}
	// An out-of-range length prefix is rejected before the body
	// read — a malformed peer must not wedge the probe.
	if DNSQueryTCP(tcpDNSFake(t, true, "badlen"), name, 2*time.Second) {
		t.Fatal("DNSQueryTCP: oversized length prefix reported true")
	}
	// A truncated frame fails the exact-length read.
	if DNSQueryTCP(tcpDNSFake(t, true, "short"), name, 2*time.Second) {
		t.Fatal("DNSQueryTCP: truncated frame reported true")
	}
	// A listener that accepts but never answers hits the deadline.
	if DNSQueryTCP(tcpDNSFake(t, true, "silent"), name, 300*time.Millisecond) {
		t.Fatal("DNSQueryTCP: silent listener reported true")
	}
	// Nothing listening at all — the wedge verdict.
	if DNSQueryTCP("127.0.0.1:1", name, 300*time.Millisecond) {
		t.Fatal("DNSQueryTCP: dead listener reported true")
	}
}

func TestProbesHonorDeadline(t *testing.T) {
	// A handler that outlives the probe timeout: the client-side
	// deadline must fire first.
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		select {
		case <-r.Context().Done():
		case <-time.After(5 * time.Second):
		}
	}))
	defer srv.Close()

	start := time.Now()
	if err := HTTPGet(context.Background(), srv.URL, 100*time.Millisecond); err == nil {
		t.Fatal("HTTPGet: hanging endpoint reported nil error")
	}
	if d := time.Since(start); d > 2*time.Second {
		t.Fatalf("HTTPGet: deadline ignored, took %v", d)
	}

	start = time.Now()
	if HTTP2xx(context.Background(), srv.URL, 100*time.Millisecond) {
		t.Fatal("HTTP2xx: hanging endpoint reported true")
	}
	if d := time.Since(start); d > 2*time.Second {
		t.Fatalf("HTTP2xx: deadline ignored, took %v", d)
	}
}

// clientOrDefault: the variadic *http.Client seam — an injected
// client wins, nil/absent falls back to the probe's package default.
func TestClientOrDefault(t *testing.T) {
	injected := &http.Client{}
	if got := clientOrDefault([]*http.Client{injected}, insecureClient); got != injected {
		t.Fatal("injected client not preferred")
	}
	if got := clientOrDefault([]*http.Client{nil}, insecureClient); got != insecureClient {
		t.Fatal("nil injected client must fall back to the default")
	}
	if got := clientOrDefault(nil, plainClient); got != plainClient {
		t.Fatal("absent client must fall back to the default")
	}
}

// failReadBody is a response body that fails every Read — the
// HTTPBodyInsecure verdict propagates it instead of returning "".
type failReadBody struct{}

func (failReadBody) Read([]byte) (int, error) { return 0, errors.New("read boom") }
func (failReadBody) Close() error             { return nil }

type rtFunc func(*http.Request) (*http.Response, error)

func (f rtFunc) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }

func TestHTTPBodyInsecureReadError(t *testing.T) {
	client := &http.Client{Transport: rtFunc(
		func(r *http.Request) (*http.Response, error) {
			return &http.Response{
				StatusCode: http.StatusOK,
				Body:       failReadBody{},
				Request:    r,
			}, nil
		})}
	if _, err := HTTPBodyInsecure(context.Background(),
		"http://probe.invalid/", 5*time.Second, client); err == nil {
		t.Fatal("body read error must propagate")
	}
}
