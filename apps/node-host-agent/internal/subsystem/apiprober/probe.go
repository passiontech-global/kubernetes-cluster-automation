package apiprober

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"strconv"
	"strings"
	"syscall"
)

// tcpPreflight mirrors `timeout 5 bash -c "echo >/dev/tcp/$h/$p"`.
func (p *Prober) tcpPreflight(ctx context.Context, addr string) error {
	if p.cfg.TCPCheck != nil {
		return p.cfg.TCPCheck(ctx, addr)
	}
	cctx, cancel := context.WithTimeout(ctx, p.cfg.TCPTimeout)
	defer cancel()
	d := net.Dialer{}
	conn, err := d.DialContext(cctx, "tcp", addr)
	if err != nil {
		return err
	}
	// The dial is the verdict — a Close failure is local noise,
	// not evidence the backend is unreachable.
	_ = conn.Close()
	return nil
}

// failClass classifies why one backend query produced no usable rv —
// the DEAD verdict must fire on apiserver-side evidence only, so
// probe-side faults (credential file, auth reject, TLS trust, local
// request build) get their own classes and never accumulate qfail.
// The class is also the diagnostic operators were missing: "API
// queries failing" alone cannot tell an expired token from a wedged
// apiserver (the field incident this fixes: api-lb-vm logged DEAD
// for ~12.5h on a healthy backend while the data path was fine —
// HAProxy marked it UP and kubectl over the VIP worked).
type failClass string

const (
	failNone    failClass = ""              // query OK
	failToken   failClass = "token_read"    // token file unreadable — request never sent
	failAuth    failClass = "auth"          // HTTP 401/403 — credential rejected
	failTLS     failClass = "tls"           // handshake/x509 — trust/identity mismatch
	failRequest failClass = "request_build" // URL/header build failed — local config
	failTimeout failClass = "timeout"       // deadline exceeded — apiserver/network stall
	failRefused failClass = "conn_refused"  // ECONNREFUSED despite TCP preflight
	failConn    failClass = "conn_dropped"  // reset/aborted/EOF mid-request
	failTransp  failClass = "transport"     // other RoundTrip error
	failStatus  failClass = "http_status"   // non-200, non-auth response
	failBody    failClass = "body_read"     // response body read error
	failParse   failClass = "parse"         // bad JSON / non-numeric resourceVersion
)

// maxProbeBody is the safety bound on how much of an apiserver LIST
// body the probe ever reads — the streaming rv decode stops at
// metadata (before items), so this only bites a pathological payload.
const maxProbeBody = 1 << 20

// errBadPayload marks structurally invalid LIST JSON — a parse class,
// never a body-read fault.
var errBadPayload = errors.New("bad LIST payload")

// probeSide reports whether c is a fault of the PROBE rather than the
// apiserver — a credential, trust or request-build failure carries
// zero evidence about apiserver health, so a cycle whose failures
// are all probe-side is inconclusive: the backend counts neither
// fresh nor stale and can never reach the DEAD verdict (the 401-from-
// a-stale-guard-token incident shape).
func (c failClass) probeSide() bool {
	switch c {
	case failToken, failAuth, failTLS, failRequest:
		return true
	default:
		return false
	}
}

// failDetail renders a (class, error) pair for structured log fields
// — "" on success, "<class>: <err>" otherwise (the error already
// embeds the HTTP status for auth/status classes).
func failDetail(c failClass, err error) string {
	if c == failNone || err == nil {
		return ""
	}
	return string(c) + ": " + err.Error()
}

// classifyTransport maps a RoundTrip failure to its failClass so the
// DEAD/probe log lines carry the concrete fault — timeout vs refused
// vs reset vs TLS — instead of an undifferentiated "transport
// failed".
func classifyTransport(err error) failClass {
	var ne net.Error
	if errors.Is(err, context.DeadlineExceeded) ||
		(errors.As(err, &ne) && ne.Timeout()) {
		return failTimeout
	}
	// Certificate verification errors surface as typed values under
	// the RoundTrip's *url.Error.
	var cv *tls.CertificateVerificationError
	var ua x509.UnknownAuthorityError
	var hn x509.HostnameError
	var ci x509.CertificateInvalidError
	if errors.As(err, &cv) || errors.As(err, &ua) ||
		errors.As(err, &hn) || errors.As(err, &ci) {
		return failTLS
	}
	// Handshake failures that surface as plain text ("tls: bad
	// certificate", "tls: protocol version not supported", "tls:
	// handshake failure") or the transport's own protocol-mismatch
	// sentinel ("server gave HTTP response to HTTPS client" — the
	// endpoint isn't speaking TLS at all) don't wrap a typed x509
	// error — match on the error string before falling through to
	// generic classes.
	if s := err.Error(); strings.Contains(s, "tls:") ||
		strings.Contains(s, "x509:") ||
		strings.Contains(s, "response to HTTPS") {
		return failTLS
	}
	switch {
	case errors.Is(err, syscall.ECONNREFUSED):
		return failRefused
	case errors.Is(err, syscall.ECONNRESET),
		errors.Is(err, syscall.ECONNABORTED),
		errors.Is(err, io.EOF),
		errors.Is(err, io.ErrUnexpectedEOF):
		return failConn
	default:
		return failTransp
	}
}

// listRV returns the LIST-level resourceVersion of one apiserver
// endpoint, or a classified failure — the class + error are what the
// DEAD/probe log lines and the probe_error split consume.
//
// The bearer token is re-read on EVERY query (projected SA tokens
// rotate; the guard token on api-lb VMs is re-pushed by hubsync on
// every converge), so a rotated credential file self-heals on the
// next probe without an agent restart — there is no startup-cached
// credential to expire.
func (p *Prober) listRV(ctx context.Context, addr, path string) (rv int64, fc failClass, err error) {
	qctx, cancel := context.WithTimeout(ctx, p.cfg.QueryTimeout)
	defer cancel()
	req, err := http.NewRequestWithContext(qctx, http.MethodGet,
		"https://"+addr+path, nil)
	if err != nil {
		return 0, failRequest, err
	}
	// Ask for object metadata only — both probe paths are nodes LISTs.
	// resourceVersion=0 on the cache path is the architecture's
	// wedged-vs-etcd discriminator (the watch-cache serves it) and
	// stays, even though the watch-cache ignores limit for rv=0: the
	// body is never buffered whole (see the decode below), so a
	// large cluster can no longer truncate the payload into a
	// failParse — which is classified apiserver-side and would drain
	// a healthy backend.
	req.Header.Set("Accept",
		"application/json;as=PartialObjectMetadataList;g=meta.k8s.io;v=v1")
	// Token re-read per query — see func doc. An injected HTTPClient
	// (the test seam) issues its own auth.
	if p.eff.tokenFile != "" && p.cfg.HTTPClient == nil {
		tok, err := os.ReadFile(p.eff.tokenFile)
		if err != nil {
			return 0, failToken,
				fmt.Errorf("read token %s: %w", p.eff.tokenFile, err)
		}
		req.Header.Set("Authorization",
			"Bearer "+strings.TrimSpace(string(tok)))
	}
	resp, err := p.client.Do(req)
	if err != nil {
		return 0, classifyTransport(err), err
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		fc := failStatus
		if resp.StatusCode == http.StatusUnauthorized ||
			resp.StatusCode == http.StatusForbidden {
			fc = failAuth
		}
		return 0, fc, fmt.Errorf("HTTP %d from apiserver", resp.StatusCode)
	}
	// Stream-decode and stop as soon as metadata.resourceVersion
	// lands — the List JSON serializes metadata BEFORE items, so the
	// items array is never read, whatever the watch-cache's limit
	// handling returned. The 1 MiB LimitReader stays as a safety
	// bound against a pathological payload. Truncating a buffered
	// read here used to turn large clusters into failParse →
	// apiserver-side → DEAD drain of healthy backends.
	var list struct {
		Metadata struct {
			ResourceVersion string `json:"resourceVersion"`
		} `json:"metadata"`
	}
	dec := json.NewDecoder(io.LimitReader(resp.Body, maxProbeBody))
	if err := decodeListRV(dec, &list.Metadata.ResourceVersion); err != nil {
		// A syntax/EOF fault is a parse; anything else inside the
		// token walk is the body stream itself failing.
		var syn *json.SyntaxError
		if errors.As(err, &syn) || errors.Is(err, io.EOF) ||
			errors.Is(err, errBadPayload) {
			return 0, failParse, err
		}
		return 0, failBody, err
	}
	// Drain the rest of the body to EOF (uncapped) so keep-alive can
	// reuse the connection; the remainder of a big items array is
	// discarded, never buffered.
	_, _ = io.Copy(io.Discard, resp.Body)
	rv, err = strconv.ParseInt(list.Metadata.ResourceVersion, 10, 64)
	if err != nil {
		return 0, failParse,
			fmt.Errorf("non-numeric resourceVersion %q: %w",
				list.Metadata.ResourceVersion, err)
	}
	return rv, failNone, nil
}

// decodeListRV token-walks a List JSON just deep enough to surface
// top-level metadata.resourceVersion, then returns — the caller stops
// reading. depth==1 is the top-level object (its opening '{' counted).
func decodeListRV(dec *json.Decoder, rv *string) error {
	t, err := dec.Token()
	if err != nil {
		return err
	}
	if d, ok := t.(json.Delim); !ok || d != '{' {
		return fmt.Errorf("%w: unexpected JSON start %v", errBadPayload, t)
	}
	depth := 1
	for {
		t, err := dec.Token()
		if err != nil {
			return err
		}
		if d, ok := t.(json.Delim); ok {
			switch d {
			case '{', '[':
				depth++
			default:
				depth--
			}
			continue
		}
		if depth == 1 {
			if s, ok := t.(string); ok && s == "metadata" {
				var m struct {
					ResourceVersion string `json:"resourceVersion"`
				}
				if err := dec.Decode(&m); err != nil {
					return err
				}
				if m.ResourceVersion == "" {
					return fmt.Errorf("%w: empty metadata.resourceVersion",
						errBadPayload)
				}
				*rv = m.ResourceVersion
				return nil
			}
		}
	}
}
