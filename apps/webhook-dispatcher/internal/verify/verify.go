// Package verify checks GitHub webhook request signatures.
package verify

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"io"
	"strings"
)

// signatureDigest decodes the "sha256=<hex>" header into the raw
// signature bytes. ok=false covers every malformed shape — missing
// prefix, non-hex, wrong length — so both verify entry points reject
// identically before touching the body.
func signatureDigest(header string) ([]byte, bool) {
	got, ok := strings.CutPrefix(header, "sha256=")
	if !ok {
		return nil, false
	}
	sig, err := hex.DecodeString(got)
	if err != nil {
		return nil, false
	}
	return sig, true
}

// Signature reports whether header is the expected
// "sha256=<hex HMAC-SHA256 of body keyed by secret>" value GitHub
// sends in X-Hub-Signature-256. The comparison is constant-time.
//
// An empty secret is rejected immediately: with no key configured
// nothing can be verified, and an HMAC keyed by the empty string
// would happily validate attacker-forged signatures — the key is no
// secret at all. Fail closed.
func Signature(secret string, body []byte, header string) bool {
	if secret == "" {
		return false
	}
	sig, ok := signatureDigest(header)
	if !ok {
		return false
	}
	mac := hmac.New(sha256.New, []byte(secret))
	mac.Write(body)
	var digest [sha256.Size]byte
	mac.Sum(digest[:0])
	return hmac.Equal(sig, digest[:])
}

// SignatureReader is Signature's streaming form: it hashes r
// incrementally instead of requiring the whole body in memory, for
// deliveries whose payload is never parsed (events outside
// resourceTypeForEvent — acknowledged 202 on a valid signature
// alone). The reader should already be bounded (the handler passes
// http.MaxBytesReader); a read error aborts the check and is
// returned so the caller can map it onto 413/400 exactly like the
// buffered path. (matched, err) — matched=false with err=nil means
// "not a valid signature", same verdict Signature returns.
func SignatureReader(secret string, r io.Reader, header string) (bool, error) {
	if secret == "" {
		return false, nil
	}
	sig, ok := signatureDigest(header)
	if !ok {
		return false, nil
	}
	mac := hmac.New(sha256.New, []byte(secret))
	if _, err := io.Copy(mac, r); err != nil {
		return false, err
	}
	var digest [sha256.Size]byte
	mac.Sum(digest[:0])
	return hmac.Equal(sig, digest[:]), nil
}

// HasValidSignatureFormat reports whether sigHeader is plausibly a
// GitHub X-Hub-Signature-256 value — the "sha256=" prefix followed by
// exactly 64 hex digits — and a secret is configured to check it
// against. It is a cheap pre-filter so unsigned or malformed requests
// can be rejected before the request body is read and allocated; the
// constant-time Signature check still makes the final call once the
// body is known.
func HasValidSignatureFormat(secret, sigHeader string) bool {
	if secret == "" {
		return false
	}
	got, ok := strings.CutPrefix(sigHeader, "sha256=")
	if !ok || len(got) != sha256.Size*2 {
		return false
	}
	for i := range len(got) {
		c := got[i]
		if !('0' <= c && c <= '9' || 'a' <= c && c <= 'f' || 'A' <= c && c <= 'F') {
			return false
		}
	}
	return true
}
