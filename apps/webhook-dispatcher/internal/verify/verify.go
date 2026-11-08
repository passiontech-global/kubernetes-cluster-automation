// Package verify checks GitHub webhook request signatures.
package verify

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"strings"
)

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
	got, ok := strings.CutPrefix(header, "sha256=")
	if !ok {
		return false
	}
	sig, err := hex.DecodeString(got)
	if err != nil {
		return false
	}
	mac := hmac.New(sha256.New, []byte(secret))
	mac.Write(body)
	return hmac.Equal(sig, mac.Sum(nil))
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
	for i := 0; i < len(got); i++ {
		c := got[i]
		if !('0' <= c && c <= '9' || 'a' <= c && c <= 'f' || 'A' <= c && c <= 'F') {
			return false
		}
	}
	return true
}
