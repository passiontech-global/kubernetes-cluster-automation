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
func Signature(secret string, body []byte, header string) bool {
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
