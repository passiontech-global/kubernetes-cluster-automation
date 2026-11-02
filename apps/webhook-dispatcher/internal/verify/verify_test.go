package verify

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"testing"
)

func sign(secret string, body []byte) string {
	mac := hmac.New(sha256.New, []byte(secret))
	mac.Write(body)
	return "sha256=" + hex.EncodeToString(mac.Sum(nil))
}

func TestSignature(t *testing.T) {
	body := []byte(`{"zen":"Keep it simple."}`)
	cases := []struct {
		name   string
		secret string
		body   []byte
		header string
		want   bool
	}{
		{"valid", "s3cret", body, sign("s3cret", body), true},
		{"valid empty body", "s3cret", nil, sign("s3cret", nil), true},
		{"wrong secret", "s3cret", body, sign("other", body), false},
		{"tampered body", "s3cret", []byte(`{"x":1}`), sign("s3cret", body), false},
		{"missing header", "s3cret", body, "", false},
		{"missing sha256= prefix", "s3cret", body, sign("s3cret", body)[7:], false},
		{"sha1 scheme", "s3cret", body, "sha1=" + sign("s3cret", body)[7:], false},
		{"not hex", "s3cret", body, "sha256=zzzz", false},
		{"truncated sig", "s3cret", body, sign("s3cret", body)[:20], false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := Signature(tc.secret, tc.body, tc.header); got != tc.want {
				t.Fatalf("Signature=%v want %v", got, tc.want)
			}
		})
	}
}
