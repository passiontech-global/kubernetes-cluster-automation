package verify

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"strings"
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

func TestHasValidSignatureFormat(t *testing.T) {
	body := []byte(`{"zen":"Keep it simple."}`)
	valid := sign("s3cret", body)
	cases := []struct {
		name   string
		secret string
		header string
		want   bool
	}{
		{"well-formed", "s3cret", valid, true},
		{"well-formed wrong sig", "s3cret", sign("other", body), true},
		{"uppercase hex", "s3cret", "sha256=" + strings.ToUpper(valid[7:]), true},
		{"empty secret", "", valid, false},
		{"missing header", "s3cret", "", false},
		{"missing sha256= prefix", "s3cret", valid[7:], false},
		{"sha1 scheme", "s3cret", "sha1=" + valid[7:], false},
		{"not hex", "s3cret", "sha256=" + strings.Repeat("z", 64), false},
		{"short hex", "s3cret", "sha256=" + valid[7:20], false},
		{"long hex", "s3cret", "sha256=" + valid[7:] + "0", false},
		{"hex with newline", "s3cret", "sha256=" + valid[7:71] + "\n000", false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := HasValidSignatureFormat(tc.secret, tc.header); got != tc.want {
				t.Fatalf("HasValidSignatureFormat=%v want %v", got, tc.want)
			}
		})
	}
}
