// validate_url_test.go — regression coverage for boot-time CONCOURSE_URL
// validation (scheme, host, no embedded userinfo, trailing slash trim).
package main

import (
	"testing"
)

func TestValidateConcourseURL(t *testing.T) {
	good := []struct {
		in   string
		want string
	}{
		{"http://concourse-web:8080", "http://concourse-web:8080"},
		{"https://ci.example.com///", "https://ci.example.com"},
		{"  http://atc:8080/  ", "http://atc:8080"},
		{"http://user:pass@atc:8080/", "http://user:pass@atc:8080"},
		{"https://user:pass@ci.example.com/prefix/", "https://user:pass@ci.example.com/prefix"},
		{"http://[::1]:8080", "http://[::1]:8080"},
	}
	for _, tc := range good {
		got, err := validateConcourseURL(tc.in)
		if err != nil {
			t.Fatalf("validateConcourseURL(%q) error = %v", tc.in, err)
		}
		if got != tc.want {
			t.Fatalf("validateConcourseURL(%q) = %q, want %q", tc.in, got, tc.want)
		}
	}

	bad := []string{
		"",
		"://broken",
		"ftp://atc:8080",
		"http://",
		"http://:8080",
		"http://atc:99999",
		"http://atc:0",
		"http://atc:abc",
		"http://atc:8080?q=1",
		"http://atc:8080?",
		"http://atc:8080#frag",
	}
	for _, in := range bad {
		if _, err := validateConcourseURL(in); err == nil {
			t.Fatalf("validateConcourseURL(%q) succeeded, want error", in)
		}
	}
}
