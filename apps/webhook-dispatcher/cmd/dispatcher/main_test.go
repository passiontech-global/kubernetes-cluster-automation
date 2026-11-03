package main

import "testing"

func TestParseLocalUsers(t *testing.T) {
	cases := []struct {
		name           string
		in             string
		user, password string
		ok             bool
	}{
		{"basic", "admin:pw", "admin", "pw", true},
		// Only the first colon splits — bcrypt hashes and passwords
		// with colons survive intact.
		{"colon in password", "admin:pw:with:colons", "admin", "pw:with:colons", true},
		{"empty password", "admin:", "", "", false},
		{"empty user", ":pw", "", "", false},
		{"no colon", "admin", "", "", false},
		{"empty", "", "", "", false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			user, password, ok := parseLocalUsers(tc.in)
			if ok != tc.ok {
				t.Fatalf("parseLocalUsers(%q) ok=%v want %v", tc.in, ok, tc.ok)
			}
			if ok && (user != tc.user || password != tc.password) {
				t.Fatalf("parseLocalUsers(%q)=(%q,%q) want (%q,%q)",
					tc.in, user, password, tc.user, tc.password)
			}
		})
	}
}
