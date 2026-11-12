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

func TestParseLocalUsersEnv(t *testing.T) {
	cases := []struct {
		name           string
		in             string
		user, password string
		ok             bool
	}{
		{"single", "admin:pw", "admin", "pw", true},
		{"surrounding space", "  admin:pw  ", "admin", "pw", true},
		{"two users first wins", "admin:pw,ops:secret", "admin", "pw", true},
		// A comma is a separator ONLY when the segment after it has
		// the user:pass shape — a comma inside a password survives.
		{"comma in password", "admin:pa,ss", "admin", "pa,ss", true},
		{"comma then user", "admin:pa,ss,ops:pw", "admin", "pa,ss", true},
		// A trailing comma or empty/whitespace segment between entries
		// is a separator and gets dropped rather than corrupting the
		// password.
		{"trailing comma dropped", "admin:pw,", "admin", "pw", true},
		{"trailing comma with space dropped", "admin:pw, , ", "admin", "pw", true},
		{"empty segment between users", "u:p, ,v:q", "u", "p", true},
		{"leading comma dropped", ",admin:pw", "admin", "pw", true},
		{"space-only entries dropped", " , admin:pw", "admin", "pw", true},
		{"first invalid second valid", "broken,ops:pw", "ops", "pw", true},
		{"all invalid", "a,b,c", "", "", false},
		{"empty", "", "", "", false},
		{"whitespace only", "   ", "", "", false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			user, password, ok := parseLocalUsersEnv(tc.in)
			if ok != tc.ok {
				t.Fatalf("parseLocalUsersEnv(%q) ok=%v want %v", tc.in, ok, tc.ok)
			}
			if ok && (user != tc.user || password != tc.password) {
				t.Fatalf("parseLocalUsersEnv(%q)=(%q,%q) want (%q,%q)",
					tc.in, user, password, tc.user, tc.password)
			}
		})
	}
}
