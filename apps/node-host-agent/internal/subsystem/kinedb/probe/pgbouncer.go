// pgbouncer.go — the in-container pgbouncer console credential
// lookup. The shell this replaces ran, INSIDE the pgbouncer
// container:
//
//	U=$(sed -n "s/^admin_users *= *//p" /etc/pgbouncer/pgbouncer.ini | cut -d, -f1 | tr -d " ")
//	[ -n "$U" ] || U=$(sed -n "s/^stats_users *= *//p" ...)
//	P=$(grep "^\"$U\"" /etc/pgbouncer/userlist.txt | cut -d\" -f4)
//	PGPASSWORD="$P" psql -h 127.0.0.1 -p 5432 -U "$U" ...
//
// Two `cat` execs + Go parsing produce the same (user, password)
// pair with no shell, no sed/cut/tr/grep forks and no quoting
// surface — the parsers below are field-for-field ports of that
// pipeline.
package probe

import (
	"context"
	"errors"
	"strings"
)

// errPGBCredsUnavailable marks the fallback's "could not even read
// the ini" exit — the psql attempt is skipped (it could only fail)
// while the caller's inconclusive-note path still fires.
var errPGBCredsUnavailable = errors.New("pgbouncer console credentials unavailable")

// pgbouncerCreds reads the pgbouncer console credentials the
// in-container fallback needs: the first non-empty value among keys
// (the e2e-auth path asks admin_users then stats_users; the
// SHOW POOLS path asks stats_users alone — the shell's two call
// sites differed exactly this way), then that user's password out
// of userlist.txt's `"user" "hash"` lines. ok=false only when the
// ini itself cannot be read or no listed key yields a user — a
// missing userlist or an unparseable password yields "" (the psql
// attempt then fails exactly like the shell version's empty
// PGPASSWORD did).
func (p *Probe) pgbouncerCreds(ctx context.Context, pgb string,
	keys ...string) (user, pass string, ok bool) {
	ini, err := p.d.Exec(ctx, []string{p.d.Cfg.Runtime, "exec", pgb,
		"cat", "/etc/pgbouncer/pgbouncer.ini"}, "")
	if err != nil {
		return "", "", false
	}
	for _, k := range keys {
		if user = iniListValue(ini, k); user != "" {
			break
		}
	}
	if user == "" {
		return "", "", false
	}
	ul, err := p.d.Exec(ctx, []string{p.d.Cfg.Runtime, "exec", pgb,
		"cat", "/etc/pgbouncer/userlist.txt"}, "")
	if err != nil {
		return user, "", true
	}
	return user, userlistPassword(ul, user), true
}

// iniListValue ports `sed -n "s/^<key> *= *//p" | cut -d, -f1 |
// tr -d " "` for one ini key: the first line anchored at <key>
// followed by optional spaces, `=` and optional spaces; the value
// up to the first comma with every space removed. sed's ` *` is
// spaces-only (a tab after the key never matched), and a key that
// is a PREFIX of a longer name (`admin_users_extra`) fails the `=`
// check and is skipped — both preserved here.
func iniListValue(ini, key string) string {
	for ln := range strings.SplitSeq(ini, "\n") {
		ln = strings.TrimSuffix(ln, "\r")
		if !strings.HasPrefix(ln, key) {
			continue
		}
		rest := strings.TrimLeft(ln[len(key):], " ")
		if !strings.HasPrefix(rest, "=") {
			continue
		}
		rest = strings.TrimLeft(rest[1:], " ")
		if i := strings.IndexByte(rest, ','); i >= 0 {
			rest = rest[:i]
		}
		return strings.ReplaceAll(rest, " ", "")
	}
	return ""
}

// userlistPassword ports `grep "^\"<user>\"" userlist.txt |
// cut -d\" -f4`: the first line starting with the quoted user key,
// then the SECOND quoted field — for `"user" "hash"` the 4th
// `"`-delimited cut field is the hash. An unterminated tail still
// yields the remainder (cut -f4 takes it); a line with no second
// quoted span yields "".
func userlistPassword(userlist, user string) string {
	prefix := `"` + user + `"`
	for ln := range strings.SplitSeq(userlist, "\n") {
		ln = strings.TrimSuffix(ln, "\r")
		if !strings.HasPrefix(ln, prefix) {
			continue
		}
		rest := ln[len(prefix):]
		open := strings.IndexByte(rest, '"')
		if open < 0 {
			return ""
		}
		rest = rest[open+1:]
		if close := strings.IndexByte(rest, '"'); close >= 0 {
			return rest[:close]
		}
		return rest
	}
	return ""
}
