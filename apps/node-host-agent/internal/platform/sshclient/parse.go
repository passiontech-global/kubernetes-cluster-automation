// parse.go — the two small helpers both former private dialers
// carried near-identical copies of: ssh_proxyjump spec parsing and
// "~/" expansion.
package sshclient

import (
	"net"
	"os"
	"path/filepath"
	"strings"
)

// SplitUserHost parses "user@host[:port]" / "host" from an
// ssh_proxyjump spec — hubsync's splitUserHost and nebulasign's
// splitJump accepted the same shape. The shared copy returns
// hubsync's EMPTY port on an unported spec (the caller applies its
// own default): nebulasign's baked-in "22" is just its Config.Port.
// An explicit port is honoured verbatim.
func SplitUserHost(j string) (user, host, port string) {
	user = "root"
	if u, h, ok := strings.Cut(j, "@"); ok {
		user, j = u, h
	}
	host = j
	if h, p, err := net.SplitHostPort(j); err == nil {
		host, port = h, p
	}
	return user, host, port
}

// ExpandHome resolves a leading "~/" against the user's home dir —
// nebulasign's --ssh-key default is "~/.ssh/id_ed25519". A no-op on
// absolute paths (hubsync's /etc/node-converge-ssh/id_ed25519) and
// when the home dir can't be resolved.
func ExpandHome(p string) string {
	if strings.HasPrefix(p, "~/") {
		if home, err := os.UserHomeDir(); err == nil {
			return filepath.Join(home, p[2:])
		}
	}
	return p
}
