// group_hosts.go — /etc/hosts managed-block helpers (ansible
// blockinfile parity, both marker styles) shared by the apilb
// cp_endpoint pin and the coredns interdc-zone-pins block, plus the
// hostname -> 127.0.1.1 pin groupBase converges every cycle (split
// out of group_base.go — pure move, same package).
package hostconfig

import (
	"os"
	"regexp"
	"strings"
)

// hostsBlockRe matches a managed block in BOTH marker styles: the
// ansible blockinfile `{mark} <name> managed block` and the first
// port's `ANSIBLE MANAGED BLOCK - <name>` — stale blocks of either
// style must be replaced/removed (dead pin otherwise).
func hostsBlockRe(mark string) *regexp.Regexp {
	q := regexp.QuoteMeta(mark)
	return regexp.MustCompile(
		`(?ms)# BEGIN ` + q + ` managed block\n.*?# END ` + q + ` managed block\n?|` +
			`(?ms)# BEGIN ANSIBLE MANAGED BLOCK - ` + q + `\n.*?# END ANSIBLE MANAGED BLOCK - ` + q + `\n?`)
}

// blockInHosts upserts an ansible-style managed block in /etc/hosts.
func (c *cyc) blockInHosts(mark, block string) {
	hosts, err := os.ReadFile(c.r.hp("/etc/hosts"))
	if err != nil && !os.IsNotExist(err) {
		// Bail like removeFromHosts: appending after a failed read
		// would rewrite /etc/hosts to ONLY the managed block.
		c.err("hosts: cannot read /etc/hosts — managed block not written",
			"mark", mark, "error", err)
		return
	}
	// ENOENT is fine — a minimal image may ship no /etc/hosts at
	// all; write it containing just the managed block.
	re := hostsBlockRe(mark)
	var nh []byte
	if re.Match(hosts) {
		nh = re.ReplaceAll(hosts, []byte(block))
	} else {
		nh = append(append([]byte{}, hosts...), []byte(block)...)
	}
	_, _ = c.r.writeManaged("/etc/hosts", nh, 0o644)
}

func (c *cyc) removeFromHosts(mark string) {
	hosts, err := os.ReadFile(c.r.hp("/etc/hosts"))
	if err != nil {
		c.err("T12: cannot read /etc/hosts — managed block not removed",
			"mark", mark, "error", err)
		return
	}
	nh := hostsBlockRe(mark).ReplaceAll(hosts, nil)
	if string(nh) != string(hosts) {
		_, _ = c.r.writeManaged("/etc/hosts", nh, 0o644)
	}
}

// pinHosts — blockinfile `# {mark} api-local-lb managed block`.
func (c *cyc) pinHosts() {
	block := "# BEGIN api-local-lb managed block\n127.0.0.1 " + c.v("cp_endpoint") +
		"\n# END api-local-lb managed block\n"
	hosts, _ := os.ReadFile(c.r.hp("/etc/hosts"))
	if len(hosts) > 0 && hosts[len(hosts)-1] != '\n' {
		block = "\n" + block
	}
	c.blockInHosts("api-local-lb", block)
}

func (c *cyc) unpinHosts() {
	c.removeFromHosts("api-local-lb")
}

// ---------- hostname -> 127.0.1.1 pin (groupBase, every cycle) ----------

// hostnamePin pins the node's hostname to 127.0.1.1 in /etc/hosts
// (ansible lineinfile parity): replaces an existing 127.0.1.1 line
// that does not yet carry THIS hostname as a whole field, or appends
// the pin.
func (c *cyc) hostnamePin() {
	r := c.r
	hosts, hostsErr := os.ReadFile(r.hp("/etc/hosts"))
	if hostsErr != nil && !os.IsNotExist(hostsErr) {
		// Best-effort pre-warning only — the writeManaged failure
		// below is what counts the group error.
		logger().Warn("base: cannot read /etc/hosts — hostname pin update will fail",
			"error", hostsErr)
	}
	hn := c.r.cfg.NodeName
	// The separator must be a non-newline whitespace — bare `\s`
	// could eat the newline after a value-less `127.0.1.1` line and
	// let the match swallow the NEXT line on replace. Capture the
	// prefix (leading space + IP + separator) and the trailing
	// aliases so a re-pin swaps ONLY the hostname field — ansible
	// lineinfile parity keeps `127.0.1.1 <hn> alias1 alias2`'s
	// aliases alive across converges.
	re := regexp.MustCompile(`(?m)^([ \t]*127\.0\.1\.1[ \t]+)\S+(.*)$`)
	line := "127.0.1.1 " + hn
	if m := re.Find(hosts); m != nil {
		// The pin must carry THIS hostname as a whole field — a
		// substring Contains matched "127.0.1.1 worker-10" when hn
		// was "worker-1" and left the wrong pin live.
		pinned := false
		for _, f := range strings.Fields(string(m))[1:] {
			if f == hn {
				pinned = true
				break
			}
		}
		if !pinned {
			nh := re.ReplaceAllFunc(hosts, func(l []byte) []byte {
				sub := re.FindSubmatch(l)
				// Copy — sub slices share hosts' backing array, and
				// appending into it would corrupt later matches.
				out := append([]byte{}, sub[1]...)
				out = append(out, []byte(hn)...)
				// Trailing empty submatches are truncated in
				// FindSubmatch's result — the no-alias line has no
				// group 2.
				if len(sub) > 2 {
					out = append(out, sub[2]...)
				}
				return out
			})
			if string(nh) != string(hosts) {
				_, _ = r.writeManaged("/etc/hosts", nh, 0o644)
			}
		}
	} else {
		// Glue guard: a hosts file without a trailing newline must
		// not fuse the pin onto the last existing line.
		if len(hosts) > 0 && hosts[len(hosts)-1] != '\n' {
			hosts = append(hosts, '\n')
		}
		nh := append(hosts, []byte(line+"\n")...)
		_, _ = r.writeManaged("/etc/hosts", nh, 0o644)
	}
}
