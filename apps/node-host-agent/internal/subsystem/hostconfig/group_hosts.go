// group_hosts.go — /etc/hosts managed-block helpers (ansible
// blockinfile parity, both marker styles) shared by the apilb
// cp_endpoint pin and the coredns interdc-zone-pins block.
package hostconfig

import (
	"os"
	"regexp"
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
