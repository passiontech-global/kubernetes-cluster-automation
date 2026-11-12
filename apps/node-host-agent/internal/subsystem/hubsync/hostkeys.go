// hostkeys.go — hubsync's SSH host-key trust policy. Precedence per
// dialed hostname: explicit fingerprint pins (single pin or the
// host=fp,host2=fp,*=fp map), the operator known_hosts file next to
// the converge key, then the persistent TOFU store
// (<StateDir>/hubsync_known_hosts, 0600, atomic). A host absent from
// every source is recorded on first connect and hard-blocked if its
// key ever changes — prod manifests carry no pin today, so TOFU is
// what keeps them working while still stopping a MITM swap.
package hubsync

import (
	"errors"
	"fmt"
	"log/slog"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"

	"golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/knownhosts"

	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-host-agent/internal/envnames"
	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-host-agent/internal/platform/sshclient"
)

// hostKeyPolicy resolves trust for one hostname. It is built once
// per sshDialer; the known_hosts/TOFU files are re-read per verify
// so a rotated operator file or a just-written TOFU entry is seen
// without a restart.
type hostKeyPolicy struct {
	// pins is the parsed host=fp map ("*" = wildcard); single is
	// the legacy whole-spec pin applied to every host. Exactly one
	// is non-empty when the env carried a pin.
	pins   map[string]string
	single string

	knownHostsPath string // "" → no operator known_hosts
	tofuPath       string // "" → TOFU disabled
	// port is the converge SSH port — known_hosts entries are
	// port-exact (a plain "host" pattern only matches :22), so the
	// verifier and the TOFU writer must agree on it.
	port int

	// insecure accepts any key (audit-logged by sshclient) — the
	// last resort before a hard reject.
	insecure bool

	log *slog.Logger

	// tofuMu serializes read-check-append on the TOFU file —
	// overlapping target dials must not lose each other's entries.
	tofuMu sync.Mutex
}

// parseHostKeySpec splits NODE_HOST_AGENT_HUBSYNC_SSH_HOST_KEY_
// FINGERPRINT into either the legacy single pin or the per-host map
// "host1=SHA256:..,host2=SHA256:..,*=SHA256:..". Map mode requires
// EVERY comma part to be a non-empty host= plus a SHA256: fingerprint
// — anything else falls back to single-pin mode so a malformed spec
// can never widen trust (a bare "SHA256:..=" pin's '=' padding fails
// the fp-nonempty test and stays single).
func parseHostKeySpec(spec string) (pins map[string]string, single string) {
	spec = strings.TrimSpace(spec)
	if spec == "" {
		return nil, ""
	}
	parts := strings.Split(spec, ",")
	m := make(map[string]string, len(parts))
	for _, p := range parts {
		i := strings.Index(p, "=")
		if i <= 0 {
			return nil, spec
		}
		host := strings.ToLower(strings.TrimSpace(p[:i]))
		fp := strings.TrimSpace(p[i+1:])
		if host == "" || !strings.HasPrefix(fp, "SHA256:") {
			return nil, spec
		}
		m[host] = fp
	}
	return m, ""
}

// newHostKeyPolicy builds the verifier inputs. knownHostsPath is
// the operator file (derived from the key dir by the caller); tofuPath
// is empty when no state dir is configured. port<=0 means 22.
func newHostKeyPolicy(spec, knownHostsPath, tofuPath string,
	port int, insecure bool, log *slog.Logger) *hostKeyPolicy {
	pins, single := parseHostKeySpec(spec)
	if port <= 0 {
		port = 22
	}
	return &hostKeyPolicy{
		pins: pins, single: single,
		knownHostsPath: knownHostsPath, tofuPath: tofuPath,
		port: port, insecure: insecure, log: log,
	}
}

// active reports whether any trust source exists — with none and
// !insecure the dial must fail closed before a transport opens
// (the historical unpinned-default rejection). The known_hosts file
// counts only when actually present: the secret may mount later and
// active() is re-evaluated on every Dial.
func (p *hostKeyPolicy) active() bool {
	if p.single != "" || len(p.pins) > 0 || p.tofuPath != "" ||
		p.insecure {
		return true
	}
	if p.knownHostsPath != "" {
		if _, err := os.Stat(p.knownHostsPath); err == nil {
			return true
		}
	}
	return false
}

// verify is the sshclient.Config.HostKeyVerify callback. hostname is
// the dial host as ssh presents it (may carry a port); trust lookups
// normalize it, while known_hosts callbacks get the raw value —
// knownhosts does its own addr normalization incl. [host]:port.
func (p *hostKeyPolicy) verify(hostname string, key ssh.PublicKey) error {
	host := normalizeSSHHost(hostname)
	fp := ssh.FingerprintSHA256(key)

	// 1. Explicit pins — a matched pin is authoritative: mismatch
	//    rejects outright (MITM signal), never falls through.
	if p.single != "" {
		if !sshclient.FingerprintMatches(p.single, key) {
			return fmt.Errorf("ssh host key %s does not match pinned %s",
				fp, p.single)
		}
		return nil
	}
	if pin, ok := p.pins[host]; ok {
		if !sshclient.FingerprintMatches(pin, key) {
			return fmt.Errorf("ssh host key %s does not match pin for %s",
				fp, host)
		}
		return nil
	}
	if pin, ok := p.pins["*"]; ok {
		if !sshclient.FingerprintMatches(pin, key) {
			return fmt.Errorf("ssh host key %s does not match wildcard pin",
				fp)
		}
		return nil
	}

	// 2. Operator known_hosts — listed hosts are enforced; an
	//    unknown host or absent/unparseable file falls through to
	//    TOFU.
	if p.knownHostsPath != "" {
		accepted, err := p.checkKnownHosts(hostname, key)
		if err != nil {
			return err
		}
		if accepted {
			return nil
		}
	}

	// 3. Persistent TOFU.
	if p.tofuPath != "" {
		return p.checkTOFU(host, key)
	}

	// 4. Explicit insecure opt-out — last resort, audit-logged by
	//    the sshclient wrapper.
	if p.insecure {
		return nil
	}
	return fmt.Errorf("ssh host key %s for %s is not pinned "+
		"(set %s or %s=1)", fp, host,
		envnames.EnvHubsyncSSHHostKeyFingerprint,
		envnames.EnvHubsyncSSHAllowInsecureHostKey)
}

// knownHostsPresent stats the operator file — split out so the
// "absent → skip" branch does not trip nilerr on the deliberate
// nil-error return.
func (p *hostKeyPolicy) knownHostsPresent() bool {
	_, err := os.Stat(p.knownHostsPath)
	return err == nil
}

// checkKnownHosts runs the OpenSSH known_hosts callback for path.
// accepted=true means the file vouched for the key — verify stops.
// accepted=false means "no authoritative answer" (host unlisted, or
// the file missing/unparseable) and the chain continues to TOFU;
// a non-nil error is a real mismatch and rejects. A missing file is
// skipped — the secret mount may not exist yet and TOFU still covers
// first contact.
func (p *hostKeyPolicy) checkKnownHosts(hostname string,
	key ssh.PublicKey) (bool, error) {
	if !p.knownHostsPresent() {
		return false, nil
	}
	cb, kerr := knownhosts.New(p.knownHostsPath)
	if kerr != nil {
		p.log.Warn("hubsync: known_hosts parse failed — skipping file",
			"path", p.knownHostsPath, "error", kerr)
		return false, nil
	}
	// knownhosts requires BOTH args in host:port form and matches
	// entries port-exactly — build the addr from the normalized
	// host + configured port.
	addrPort := net.JoinHostPort(normalizeSSHHost(hostname),
		strconv.Itoa(p.port))
	err := cb(addrPort, hostPortAddr(addrPort), key)
	if err == nil {
		return true, nil
	}
	var ke *knownhosts.KeyError
	if errors.As(err, &ke) && len(ke.Want) == 0 {
		return false, nil // host unlisted — TOFU may record it
	}
	return false, fmt.Errorf("ssh host key rejected by %s: %w",
		p.knownHostsPath, err)
}

// checkTOFU validates against <StateDir>/hubsync_known_hosts and
// records first-seen keys. The file is itself a known_hosts database
// (knownhosts.Line output), so later verifies — and operators with
// ssh-keygen — read it natively.
func (p *hostKeyPolicy) checkTOFU(host string, key ssh.PublicKey) error {
	p.tofuMu.Lock()
	defer p.tofuMu.Unlock()

	if _, err := os.Stat(p.tofuPath); err == nil {
		cb, err := knownhosts.New(p.tofuPath)
		if err != nil {
			return fmt.Errorf("hubsync: tofu known_hosts parse: %w", err)
		}
		// Feed host:port — entries were written under the same
		// port-exact matching the operator file uses.
		addrPort := net.JoinHostPort(host, strconv.Itoa(p.port))
		err = cb(addrPort, hostPortAddr(addrPort), key)
		if err == nil {
			return nil
		}
		var ke *knownhosts.KeyError
		if !(errors.As(err, &ke) && len(ke.Want) == 0) {
			return fmt.Errorf("ssh host key for %s changed since "+
				"first trust — refusing (possible MITM); remove %s "+
				"to re-pin", host, p.tofuPath)
		}
		// Unknown host → record below.
	} else if !os.IsNotExist(err) {
		return fmt.Errorf("hubsync: tofu known_hosts stat: %w", err)
	}

	// First contact (or a host new to the file): append the key
	// atomically — tmp+rename in the same dir, 0600 so the trust
	// store is not world-readable. The pattern is port-exact like
	// OpenSSH: plain host on :22, "[host]:port" otherwise.
	pattern := host
	if p.port != 22 {
		pattern = "[" + strings.Trim(host, "[]") + "]:" +
			strconv.Itoa(p.port)
	}
	line := knownhosts.Line([]string{pattern}, key) + "\n"
	if err := appendFileAtomic(p.tofuPath, []byte(line), 0o600); err != nil {
		return fmt.Errorf("hubsync: tofu known_hosts write: %w", err)
	}
	if p.log != nil {
		p.log.Info("hubsync: trusted new ssh host key (TOFU)",
			"host", host, "fingerprint", ssh.FingerprintSHA256(key),
			"file", p.tofuPath)
	}
	return nil
}

// hostPortAddr is a net.Addr whose String() is already "host:port" —
// knownhosts SplitHostPorts both its args, and a real *net.TCPAddr
// cannot carry a DNS hostname.
type hostPortAddr string

func (a hostPortAddr) Network() string { return "tcp" }
func (a hostPortAddr) String() string  { return string(a) }

// normalizeSSHHost lowercases the dial hostname and strips a
// :port suffix — pin-map keys and TOFU entries are port-independent
// (the converge port is a Config knob, not part of host identity).
func normalizeSSHHost(hostname string) string {
	h := strings.ToLower(strings.TrimSpace(hostname))
	if host, _, err := net.SplitHostPort(h); err == nil {
		return strings.Trim(host, "[]")
	}
	return strings.Trim(h, "[]")
}

// appendFileAtomic appends data to path via write-temp+rename so a
// crash mid-append cannot leave a torn trust store. An absent file
// is created; an existing file keeps its prior lines (read +
// rewrite — known_hosts files are tiny).
func appendFileAtomic(path string, data []byte, perm os.FileMode) error {
	var prev []byte
	if b, err := os.ReadFile(path); err == nil {
		prev = b
	} else if !os.IsNotExist(err) {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return err
	}
	tmp, err := os.CreateTemp(filepath.Dir(path), ".hubsync_known_hosts-*")
	if err != nil {
		return err
	}
	tmpName := tmp.Name()
	defer func() { _ = os.Remove(tmpName) }()
	if _, err := tmp.Write(append(prev, data...)); err != nil {
		_ = tmp.Close()
		return err
	}
	if err := tmp.Chmod(perm); err != nil {
		_ = tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	return os.Rename(tmpName, path)
}
