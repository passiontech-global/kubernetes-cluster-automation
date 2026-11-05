package nethealth

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-host-agent/internal/platform/hoststate"
	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-host-agent/internal/platform/hostutil"
)

const hostsBlockBegin = "# BEGIN node-watchdog-dns"
const hostsBlockEnd = "# END node-watchdog-dns"

// --- Check: dns-fallback (20-dns-fallback.sh) ---

// nameservers returns up to 3 nameserver IPs from a resolv.conf
// (shell `awk $1=="nameserver" | head -3`).
func nameservers(path string, max int) []string {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil
	}
	var out []string
	for _, line := range strings.Split(string(data), "\n") {
		f := strings.Fields(line)
		if len(f) >= 2 && f[0] == "nameserver" {
			out = append(out, f[1])
			if len(out) >= max {
				break
			}
		}
	}
	return out
}

// pinFiles returns the sorted dnsfb-pin-* files — the source of truth
// for the managed /etc/hosts block.
func (n *NetHealth) pinFiles() []string {
	files, err := filepath.Glob(
		filepath.Join(n.cfg.WatchdogStateDir, "dnsfb-pin-*"))
	if err != nil {
		return nil
	}
	sort.Strings(files)
	return files
}

// renderHostsBlock rewrites the managed block in HostsFile from the
// pin files. block=="" (no pins) removes the block. Returns whether
// the file changed.
func (n *NetHealth) renderHostsBlock(block string) (changed bool) {
	data, err := os.ReadFile(n.cfg.HostsFile)
	if err != nil {
		logger().Warn("nethealth: hosts file unreadable — dns-fallback "+
			"block left untouched",
			"path", n.cfg.HostsFile,
			"error", err)
		return false
	}
	cur := string(data)
	var kept []string
	var tail []string // lines inside an unterminated managed block
	inBlock := false
	hadBlock := false
	for _, line := range strings.Split(cur, "\n") {
		switch strings.TrimSpace(line) {
		case hostsBlockBegin:
			inBlock, hadBlock = true, true
			continue
		case hostsBlockEnd:
			inBlock = false
			continue
		}
		if inBlock {
			tail = append(tail, line)
			continue
		}
		kept = append(kept, line)
	}
	if inBlock {
		// BEGIN without END (truncated/corrupted file): the block
		// ran to EOF. Don't silently eat its lines — they may be
		// real host entries stranded inside a stray marker — keep
		// them as ordinary content before the (re-)written block
		// and warn so the corruption is visible.
		//
		// The exception: lines pinning a MANAGED DNSFallback name.
		// Those are stale output of an earlier managed block, not
		// foreign entries, and re-emitting them ABOVE the new block
		// would let a dead pin shadow the fresh one (first match
		// wins in /etc/hosts). They are regenerable — the block
		// carries the live pins — so they drop; genuinely foreign
		// entries still keep their rescue.
		managed := map[string]bool{}
		if n.cfg.Watchdog != nil {
			for _, e := range n.cfg.Watchdog.DNSFallback {
				managed[e.Name] = true
			}
		}
		dropped := 0
		for _, line := range tail {
			if managedPinLine(line, managed) {
				dropped++
				continue
			}
			kept = append(kept, line)
		}
		logger().Warn("nethealth: unterminated "+hostsBlockBegin+" block "+
			"in hosts file — treating EOF as block end, keeping the "+
			"tail outside the managed block",
			"path", n.cfg.HostsFile,
			"stalePinsDropped", dropped)
	}
	body := strings.TrimRight(strings.Join(kept, "\n"), "\n")
	next := body + "\n"
	if block != "" {
		next = body + "\n" + hostsBlockBegin + "\n" + block + hostsBlockEnd + "\n"
	}
	if !hadBlock && block == "" {
		return false
	}
	if next == cur {
		return false
	}
	if err := hostutil.WriteFileAtomic(n.cfg.HostsFile, next); err != nil {
		logger().Warn("nethealth: hosts file write failed — dns-fallback "+
			"block not applied",
			"path", n.cfg.HostsFile,
			"error", err)
		return false
	}
	return true
}

// managedPinLine reports whether a hosts-file line pins one of the
// DNSFallback names — i.e. it is residue of an earlier managed block
// rather than a foreign entry worth rescuing from an unterminated
// block tail. Hostname fields are fields[1:] (field 0 is the IP);
// comments, blanks and malformed lines never match.
func managedPinLine(line string, managed map[string]bool) bool {
	if len(managed) == 0 {
		return false
	}
	f := strings.Fields(line)
	if len(f) < 2 || strings.HasPrefix(f[0], "#") {
		return false
	}
	for _, h := range f[1:] {
		if managed[h] {
			return true
		}
	}
	return false
}

// checkDNSFallback — sig10: DNS dead → pin fallback names into the
// managed /etc/hosts block so kubelet can still resolve the API name.
func (n *NetHealth) checkDNSFallback(ctx context.Context) {
	wd := n.cfg.Watchdog
	if len(wd.DNSFallback) == 0 {
		// Map empty → clean up block + files like the shell's else
		// (`rm -f dnsfb-*`: pin/last-good/counter files all go —
		// shell leftovers included).
		if n.renderHostsBlock("") {
			n.state.AppendLog("ACTION: /etc/hosts dns-fallback block removed (map empty)")
		}
		for _, f := range n.egressFiles("dnsfb-") {
			_ = os.Remove(f)
		}
		n.dnsfails = map[string]int{}
		n.stateExit(hoststate.LatchDNSFallback)
		n.cycles.WithLabelValues(checkDNSFB, "ok").Inc()
		return
	}
	ns := nameservers(n.cfg.HostResolvConf, 3)
	inMap := map[string]bool{}
	for _, e := range wd.DNSFallback {
		inMap[e.Name] = true
	}
	for _, e := range wd.DNSFallback {
		lg := filepath.Join(n.cfg.WatchdogStateDir, "dnsfb-lg-"+e.Name)
		pinf := filepath.Join(n.cfg.WatchdogStateDir, "dnsfb-pin-"+e.Name)
		resolved := ""
		for _, server := range ns {
			ip, err := n.cfg.dnsProbe(ctx, server, e.Name)
			if err != nil {
				logger().Debug("nethealth: dns probe failed",
					"name", e.Name,
					"nameserver", server, "error", err)
				continue
			}
			if ip != "" {
				resolved = ip
				break
			}
		}
		if resolved != "" {
			if hostutil.ReadTrimmed(lg) != resolved {
				if err := hostutil.WriteFileAtomic(lg, resolved+"\n"); err != nil {
					logger().Warn("nethealth: dns last-good write "+
						"failed — fallback pick may lose the "+
						"last-known-good IP",
						"name", e.Name,
						"path", lg, "error", err)
				}
			}
			delete(n.dnsfails, e.Name)
			_ = os.Remove(pinf)
			continue
		}
		n.dnsfails[e.Name]++
		fails := n.dnsfails[e.Name]
		curIP := ""
		if pin := strings.Fields(hostutil.ReadTrimmed(pinf)); len(pin) >= 1 {
			curIP = pin[0]
		}
		if fails < n.cfg.ConsecNeeded && curIP == "" {
			n.state.AppendLog(fmt.Sprintf(
				"suspect: dns-resolve %s fail via resolv.conf (check %d/%d)",
				e.Name, fails, n.cfg.ConsecNeeded))
			continue
		}
		// Over threshold or already pinned: keep a live pin, probe a
		// replacement when the current one dies — last-known-good
		// first, then map candidates (TCP probe, never ICMP — some
		// hubs filter it).
		if curIP == "" || n.cfg.tcpProbe(ctx, curIP, e.Port, 3*time.Second) != nil {
			newIP := ""
			cands := append([]string{hostutil.ReadTrimmed(lg)}, e.Candidates...)
			for _, c := range cands {
				if c == "" || c == curIP {
					continue
				}
				if n.cfg.tcpProbe(ctx, c, e.Port, 3*time.Second) == nil {
					newIP = c
					break
				}
			}
			if newIP != "" {
				n.state.AppendLog(fmt.Sprintf(
					"ACTION: dns-fallback pin %s -> %s (DNS fail %dx, was '%s')",
					e.Name, newIP, fails, curIP))
				if err := hostutil.WriteFileAtomic(pinf,
					newIP+" "+e.Name+"\n"); err != nil {
					n.state.AppendLog(fmt.Sprintf(
						"dns-fallback: pin file write failed for %s -> %s: %v",
						e.Name, newIP, err))
				}
				n.actions.WithLabelValues(checkDNSFB, "pin").Inc()
			} else if curIP == "" {
				n.state.SuspectLog("dnsfb-nocand-"+e.Name, fmt.Sprintf(
					"suspect: dns-fallback %s — all candidates unreachable, not pinning",
					e.Name), suspectLogCadence)
			}
			// Dead pin with no replacement → keep it (a pinned dead
			// IP is no worse than NXDOMAIN and may come back).
		}
	}
	// Prune pin files for names removed from the map — the shell
	// also dropped the matching dnsfb-ctr-* counter (the lg
	// last-known-good file stays: it is still the best hint if the
	// name ever comes back). The in-memory fail counters get the
	// same prune — otherwise a removed name's key lingers forever.
	for _, f := range n.pinFiles() {
		name := strings.TrimPrefix(filepath.Base(f), "dnsfb-pin-")
		if !inMap[name] {
			_ = os.Remove(f)
			_ = os.Remove(filepath.Join(n.cfg.WatchdogStateDir, "dnsfb-ctr-"+name))
		}
	}
	for name := range n.dnsfails {
		if !inMap[name] {
			delete(n.dnsfails, name)
		}
	}
	// Render the managed block from the pins.
	var block strings.Builder
	for _, f := range n.pinFiles() {
		if c := hostutil.ReadTrimmed(f); c != "" {
			block.WriteString(c + "\n")
		}
	}
	if block.Len() != 0 {
		if n.renderHostsBlock(block.String()) {
			n.state.AppendLog("ACTION: /etc/hosts dns-fallback block updated")
			// Newly written pins mean DNS was dead — conntrack
			// entries learned on the broken path blackhole lookups
			// until expiry unless flushed now.
			n.flushStaleUDPConntrack(ctx, checkDNSFB)
		}
		n.state.Enter(hoststate.LatchDNSFallback, "")
	} else {
		if n.renderHostsBlock("") {
			n.state.AppendLog("ACTION: /etc/hosts dns-fallback block removed (DNS OK)")
			// Unpin is a DNS-path transition too — replies for the
			// restored resolver may sit in stale udp/53 entries.
			n.flushStaleUDPConntrack(ctx, checkDNSFB)
		}
		n.stateExit(hoststate.LatchDNSFallback)
	}
	n.cycles.WithLabelValues(checkDNSFB, "ok").Inc()
}
