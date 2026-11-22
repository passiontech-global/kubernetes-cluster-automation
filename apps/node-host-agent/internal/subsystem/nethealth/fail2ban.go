package nethealth

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"time"
	"unicode"

	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-host-agent/internal/latchdefs"
	"github.com/passiontech-global/kubernetes-cluster-automation/libs/hostkit/fsx"
)

const f2bRestartInterval = 30 * time.Minute

// --- Check: fail2ban (50-fail2ban.sh) ---

// jailRe extracts the jail list / banned counts from
// fail2ban-client status output.
var (
	jailListRe = regexp.MustCompile(`Jail list:\s*(.+)`)
	bannedRe   = regexp.MustCompile(`Currently banned:\s*([0-9]+)`)
)

// checkFail2ban — unit installed but service down → fail2ban-down
// latch; per-jail banned counts go to fail2ban-banned for the
// node_fail2ban_banned_ips metric.
func (n *NetHealth) checkFail2ban(ctx context.Context) {
	if n.cfg.Systemd == nil {
		n.cycles.WithLabelValues(checkF2B, "gated").Inc()
		return
	}
	// Fail closed like coredns-stub: a failed existence probe counts
	// as present (the check still runs its other evidence — the
	// banned-metrics collector below does not need systemd), and a
	// failed is-active leaves the down-latch untouched rather than
	// entering or clearing it on a guess.
	exists, err := n.cfg.Systemd.Exists(ctx, "fail2ban.service")
	if err != nil {
		logger().Warn("nethealth: fail2ban existence probe failed — "+
			"treating unit as present this cycle (fail closed)",
			"unit", "fail2ban.service",
			"error", err)
		exists = true
	}
	if !exists {
		n.cycles.WithLabelValues(checkF2B, "gated").Inc()
		return
	}
	active, err := n.cfg.Systemd.Active(ctx, "fail2ban.service")
	serviceDown := false
	if err != nil {
		logger().Warn("nethealth: fail2ban is-active probe failed — "+
			"down-latch left unchanged this cycle (fail closed)",
			"unit", "fail2ban.service",
			"error", err)
	} else if !active {
		serviceDown = true
		n.state.SuspectLog(latchdefs.LatchFail2banDown,
			"suspect: fail2ban-down (unit exists but service inactive)",
			suspectLogCadence)
		n.state.Enter(latchdefs.LatchFail2banDown, "service=inactive")
		// A stopped jail protects nothing — restart it under the
		// last-fail2ban-restart budget (30m) instead of only latching.
		if n.state.RateOK("last-fail2ban-restart", f2bRestartInterval) {
			n.state.AppendLog("ACTION: restarting fail2ban.service - unit exists but service inactive")
			n.state.RateSpend("last-fail2ban-restart")
			if err := n.cfg.Systemd.Restart(ctx, "fail2ban.service"); err != nil {
				n.state.AppendLog(fmt.Sprintf("fail2ban.service restart failed: %v", err))
			} else {
				n.actions.WithLabelValues(checkF2B, "restart").Inc()
			}
		}
	} else {
		n.stateExit(latchdefs.LatchFail2banDown)
	}
	bannedFile := filepath.Join(n.cfg.WatchdogStateDir, "fail2ban-banned")
	if serviceDown {
		// Unit KNOWN-inactive: fail2ban-client can only fail — no
		// jails running means nothing is banned, so skip the fork
		// entirely and drop the series (absent, not stale). A failed
		// is-active probe (err != nil) still falls through to the
		// client call — the metrics path does not need systemd.
		n.removeFail2banBanned(bannedFile)
		n.cycles.WithLabelValues(checkF2B, "ok").Inc()
		return
	}

	var pairs []string
	resolved := false
	var bannedErr error
	if !n.f2bBannedUnsupported {
		out, err := n.cfg.runMountCmd(ctx, []string{"fail2ban-client", "banned"})
		bannedErr = err
		if err == nil {
			if p, ok := parseFail2banBanned(out); ok {
				pairs = p
				resolved = true
			}
		}
	}

	if !resolved {
		out, err := n.cfg.runMountCmd(ctx, []string{"fail2ban-client", "status"})
		if err != nil {
			// Client missing/failed → remove the metric file (no stale
			// series — absent, not 0). Do not latch f2bBannedUnsupported
			// when status also failed (daemon/socket may just be down).
			n.state.SuspectLog("fail2ban-client", fmt.Sprintf(
				"fail2ban: fail2ban-client status failed: %v (%s) — banned metrics dropped",
				err, trimRunErr(out)), suspectLogCadence)
			n.removeFail2banBanned(bannedFile)
			n.cycles.WithLabelValues(checkF2B, "ok").Inc()
			return
		}
		if bannedErr != nil {
			// `banned` errored while `status` succeeded → Fail2Ban < 0.11;
			// latch so subsequent cycles skip the failing `banned` fork.
			n.f2bBannedUnsupported = true
		}
		if m := jailListRe.FindStringSubmatch(out); m != nil {
			for j := range strings.SplitSeq(m[1], ",") {
				j = strings.TrimSpace(j)
				if j == "" {
					continue
				}
				cnt := "0"
				// runMountCmd (nsenter -t 1 -m -n) like the aggregate
				// call — fail2ban-client and its socket only exist on
				// the host, so runHostCmd (netns only) can never reach
				// them containerized and the jail silently read "0".
				st, err := n.cfg.runMountCmd(ctx,
					[]string{"fail2ban-client", "status", j})
				if err != nil {
					logger().Warn("nethealth: fail2ban per-jail status "+
						"failed — banned count reported as 0",
						"jail", j,
						"output", trimRunErr(st), "error", err)
				} else if b := bannedRe.FindStringSubmatch(st); b != nil {
					cnt = b[1]
				}
				pairs = append(pairs, j+"="+cnt)
			}
		}
	}

	if len(pairs) > 0 {
		n.writeFail2banBanned(bannedFile, strings.Join(pairs, " ")+"\n")
	} else {
		n.removeFail2banBanned(bannedFile)
	}
	n.cycles.WithLabelValues(checkF2B, "ok").Inc()
}

func (n *NetHealth) writeFail2banBanned(bannedFile, content string) {
	if n.f2bLastKnown && n.f2bLastPath == bannedFile && n.f2bLastContent == content {
		if _, err := os.Stat(bannedFile); err == nil {
			return
		}
	}
	// NoSync: fail2ban-banned is an ephemeral per-cycle metric file
	// rewritten next cycle if lost; tmp+rename atomicity prevents torn
	// reads without paying fsync + dirsync every cycle.
	if err := fsx.WriteFileAtomicNoSync(bannedFile, content); err != nil {
		logger().Warn("nethealth: fail2ban banned-count write "+
			"failed — node_fail2ban_banned_ips stale this cycle",
			"path", bannedFile,
			"error", err)
		n.f2bLastKnown = false
		return
	}
	n.f2bLastPath = bannedFile
	n.f2bLastContent = content
	n.f2bLastKnown = true
}

func (n *NetHealth) removeFail2banBanned(bannedFile string) {
	if n.f2bLastKnown && n.f2bLastPath == bannedFile && n.f2bLastContent == "" {
		return
	}
	err := os.Remove(bannedFile)
	if err == nil || os.IsNotExist(err) {
		n.f2bLastPath = bannedFile
		n.f2bLastContent = ""
		n.f2bLastKnown = true
		return
	}
	n.f2bLastKnown = false
}

// parseFail2banBanned parses `fail2ban-client banned` output in either
// Python repr() or JSON list-of-dicts format, e.g.:
// `[{'sshd': ['192.0.2.1', '192.0.2.2']}, {'recidive': []}]` or `[]`.
// Returns ok=false on empty or unparseable output so callers fall back
// to `fail2ban-client status`.
func parseFail2banBanned(out string) ([]string, bool) {
	p := f2bBannedParser{s: strings.TrimSpace(out)}
	if p.s == "" {
		return nil, false
	}
	pairs, ok := p.parseList()
	if !ok {
		return nil, false
	}
	p.skipWS()
	if p.i != len(p.s) {
		return nil, false
	}
	return pairs, true
}

type f2bBannedParser struct {
	s string
	i int
}

func (p *f2bBannedParser) skipWS() {
	for p.i < len(p.s) {
		r := rune(p.s[p.i])
		if r > 0x7f {
			break
		}
		if !unicode.IsSpace(r) {
			break
		}
		p.i++
	}
}

func (p *f2bBannedParser) consume(ch byte) bool {
	p.skipWS()
	if p.i < len(p.s) && p.s[p.i] == ch {
		p.i++
		return true
	}
	return false
}

func (p *f2bBannedParser) parseString() (string, bool) {
	p.skipWS()
	if p.i >= len(p.s) {
		return "", false
	}
	quote := p.s[p.i]
	if quote != '\'' && quote != '"' {
		return "", false
	}
	p.i++
	var b strings.Builder
	for p.i < len(p.s) {
		ch := p.s[p.i]
		p.i++
		if ch == quote {
			return b.String(), true
		}
		if ch == '\\' {
			if p.i >= len(p.s) {
				return "", false
			}
			esc := p.s[p.i]
			p.i++
			switch esc {
			case 'n':
				b.WriteByte('\n')
			case 't':
				b.WriteByte('\t')
			case 'r':
				b.WriteByte('\r')
			default:
				b.WriteByte(esc)
			}
			continue
		}
		b.WriteByte(ch)
	}
	return "", false
}

func (p *f2bBannedParser) parseStringListCount() (int, bool) {
	if !p.consume('[') {
		return 0, false
	}
	p.skipWS()
	if p.i < len(p.s) && p.s[p.i] == ']' {
		p.i++
		return 0, true
	}
	count := 0
	for {
		if _, ok := p.parseString(); !ok {
			return 0, false
		}
		count++
		p.skipWS()
		if p.i >= len(p.s) {
			return 0, false
		}
		switch p.s[p.i] {
		case ',':
			p.i++
			p.skipWS()
			if p.i < len(p.s) && p.s[p.i] == ']' {
				p.i++
				return count, true
			}
		case ']':
			p.i++
			return count, true
		default:
			return 0, false
		}
	}
}

func (p *f2bBannedParser) parseList() ([]string, bool) {
	if !p.consume('[') {
		return nil, false
	}
	p.skipWS()
	if p.i < len(p.s) && p.s[p.i] == ']' {
		p.i++
		return nil, true
	}
	var pairs []string
	for {
		if !p.consume('{') {
			return nil, false
		}
		p.skipWS()
		if p.i < len(p.s) && p.s[p.i] == '}' {
			p.i++
		} else {
			for {
				jail, ok := p.parseString()
				if !ok {
					return nil, false
				}
				if !p.consume(':') {
					return nil, false
				}
				cnt, ok := p.parseStringListCount()
				if !ok {
					return nil, false
				}
				if jail != "" {
					pairs = append(pairs, jail+"="+strconv.Itoa(cnt))
				}
				p.skipWS()
				if p.i >= len(p.s) {
					return nil, false
				}
				if p.s[p.i] == ',' {
					p.i++
					p.skipWS()
					if p.i < len(p.s) && p.s[p.i] == '}' {
						p.i++
						break
					}
					continue
				}
				if p.s[p.i] == '}' {
					p.i++
					break
				}
				return nil, false
			}
		}
		p.skipWS()
		if p.i >= len(p.s) {
			return nil, false
		}
		switch p.s[p.i] {
		case ',':
			p.i++
			p.skipWS()
			if p.i < len(p.s) && p.s[p.i] == ']' {
				p.i++
				return pairs, true
			}
		case ']':
			p.i++
			return pairs, true
		default:
			return nil, false
		}
	}
}
