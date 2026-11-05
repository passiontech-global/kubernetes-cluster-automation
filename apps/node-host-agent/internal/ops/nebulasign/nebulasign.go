// Package nebulasign ports bootstrap/ansible/nebula/sign.yaml —
// signs one host cert per interdc registry node (or only --node)
// with the LOCAL CA; the private key never leaves the operator box.
//
// Pubkey source: registry `nebula_key:` (bare b64 or PEM), else
// /etc/nebula/<interdc_nebula_net>/host.pub fetched over SSH from the
// node (nodes keygen on-node — private key never leaves it either).
//
// cmd/agent wires this as the `nebula-sign` subcommand via Cmd.
package nebulasign

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strconv"
	"strings"

	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-host-agent/internal/platform/topology"
)

// signJob is one cert request, mirroring sign.yaml's nebula_sign_jobs
// entries: hostname is the registry key, name the cert name.
type signJob struct {
	Hostname string
	Name     string
	IPCIDR   string // marker/24 — the nebula cert IP
	Subnets  string // unsafe-route subnets: ip/32 + relay ips/32 (csv, sorted)
	Pub      string // bare base64 X25519 pubkey ("" until resolved)

	// SSH lookup fields — only used when Pub is empty.
	IP        string
	SSHUser   string
	ProxyJump string
}

// signConfig carries the nebula-sign inputs (flags resolved).
type signConfig struct {
	VarsDir  string
	CaDir    string
	Node     string // registry key filter; "" = every registry node
	Duration string
	SSHKey   string
}

// Cmd is the `nebula-sign` subcommand entrypoint: flag parsing +
// dispatch, returning the process exit code (0 clean, 1 runtime
// failure, 2 usage error — same contract as the other ops subcommands).
func Cmd(ctx context.Context, args []string) int {
	fs := flag.NewFlagSet("nebula-sign", flag.ContinueOnError)
	fs.SetOutput(os.Stderr)
	varsDir := fs.String("vars-dir",
		getenv("NODE_HOST_AGENT_HOSTCONFIG_VARS_DIR", "/etc/node-host-agent/vars"),
		"vars dir holding cluster.yaml/interdc_nodes.yaml; nebula-<name>.crt lands here")
	caDir := fs.String("ca-dir", "",
		"directory holding ca.crt + ca.key (required — backup/nebula-ca)")
	only := fs.String("node", "",
		"sign only this registry node (interdc_nodes.yaml key)")
	duration := fs.String("duration", "8760h", "cert validity (1y; CA renews at 10y)")
	sshKey := fs.String("ssh-key",
		getenv("NODE_HOST_AGENT_CONVERGE_SSH_KEY", "~/.ssh/id_ed25519"),
		"SSH private key for the host.pub fetch fallback")
	if err := fs.Parse(args); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return 0 // -h/--help is a clean exit, not a usage error
		}
		return 2
	}
	if *caDir == "" {
		fmt.Fprintln(os.Stderr, "nebula-sign: --ca-dir is required")
		fs.Usage()
		return 2
	}
	cfg := signConfig{
		VarsDir: *varsDir, CaDir: *caDir, Node: *only,
		Duration: *duration, SSHKey: *sshKey,
	}
	if err := nebulaSign(ctx, cfg); err != nil {
		fmt.Fprintln(os.Stderr, "nebula-sign:", err)
		return 1
	}
	return 0
}

// getenv mirrors cmd/agent's env-or-default helper — the flag
// defaults keep reading the same NODE_HOST_AGENT_* envs.
func getenv(key, def string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return def
}

func nebulaSign(ctx context.Context, cfg signConfig) error {
	certBin, err := exec.LookPath("nebula-cert")
	if err != nil {
		return fmt.Errorf("nebula-cert not found in PATH: %w", err)
	}
	for _, f := range []string{"ca.crt", "ca.key"} {
		if _, err := os.Stat(filepath.Join(cfg.CaDir, f)); err != nil {
			return fmt.Errorf("missing %s in %s — the CA key is read "+
				"from backup/ (gitignored), it never enters git: %w",
				f, cfg.CaDir, err)
		}
	}
	t, err := topology.Load(topology.Config{VarsDir: cfg.VarsDir})
	if err != nil {
		return fmt.Errorf("load vars: %w", err)
	}
	jobs, err := buildSignJobs(t, cfg.Node)
	if err != nil {
		return err
	}
	// Resolve missing pubkeys (registry nebula_key → SSH host.pub
	// fetch), then fail EARLY listing every node still missing one —
	// sign.yaml's assert ran before any nebula-cert exec.
	nebulaNet := t.Vars.Str("interdc_nebula_net")
	if nebulaNet == "" {
		nebulaNet = "interdc"
	}
	// nebulaNet interpolates into a remote root shell command — it
	// is vars-derived, so gate it to a safe alphabet.
	if !nebulaNetRe.MatchString(nebulaNet) {
		return fmt.Errorf("invalid interdc_nebula_net %q — only "+
			"[A-Za-z0-9_-] is allowed", nebulaNet)
	}
	for i := range jobs {
		if jobs[i].Pub != "" {
			continue
		}
		pub, err := sshFetchHostPub(ctx, jobs[i], nebulaNet, cfg.SSHKey)
		if err != nil {
			fmt.Fprintf(os.Stderr,
				"nebula-sign: host.pub fetch failed for %s (%s): %v\n",
				jobs[i].Hostname, jobs[i].IP, err)
			continue
		}
		jobs[i].Pub = stripPubArmor(pub)
	}
	var missing []string
	for _, j := range jobs {
		if j.Pub == "" {
			missing = append(missing, fmt.Sprintf("%s (%s)", j.Hostname, j.Name))
		}
	}
	if len(missing) > 0 {
		return fmt.Errorf("missing nebula pubkey for %s — the node must "+
			"have keygen'd on-node (or be reachable over SSH); commit its "+
			"pubkey to the registry `nebula_key:` and retry",
			strings.Join(missing, ", "))
	}
	return signAll(ctx, certBin, cfg, jobs)
}

// buildSignJobs computes the cert request per registry node — the
// set_fact block of sign.yaml: marker = marker_base.marker_octet|ip
// last octet, subnets = ip/32 + each relay ip/32 (unique+sorted).
// Jobs are returned in registry order; --node filters by registry key.
func buildSignJobs(t *topology.Topology, only string) ([]signJob, error) {
	base := t.Vars.Str("interdc_marker_base")
	if base == "" || base == "None" {
		base = "172.29.0"
	}
	defUser := t.Vars.Str("interdc_ssh_default_user")
	if defUser == "" {
		defUser = "root"
	}
	bySite := jstrMap(t.Vars.Get("interdc_ssh_user_by_site"))

	var jobs []signJob
	var badNodes []string
	for _, k := range t.Nodes.Keys() {
		if only != "" && k != only {
			continue
		}
		nv, _ := t.Nodes.Get(k)
		om, _ := nv.(*topology.OMap)
		if om == nil {
			continue
		}
		ip := omStr(om, "ip")
		octet := omStr(om, "marker_octet")
		if octet == "" {
			octet = lastOctet(ip)
		}
		// ip feeds Subnets and the SSH fallback, octet feeds
		// IPCIDR — an empty one would produce "172.29.0./24" or
		// -subnets "" and fail opaquely inside nebula-cert, so
		// report the missing fields per node upfront instead.
		var missingFields []string
		if ip == "" {
			missingFields = append(missingFields, "ip")
		}
		if octet == "" {
			missingFields = append(missingFields, "marker_octet")
		}
		if len(missingFields) > 0 {
			badNodes = append(badNodes, fmt.Sprintf("%s (missing %s)",
				k, strings.Join(missingFields, ", ")))
			continue
		}
		subs := []string{ip + "/32"}
		for _, r := range omList(om, "relay") {
			var rip string
			if rm, ok := r.(*topology.OMap); ok {
				rip = omStr(rm, "ip")
			} else {
				rip = jstr(r)
			}
			if rip != "" {
				subs = append(subs, rip+"/32")
			}
		}
		user := omStr(om, "ssh_user")
		if user == "" {
			if u := bySite[omStr(om, "site")]; u != "" {
				user = u
			} else {
				user = defUser
			}
		}
		name := omStr(om, "name")
		if name == "" {
			name = k
		}
		// The name lands in <varsDir>/nebula-<name>.crt — a registry
		// entry carrying '/', '\' or '..' would path-traverse out.
		if strings.ContainsAny(name, `/\`) ||
			strings.Contains(name, "..") {
			return nil, fmt.Errorf("node %s: cert name %q must not "+
				"contain path separators or \"..\"", k, name)
		}
		jobs = append(jobs, signJob{
			Hostname:  k,
			Name:      name,
			IPCIDR:    base + "." + octet + "/24",
			Subnets:   strings.Join(uniqSortedStrings(subs), ","),
			Pub:       stripPubArmor(omStr(om, "nebula_key")),
			IP:        ip,
			SSHUser:   user,
			ProxyJump: omStr(om, "ssh_proxyjump"),
		})
	}
	if len(badNodes) > 0 {
		return nil, fmt.Errorf("interdc_nodes.yaml nodes missing "+
			"required fields: %s", strings.Join(badNodes, ", "))
	}
	if only != "" && len(jobs) == 0 {
		return nil, fmt.Errorf("node %q not in interdc_nodes.yaml registry", only)
	}
	return jobs, nil
}

// signAll runs `nebula-cert sign` + `verify` per job in a per-node
// tmp dir and writes <varsDir>/nebula-<name>.crt (0644) — the
// `command` + `copy` loop of sign.yaml.
func signAll(ctx context.Context, certBin string, cfg signConfig, jobs []signJob) error {
	for _, j := range jobs {
		if err := ctx.Err(); err != nil {
			return err
		}
		tmp, err := os.MkdirTemp("", "nebula-sign-")
		if err != nil {
			return err
		}
		pubPath := filepath.Join(tmp, "host.pub")
		crtPath := filepath.Join(tmp, "host.crt")
		pemPub := "-----BEGIN NEBULA X25519 PUBLIC KEY-----\n" + j.Pub +
			"\n-----END NEBULA X25519 PUBLIC KEY-----\n"
		if err := os.WriteFile(pubPath, []byte(pemPub), 0o600); err != nil {
			_ = os.RemoveAll(tmp)
			return fmt.Errorf("%s: %w", j.Hostname, err)
		}
		caCrt := filepath.Join(cfg.CaDir, "ca.crt")
		caKey := filepath.Join(cfg.CaDir, "ca.key")
		sign := exec.CommandContext(ctx, certBin, "sign",
			"-ca-crt", caCrt, "-ca-key", caKey,
			"-in-pub", pubPath, "-name", j.Name,
			"-ip", j.IPCIDR, "-subnets", j.Subnets,
			"-duration", cfg.Duration, "-out-crt", crtPath)
		if out, err := sign.CombinedOutput(); err != nil {
			_ = os.RemoveAll(tmp)
			return fmt.Errorf("%s: nebula-cert sign: %w\n%s", j.Hostname, err, out)
		}
		verify := exec.CommandContext(ctx, certBin, "verify",
			"-ca", caCrt, "-crt", crtPath)
		if out, err := verify.CombinedOutput(); err != nil {
			_ = os.RemoveAll(tmp)
			return fmt.Errorf("%s: nebula-cert verify: %w\n%s", j.Hostname, err, out)
		}
		crt, err := os.ReadFile(crtPath)
		_ = os.RemoveAll(tmp)
		if err != nil {
			return fmt.Errorf("%s: %w", j.Hostname, err)
		}
		dst := filepath.Join(cfg.VarsDir, "nebula-"+j.Name+".crt")
		tmpDst := dst + ".tmp"
		if err := os.WriteFile(tmpDst, crt, 0o644); err != nil {
			_ = os.Remove(tmpDst)
			return fmt.Errorf("%s: %w", j.Hostname, err)
		}
		if err := os.Rename(tmpDst, dst); err != nil {
			_ = os.Remove(tmpDst)
			return fmt.Errorf("%s: %w", j.Hostname, err)
		}
		fmt.Fprintf(os.Stderr, "nebula-sign: signed %s (%s) -> %s\n",
			j.Hostname, j.Name, dst)
	}
	return nil
}

// stripPubArmor normalizes a pubkey to bare base64: PEM armor lines
// and all whitespace are dropped (sign.yaml's reject(BEGIN|END)+join).
// Handles a bare b64 string, a full PEM block, and the b64decode'd
// host.pub slurp — all produce the same output.
func stripPubArmor(s string) string {
	var b strings.Builder
	for _, line := range strings.Split(s, "\n") {
		line = strings.TrimSpace(line)
		// Armor lines start with "-----" (-----BEGIN/END ...-----).
		// Base64 content can legitimately contain "BEGIN"/"END" as
		// substrings, so match the armor prefix — never Contains.
		if line == "" || strings.HasPrefix(line, "-----") {
			continue
		}
		b.WriteString(line)
	}
	return b.String()
}

func lastOctet(ip string) string {
	if i := strings.LastIndex(ip, "."); i >= 0 {
		return ip[i+1:]
	}
	return ip
}

func uniqSortedStrings(in []string) []string {
	seen := map[string]bool{}
	var out []string
	for _, x := range in {
		if !seen[x] {
			seen[x] = true
			out = append(out, x)
		}
	}
	sort.Strings(out)
	return out
}

// --- jinja value helpers ---
//
// topology keeps its coercions unexported; hubsync carries the same
// minimal shims (strOf/strMap/omStr/omBool in targets.go). The copies
// are NOT identical — jstr/jstrMap/omStr here coerce bool → "true"
// where hubsync's strOf/strMap/omStr drop it — so the shims stay
// per-package rather than being exported from topology.

func jstr(v any) string {
	switch t := v.(type) {
	case string:
		return t
	case int64:
		return strconv.FormatInt(t, 10)
	case float64:
		return strconv.FormatFloat(t, 'f', -1, 64)
	case bool:
		if t {
			return "true"
		}
	}
	return ""
}

func omStr(m *topology.OMap, key string) string {
	v, ok := m.Get(key)
	if !ok {
		return ""
	}
	return jstr(v)
}

func omList(m *topology.OMap, key string) []any {
	v, ok := m.Get(key)
	if !ok {
		return nil
	}
	switch t := v.(type) {
	case []any:
		return t
	case *topology.List:
		return t.V
	}
	return nil
}

func jstrMap(v any) map[string]string {
	out := map[string]string{}
	if om, ok := v.(*topology.OMap); ok && om != nil {
		for _, k := range om.Keys() {
			vv, _ := om.Get(k)
			out[k] = jstr(vv)
		}
	}
	return out
}
