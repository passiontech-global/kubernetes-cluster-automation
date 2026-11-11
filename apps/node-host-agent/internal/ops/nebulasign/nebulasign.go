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
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"

	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-host-agent/internal/domain/topology"
	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-host-agent/internal/envnames"
	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-host-agent/internal/ops/opsx"
	"github.com/passiontech-global/kubernetes-cluster-automation/libs/hostkit/envx"
	"github.com/passiontech-global/kubernetes-cluster-automation/libs/hostkit/fsx"
	"github.com/passiontech-global/kubernetes-cluster-automation/libs/jinja"
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
	fs := opsx.FlagSet("nebula-sign")
	varsDir := opsx.VarsDirFlag(fs)
	caDir := fs.String("ca-dir", "",
		"directory holding ca.crt + ca.key (required — backup/nebula-ca)")
	only := fs.String("node", "",
		"sign only this registry node (interdc_nodes.yaml key)")
	duration := fs.String("duration", "8760h", "cert validity (1y; CA renews at 10y)")
	sshKey := fs.String("ssh-key",
		envx.String(envnames.EnvConvergeSSHKey, "~/.ssh/id_ed25519"),
		"SSH private key for the host.pub fetch fallback")
	if code, ok := opsx.Parse(fs, args); !ok {
		return code
	}
	if *caDir == "" {
		fmt.Fprintln(os.Stderr, "nebula-sign: --ca-dir is required")
		fs.Usage()
		return opsx.ExitUsage
	}
	cfg := signConfig{
		VarsDir: *varsDir, CaDir: *caDir, Node: *only,
		Duration: *duration, SSHKey: *sshKey,
	}
	if err := nebulaSign(ctx, cfg); err != nil {
		fmt.Fprintln(os.Stderr, "nebula-sign:", err)
		return opsx.ExitRuntime
	}
	return opsx.ExitOK
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
	// bySite is an arbitrary resolved value, not a key read — box it
	// into a one-key OMap so StrMap's flatten/empty-non-nil semantics
	// apply unchanged.
	bySiteBox := jinja.NewOMap()
	bySiteBox.Set("by_site", t.Vars.Get("interdc_ssh_user_by_site"))
	bySite := bySiteBox.StrMap("by_site")

	var jobs []signJob
	var badNodes []string
	for _, k := range t.Nodes.Keys() {
		if only != "" && k != only {
			continue
		}
		nv, _ := t.Nodes.Get(k)
		om, _ := nv.(*jinja.OMap)
		if om == nil {
			continue
		}
		ip := om.Str("ip")
		octet := om.Str("marker_octet")
		if octet == "" {
			octet = topology.LastOctet(ip)
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
		for _, r := range om.Slice("relay") {
			var rip string
			if rm, ok := r.(*jinja.OMap); ok {
				rip = rm.Str("ip")
			} else {
				rip = jstr(r)
			}
			if rip != "" {
				subs = append(subs, rip+"/32")
			}
		}
		user := om.Str("ssh_user")
		if user == "" {
			if u := bySite[om.Str("site")]; u != "" {
				user = u
			} else {
				user = defUser
			}
		}
		name := om.Str("name")
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
			Subnets:   strings.Join(topology.UniqSorted(subs), ","),
			Pub:       stripPubArmor(om.Str("nebula_key")),
			IP:        ip,
			SSHUser:   user,
			ProxyJump: om.Str("ssh_proxyjump"),
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
		// fsx.WriteFile: same-dir staging (the historical fixed
		// <dst>.tmp shape, kept verbatim), mode forced before the
		// sync+rename, payload fsync before the rename, staging file
		// swept on every failure — the tmp+chmod+fsync+rename ladder
		// this block hand-rolled. No DirSync: the original never
		// fsynced the dir, and raising that here would be a
		// durability drift, not a dedup.
		if err := fsx.WriteFile(dst, crt, fsx.Opts{
			Mode: 0o644,
			Stage: func(dir string) (*os.File, error) {
				return os.Create(dst + ".tmp")
			},
		}); err != nil {
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

// --- jinja value helpers ---
//
// omStr/omList/jstrMap are gone: the typed getters on *jinja.OMap
// (Str/Slice/StrMap) are that family's single home now, and this
// package's call sites read through them directly. jstr stays only
// for the bare-relay-entry coercion below — a list element (any),
// not an OMap key read, so no OMap method covers it.

// jstr coerces a resolved template var to its string form. string /
// int64 / float64 keep their dedicated formatting, bool keeps
// true→"true" / false→"" (the flag-off renders empty, the difference
// from hubsync's strOf). Everything else NON-NIL that is not a
// container prints via fmt: a hubsign host/port var can arrive in
// any JSON-decode kind (int, uint64, json.Number … depending on the
// decode path) and must render its value — the old fallthrough
// silently rendered "" and wrote an empty host/port into the signed
// config instead of failing visibly. Containers (maps/slices,
// including the jinja OMap/List wrappers — flattening a whole map
// into one string was never meaningful) and nil still render "".
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
		return ""
	case nil, map[string]any, []any, *jinja.OMap, *jinja.List:
		return ""
	}
	return fmt.Sprint(v)
}
