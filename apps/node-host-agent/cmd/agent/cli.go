// cli.go — multi-call subcommand dispatch. The binary is also copied
// to /concourse-runc/runc by the concourse worker init, so argv[0]
// selects the runc wrapper directly; everything else is argv[1].
// Dispatch runs BEFORE flag.Parse so daemon flags stay untouched.
package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"log/slog"
	"net"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"syscall"
	"time"

	"golang.org/x/crypto/ssh"

	"github.com/passiontech-global/kubernetes-node-automation/apps/node-host-agent/internal/ops/concourseinit"
	"github.com/passiontech-global/kubernetes-node-automation/apps/node-host-agent/internal/ops/etcdrescue"
	"github.com/passiontech-global/kubernetes-node-automation/apps/node-host-agent/internal/ops/evpurge"
	"github.com/passiontech-global/kubernetes-node-automation/apps/node-host-agent/internal/platform/topology"
	"github.com/passiontech-global/kubernetes-node-automation/apps/node-host-agent/internal/subsystem/hostconfig"
	"github.com/passiontech-global/kubernetes-node-automation/apps/node-host-agent/internal/subsystem/hostmetrics"
	"github.com/passiontech-global/kubernetes-node-automation/apps/node-host-agent/internal/subsystem/kinedb"
)

// dispatch runs a subcommand selected by argv[0]/argv[1] and returns
// (exitCode, true) when one handled the invocation; (0, false) means
// "not a subcommand — run the daemon" (argv[1] absent or a flag).
func dispatch(argv []string) (int, bool) {
	if len(argv) == 0 {
		return 0, false
	}
	// /concourse-runc/runc is a copy of this binary exec'd by
	// containerd-shim — argv[0] selects the wrapper.
	if filepath.Base(argv[0]) == "runc" {
		return concourseinit.RuncWrapper(), true
	}
	if len(argv) < 2 || strings.HasPrefix(argv[1], "-") {
		return 0, false
	}
	ctx, stop := signal.NotifyContext(context.Background(),
		syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	switch argv[1] {
	case "concourse-worker-init":
		return concourseWorkerInit(ctx, argv[2:]), true
	case "concourse-runc-wrapper":
		// The subcommand word is not part of the runc argv — the
		// wrapper forwards argv[1:] to runc.real.
		runcArgv := append([]string{argv[0]}, argv[2:]...)
		return concourseinit.RunRuncWrapper(runcArgv, os.Environ()), true
	case "converge-once":
		return convergeOnce(ctx, argv[2:]), true
	case "nebula-sign":
		return nebulaSignCmd(ctx, argv[2:]), true
	case "purge-events":
		return purgeEventsCmd(ctx, argv[2:]), true
	case "check-kine-db":
		return checkKineDBCmd(ctx, argv[2:]), true
	case "check-k0s-drift":
		return checkK0sDriftCmd(argv[2:]), true
	case "rescue-etcd":
		return rescueEtcdCmd(ctx, argv[2:]), true
	default:
		subcommandUsage(argv[1])
		return 2, true
	}
}

// subcommandUsage prints the dispatch table for an unknown word.
func subcommandUsage(word string) {
	fmt.Fprintf(os.Stderr, `unknown subcommand %q

usage:
  node-host-agent [daemon flags]            run the agent daemon
  node-host-agent concourse-worker-init [--work-dir=DIR] [--runc-dir=DIR] [--runc-source=PATH] [--wrapper-source=PATH]
                                            concourse worker init-rm (init container)
  node-host-agent concourse-runc-wrapper    runc shim (argv[0] "runc" works too)
  node-host-agent converge-once --vars-dir=DIR [--node-name=N] [--nebula-certs-dir=DIR]
                                            one hostconfig converge on the host, then exit
  node-host-agent nebula-sign --vars-dir=DIR --ca-dir=DIR [--node=N] [--duration=8760h] [--ssh-key=PATH]
                                            sign interdc nebula host certs with the local CA
  node-host-agent purge-events [--api=URL] [--ca=FILE] [--cert=FILE] [--key=FILE] [--workers=N] [--before=TS | RFC3339]
                                            delete apiserver events older than the cutoff (etcd backlog GC)
  node-host-agent check-kine-db [--env-file=FILE] [--wire-addr=HOST:PORT] [--runtime=podman|docker]
                                            verify the kine postgres+pgbouncer stack (exit 1 on any FAIL)
  node-host-agent check-k0s-drift [--config=FILE] [--expected-keys=a,b] [--removed-flags=x,y] [--unit-file=FILE]
                                            report k0s.yaml extraArgs drift (removed-flag/extra-key/missing-key)
  node-host-agent rescue-etcd [--k0s-dir=DIR] [--endpoint=URL] [--force-offline]
                                            rescue a k0s etcd at backend quota
                                            (compact -> online defrag -> offline defrag -> alarm disarm -> canary)
`, word)
}

// concourseWorkerInit is the init-rm subcommand: the flags map onto
// concourseinit.Config's path knobs so the container invocation can
// point at its mounts (`--wrapper-source=/usr/local/bin/node-host-agent`
// self-installs the agent as the runc wrapper even when argv[0]
// resolves elsewhere).
func concourseWorkerInit(ctx context.Context, args []string) int {
	fs := flag.NewFlagSet("concourse-worker-init", flag.ContinueOnError)
	fs.SetOutput(os.Stderr)
	workDir := fs.String("work-dir", "",
		"concourse work dir to soft-reset (default "+concourseinit.DefaultWorkDir+")")
	runcDir := fs.String("runc-dir", "",
		"emptyDir shared with the worker holding runc + runc.real (default "+
			concourseinit.DefaultRuncDir+")")
	runcSource := fs.String("runc-source", "",
		"the image's real runc, copied to <runc-dir>/runc.real (default "+
			concourseinit.DefaultRuncSource+")")
	wrapperSource := fs.String("wrapper-source", "",
		"binary installed as <runc-dir>/runc — the multi-call agent "+
			"(default: os.Executable)")
	if err := fs.Parse(args); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return 0 // -h/--help is a clean exit, not a usage error
		}
		return 2
	}
	if err := concourseinit.WorkerInit(ctx, concourseinit.Config{
		WorkDir:       *workDir,
		RuncDir:       *runcDir,
		RuncSource:    *runcSource,
		WrapperSource: *wrapperSource,
	}); err != nil {
		fmt.Fprintln(os.Stderr, "concourse-worker-init:", err)
		return 1
	}
	return 0
}

// convergeHostRoot/convergeRunner wire the production standalone
// contract ("/" + DirectRunner) — tests stub both to run a scripted
// converge against a tempdir host root instead of exec'ing real
// host commands.
var (
	convergeHostRoot = "/"
	convergeRunner   = func() hostconfig.Runner { return hostconfig.DirectRunner{} }
)

// convergeOnce runs exactly one hostconfig cycle on the host — the
// systemd timer / manual "converge now" entrypoint for standalone
// targets (DirectRunner: already inside the host namespaces).
func convergeOnce(ctx context.Context, args []string) int {
	fs := flag.NewFlagSet("converge-once", flag.ContinueOnError)
	fs.SetOutput(os.Stderr)
	varsDir := fs.String("vars-dir",
		getenv("NODE_HOST_AGENT_HOSTCONFIG_VARS_DIR", "/etc/node-host-agent/vars"),
		"vars dir holding defaults.yaml/cluster.yaml/interdc_nodes.yaml")
	nodeName := fs.String("node-name",
		getenv("NODE_HOST_AGENT_NODE_NAME", getenv("NODE_NAME", "")),
		"registry node name (default: OS hostname)")
	certsDir := fs.String("nebula-certs-dir",
		getenv("NODE_HOST_AGENT_NEBULA_CERTS_DIR", "/etc/node-host-agent/nebula-certs"),
		"nebula cert dir (hubsync pushes to /etc/node-host-agent/nebula-certs)")
	if err := fs.Parse(args); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return 0 // -h/--help is a clean exit, not a usage error
		}
		return 2
	}

	hostname, _ := os.Hostname()
	nn := *nodeName
	if nn == "" {
		nn = hostname
	}
	hc, err := hostconfig.New(hostconfig.Config{
		Enabled:        true,
		NodeName:       nn,
		Hostname:       hostname,
		HostRoot:       convergeHostRoot,
		VarsDir:        *varsDir,
		NebulaCertsDir: *certsDir,
		Runner:         convergeRunner(),
	}, nil)
	if err != nil {
		fmt.Fprintln(os.Stderr, "converge-once:", err)
		return 1
	}
	slog.Info("converge-once starting",
		"node", nn, "varsDir", *varsDir, "certsDir", *certsDir)
	// CycleWithErrors counts topology/vars failures, group
	// write/command errors and panics — a non-zero count means the
	// converge did not fully apply, so the timer/CI caller gets a
	// non-zero exit (ansible failed_when parity).
	if errs := hc.CycleWithErrors(ctx); errs > 0 {
		slog.Error("converge-once finished with errors",
			"node", nn, "errors", errs)
		return 1
	}
	return 0
}

// --- nebula-sign: port of bootstrap/ansible/nebula/sign.yaml ---
//
// Signs one host cert per interdc registry node (or only --node) with
// the LOCAL CA — the private key never leaves the operator box.
// Pubkey source: registry `nebula_key:` (bare b64 or PEM), else
// /etc/nebula/<interdc_nebula_net>/host.pub fetched over SSH from the
// node (nodes keygen on-node — private key never leaves it either).

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

func nebulaSignCmd(ctx context.Context, args []string) int {
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
		var subs []string
		if ip != "" {
			subs = append(subs, ip+"/32")
		}
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
			os.RemoveAll(tmp)
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
			os.RemoveAll(tmp)
			return fmt.Errorf("%s: nebula-cert sign: %w\n%s", j.Hostname, err, out)
		}
		verify := exec.CommandContext(ctx, certBin, "verify",
			"-ca", caCrt, "-crt", crtPath)
		if out, err := verify.CombinedOutput(); err != nil {
			os.RemoveAll(tmp)
			return fmt.Errorf("%s: nebula-cert verify: %w\n%s", j.Hostname, err, out)
		}
		crt, err := os.ReadFile(crtPath)
		os.RemoveAll(tmp)
		if err != nil {
			return fmt.Errorf("%s: %w", j.Hostname, err)
		}
		dst := filepath.Join(cfg.VarsDir, "nebula-"+j.Name+".crt")
		tmpDst := dst + ".tmp"
		if err := os.WriteFile(tmpDst, crt, 0o644); err != nil {
			return fmt.Errorf("%s: %w", j.Hostname, err)
		}
		if err := os.Rename(tmpDst, dst); err != nil {
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
		if line == "" || strings.Contains(line, "BEGIN") ||
			strings.Contains(line, "END") {
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

// --- jinja value helpers (topology keeps its coercions unexported —
// same minimal shims hubsync carries) ---

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

// --- minimal SSH host.pub fetch ---
//
// hubsync's real dialer is package-private; the signer only needs a
// one-command fetch so it carries the smallest dialer: same key
// resolution (flag/env, default ~/.ssh/id_ed25519), same tolerance
// (InsecureIgnoreHostKey — infra VMs rotate host keys on rebuild),
// same ssh_proxyjump bastion semantics as hubsync's sshDialer.

func sshFetchHostPub(ctx context.Context, j signJob, nebulaNet, keyPath string) (string, error) {
	if j.IP == "" {
		return "", fmt.Errorf("no ip in registry")
	}
	keyPath = expandHome(keyPath)
	pem, err := os.ReadFile(keyPath)
	if err != nil {
		return "", fmt.Errorf("read ssh key %s: %w", keyPath, err)
	}
	signer, err := ssh.ParsePrivateKey(pem)
	if err != nil {
		return "", fmt.Errorf("parse ssh key %s: %w", keyPath, err)
	}
	user := j.SSHUser
	if user == "" {
		user = "root"
	}
	timeout := 15 * time.Second
	cfg := &ssh.ClientConfig{
		User:            user,
		Auth:            []ssh.AuthMethod{ssh.PublicKeys(signer)},
		HostKeyCallback: ssh.InsecureIgnoreHostKey(), //nolint:gosec // hub_converge parity
		Timeout:         timeout,
	}
	addr := net.JoinHostPort(j.IP, "22")

	var client *ssh.Client
	var jumpClient *ssh.Client
	if j.ProxyJump != "" {
		juser, jhost, jport := splitJump(j.ProxyJump)
		jcfg := &ssh.ClientConfig{
			User:            juser,
			Auth:            []ssh.AuthMethod{ssh.PublicKeys(signer)},
			HostKeyCallback: ssh.InsecureIgnoreHostKey(), //nolint:gosec
			Timeout:         timeout,
		}
		jc, err := dialSSH(ctx, net.JoinHostPort(jhost, jport), jcfg, timeout)
		if err != nil {
			return "", fmt.Errorf("jump %s: %w", j.ProxyJump, err)
		}
		jumpClient = jc
		defer jumpClient.Close()
		nc, err := jc.Dial("tcp", addr)
		if err != nil {
			return "", fmt.Errorf("jump %s -> %s: %w", j.ProxyJump, addr, err)
		}
		c, chans, reqs, err := ssh.NewClientConn(nc, addr, cfg)
		if err != nil {
			nc.Close()
			return "", fmt.Errorf("handshake via %s: %w", j.ProxyJump, err)
		}
		client = ssh.NewClient(c, chans, reqs)
	} else {
		client, err = dialSSH(ctx, addr, cfg, timeout)
		if err != nil {
			return "", err
		}
	}
	defer client.Close()

	sess, err := client.NewSession()
	if err != nil {
		return "", err
	}
	defer sess.Close()
	type result struct {
		out []byte
		err error
	}
	done := make(chan result, 1)
	go func() {
		out, err := sess.CombinedOutput(
			"cat /etc/nebula/" + nebulaNet + "/host.pub")
		done <- result{out, err}
	}()
	select {
	case <-ctx.Done():
		sess.Close()
		return "", ctx.Err()
	case r := <-done:
		if r.err != nil {
			return "", fmt.Errorf("read host.pub: %w (%s)", r.err,
				strings.TrimSpace(string(r.out)))
		}
		return string(r.out), nil
	}
}

func dialSSH(ctx context.Context, addr string, cfg *ssh.ClientConfig,
	timeout time.Duration) (*ssh.Client, error) {
	nd := net.Dialer{Timeout: timeout}
	nc, err := nd.DialContext(ctx, "tcp", addr)
	if err != nil {
		return nil, err
	}
	dl := time.Now().Add(timeout)
	if cdl, ok := ctx.Deadline(); ok && cdl.Before(dl) {
		dl = cdl
	}
	_ = nc.SetDeadline(dl)
	c, chans, reqs, err := ssh.NewClientConn(nc, addr, cfg)
	if err != nil {
		nc.Close()
		return nil, err
	}
	_ = nc.SetDeadline(time.Time{})
	return ssh.NewClient(c, chans, reqs), nil
}

// splitJump parses "user@host[:port]" / "host" from ssh_proxyjump —
// the same shape hubsync's splitUserHost accepts.
func splitJump(j string) (user, host, port string) {
	user, port = "root", "22"
	if u, h, ok := strings.Cut(j, "@"); ok {
		user, j = u, h
	}
	host = j
	if h, p, err := net.SplitHostPort(j); err == nil {
		host, port = h, p
	}
	return user, host, port
}

func expandHome(p string) string {
	if strings.HasPrefix(p, "~/") {
		if home, err := os.UserHomeDir(); err == nil {
			return filepath.Join(home, p[2:])
		}
	}
	return p
}

// --- purge-events: port of scripts/purge-events.py ---
//
// Bulk-deletes apiserver Events older than a cutoff through the
// k0s admin client certs — run as root ON a controller node. The
// cutoff is a flag (--before) or a bare positional RFC3339 arg, like
// the script's sys.argv[1]; the empty default is the script's
// "1970-01-01T00:00:00Z" (delete everything).
func purgeEventsCmd(ctx context.Context, args []string) int {
	fs := flag.NewFlagSet("purge-events", flag.ContinueOnError)
	fs.SetOutput(os.Stderr)
	api := fs.String("api", "https://127.0.0.1:6443", "apiserver base URL")
	ca := fs.String("ca", "",
		"CA bundle (default /var/lib/k0s/pki/ca.crt, fallback /var/lib/k0s/pki/etcd/ca.crt)")
	cert := fs.String("cert", "/var/lib/k0s/pki/admin.crt", "client certificate")
	key := fs.String("key", "/var/lib/k0s/pki/admin.key", "client key")
	workers := fs.Int("workers", 8,
		"parallel DELETE workers (drop to 2 on a weak cluster)")
	before := fs.String("before", "",
		"delete events created before this RFC3339 timestamp "+
			"(positional arg also accepted; default deletes everything)")
	if err := fs.Parse(args); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return 0 // -h/--help is a clean exit, not a usage error
		}
		return 2
	}
	cutStr := *before
	if cutStr == "" && fs.NArg() > 0 {
		cutStr = fs.Arg(0)
	}
	if cutStr == "" {
		cutStr = "1970-01-01T00:00:00Z"
	}
	cutoff, err := time.Parse(time.RFC3339, cutStr)
	if err != nil {
		fmt.Fprintf(os.Stderr, "purge-events: bad cutoff %q: %v\n", cutStr, err)
		return 2
	}
	if err := evpurge.Run(ctx, evpurge.Config{
		API:      *api,
		CAFile:   *ca,
		CertFile: *cert,
		KeyFile:  *key,
		Workers:  *workers,
	}, cutoff, os.Stdout); err != nil {
		fmt.Fprintln(os.Stderr, "purge-events:", err)
		return 1
	}
	return 0
}

// --- check-kine-db: port of scripts/check-kine-db.sh ---
//
// The operator-side verify after a postgres+pgbouncer stack update
// on the kine DB VM. Prints the script's OK/FAIL check lines and
// exits 1 on any failure.
func checkKineDBCmd(ctx context.Context, args []string) int {
	fs := flag.NewFlagSet("check-kine-db", flag.ContinueOnError)
	fs.SetOutput(os.Stderr)
	envFile := fs.String("env-file", "/opt/apps/postgres/.env",
		"postgres stack .env (POSTGRES_USER/POSTGRES_PASSWORD)")
	wireAddr := fs.String("wire-addr", "127.0.0.1:6432",
		"pgbouncer host:port for the wire probe")
	runtime := fs.String("runtime", "",
		"container runtime podman|docker (default: auto-detect)")
	if err := fs.Parse(args); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return 0 // -h/--help is a clean exit, not a usage error
		}
		return 2
	}
	return kinedb.RunCheckCLI(ctx, kinedb.Config{
		EnvFile:  *envFile,
		WireAddr: *wireAddr,
		Runtime:  *runtime,
	}, os.Stdout)
}

// --- check-k0s-drift: on-node half of scripts/check-node-config-drift.sh ---
//
// Reports removed-flag / extra-key / missing-key drift between the
// node's /etc/k0s/k0s.yaml controllerManager.extraArgs and the
// expected set. Exit 0 clean (or not a k0s controller), 1 on drift.
func checkK0sDriftCmd(args []string) int {
	fs := flag.NewFlagSet("check-k0s-drift", flag.ContinueOnError)
	fs.SetOutput(os.Stderr)
	config := fs.String("config", "/etc/k0s/k0s.yaml", "k0s config to scan")
	expected := fs.String("expected-keys", "",
		"comma-separated expected controllerManager.extraArgs keys "+
			"(default: the repo-pinned set)")
	removed := fs.String("removed-flags", "",
		"comma-separated config keys removed upstream "+
			"(default: concurrent-service-syncs)")
	unit := fs.String("unit-file", "/etc/systemd/system/k0scontroller.service",
		"k0s controller gate — the check only runs when this unit file "+
			"exists (point at /dev/null to force on a non-controller)")
	if err := fs.Parse(args); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return 0 // -h/--help is a clean exit, not a usage error
		}
		return 2
	}
	// Provided-vs-absent matters: --expected-keys= (explicit empty)
	// means "no expected keys" while a missing flag means "use the
	// repo-pinned default" — see K0sDriftConfig.
	provided := map[string]bool{}
	fs.Visit(func(f *flag.Flag) { provided[f.Name] = true })
	var exp, rem []string
	if provided["expected-keys"] {
		exp = splitCSV(*expected)
	}
	if provided["removed-flags"] {
		rem = splitCSV(*removed)
	}
	return hostmetrics.RunK0sDriftCLI(hostmetrics.K0sDriftConfig{
		ConfigFile:   *config,
		UnitFile:     *unit,
		ExpectedKeys: exp,
		RemovedFlags: rem,
	}, os.Stdout)
}

// --- rescue-etcd: port of scripts/rescue-etcd.sh ---
//
// Rescues a k0s controller etcd that hit the backend quota — run as
// root ON the controller. Compact -> online defrag -> offline defrag
// when the online pass reclaims nothing (or --force-offline) ->
// alarm disarm -> write canary.
func rescueEtcdCmd(ctx context.Context, args []string) int {
	fs := flag.NewFlagSet("rescue-etcd", flag.ContinueOnError)
	fs.SetOutput(os.Stderr)
	k0sDir := fs.String("k0s-dir", "/var/lib/k0s",
		"k0s data dir (derives bin/etcd*, pki/ cert paths)")
	endpoint := fs.String("endpoint", "https://127.0.0.1:2379",
		"etcd client endpoint")
	forceOffline := fs.Bool("force-offline", false,
		"skip the online defrag attempt, go straight to offline defrag")
	if err := fs.Parse(args); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return 0 // -h/--help is a clean exit, not a usage error
		}
		return 2
	}
	if err := etcdrescue.Run(ctx, etcdrescue.Config{
		K0sDir:       *k0sDir,
		Endpoint:     *endpoint,
		ForceOffline: *forceOffline,
	}, os.Stdout); err != nil {
		fmt.Fprintln(os.Stderr, "rescue-etcd:", err)
		return 1
	}
	return 0
}

// splitCSV splits a comma-separated flag value, trimming spaces and
// dropping empty elements. Empty input yields an empty NON-nil
// slice — callers distinguish "flag absent" (nil -> defaults) from
// "flag provided empty" (empty set honored).
func splitCSV(s string) []string {
	out := []string{}
	for _, p := range strings.Split(s, ",") {
		if p = strings.TrimSpace(p); p != "" {
			out = append(out, p)
		}
	}
	return out
}
