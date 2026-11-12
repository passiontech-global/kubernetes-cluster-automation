// group_etcdctl.go — hub_converge.yaml etcd/kine splits: the pinned
// etcdctl binary for embedded-etcd controllers and the Phase-3
// kine.service split-out (own cgroup boundary so a kine OOM cannot
// drag the apiserver down).
package hostconfig

import (
	"net"
	"os"
	pathpkg "path"
	"path/filepath"
	"slices"
	"strings"
)

// ---------- etcdctl (embedded-etcd controllers) ----------
//
// k0s extracts etcd into /var/lib/k0s/bin but does NOT ship etcdctl —
// and both consumers look for it THERE, not in /usr/local/bin:
// controllerhygiene's checkEtcdQuota gates on <K0sDir>/bin/etcdctl +
// pki/etcd/ca.crt (result="no_etcdctl" on cicd's controller today) and
// the rescue-etcd subcommand execs the same path. So the managed
// binary goes to <k0s>/bin/etcdctl — pinning it in /usr/local/bin
// would not re-enable the guard.
//
// Version MUST match the etcd k0s bundles — k0s.default ->
// embedded-bins/Makefile.variables etcd_version in the fluxcd repo
// (k0s v1.37.1+k0s.0 -> etcd 3.7.3). Pins: etcdctl_version +
// etcdctl_tgz_{url,sha256,file} in defaults.yaml (synced from
// versions.yaml pins.etcdctl-tgz — sha256 of the release tarball, not
// of the extracted binary).
//
// Gate: only hosts running embedded etcd — k0scontroller.service
// exists AND pki/etcd/ca.crt is present (the same composite
// checkEtcdQuota requires). Kine-split controllers carry the unit but
// not the pki dir, so they are left alone; workers and infra VMs are
// never touched.
func (c *cyc) groupEtcdctl() {
	if !c.controller() ||
		!c.r.fileExists("/var/lib/k0s/pki/etcd/ca.crt") {
		return
	}
	c.etcdctlInstallBinary()
}

// etcdctlInstallBinary ports the nebula/coredns managed-binary
// pattern through installManagedBinary: <bin> version probe ->
// sha256-pinned tarball (staged or downloaded) -> untarInstall
// (tmp+rename).
func (c *cyc) etcdctlInstallBinary() {
	ver := c.t.Vars.StrDef("etcdctl_version", "")
	sum := c.t.Vars.StrDef("etcdctl_tgz_sha256", "")
	url := c.t.Vars.StrDef("etcdctl_tgz_url", "")
	tgz := defStr(c.v("etcdctl_tgz_file"), pathpkg.Base(url))
	if ver == "" || url == "" || sum == "" {
		c.err("etcdctl: missing etcdctl_version+etcdctl_tgz_{url,sha256} pins — not converging")
		return
	}
	bin := "/var/lib/k0s/bin/etcdctl"
	c.installManagedBinary(managedBinarySpec{
		name:     "etcdctl",
		artifact: "tgz",
		probe: func(c *cyc) bool {
			out, err := c.r.run(c.ctx, bin, "version")
			return err == nil && strings.Contains(out, ver)
		},
		url:    url,
		sum:    sum,
		staged: filepath.Join(c.r.cfg.DownloadDir, tgz),
		// same contract as T5b/T9: verify the STAGED file every run —
		// a corrupted/operator-swapped tarball must not install.
		refuseBadStaged: true,
		downloadLine:    "etcdctl: tgz download",
		prepare: func(c *cyc) bool {
			// /var/lib/k0s/bin exists on every k0s host, but
			// untarInstall does not create parents — keep the install
			// self-contained.
			if err := c.r.ensureDir("/var/lib/k0s/bin", 0o755); err != nil {
				// ensureDir already counted the failure via noteErr —
				// log context only, do not count the same fault twice.
				logger().Error("etcdctl: ensure k0s bin dir", "error", err)
				return false
			}
			return true
		},
		member: "etcdctl",
		dest:   bin,
		mode:   0o755,
		installErr: func(c *cyc, local string, err error) {
			c.err("etcdctl: install", "file", local, "dst", bin, "error", err)
		},
	})
}

// ---------- Phase 3: kine.service (split kine out of k0scontroller) ----------
//
// Kine embedded in k0scontroller shares cgroup + lifecycle with the
// apiserver: one kine OOM (catch-up storm after compact) drags the
// whole controller into a metastable OOM loop (incident 2026-10-02 —
// /swapfile-kine is the band-aid for that shared cgroup). Splitting
// kine into its OWN systemd unit with its own MemoryMax/GOMEMLIMIT
// boundary means a kine OOM only kills+restarts kine — the apiserver
// loses storage temporarily but is not dragged down with it.
// k0scontroller connects over the kine socket — Before= guarantees
// storage is up before the apiserver.
//
// Hard gate: only runs when NodeName is listed in kine_service_hosts
// (defaults.yaml declares [] => fully off until cluster.yaml lists
// cutover hosts). An unlisted node is never touched.

func (c *cyc) groupKineService() {
	r, ctx := c.r, c.ctx
	if !slices.Contains(c.vs("kine_service_hosts"), r.cfg.NodeName) {
		// NB: no rollback — unlisting a host only stops converge, a
		// running unit keeps running (deliberate: never kill the
		// apiserver datastore just because a host left the list).
		return
	}

	// defaults.yaml contract: empty kine_endpoint = do not render the
	// unit. A kine with no DSN falls back to sqlite on the unix socket
	// the apiserver points at -> empty datastore (data loss). Fail
	// closed: keep last-good, warn so the operator fixes the vars.
	ep := c.t.Vars.StrDef("kine_endpoint", "")
	if ep == "" {
		c.err("kine.service: kine_endpoint not configured — skipping converge")
		return
	}

	listen := defStr(c.v("kine_listen_address"), "unix:///run/k0s/kine.sock")
	// Fail-closed mTLS guard: a tcp:// listener on a NON-loopback host
	// exposes the etcd3 API to the network — without full mTLS the
	// datastore is wide open (read+write+delete) to anyone who can
	// reach the port. All three cert vars must be configured AND
	// exist on disk before the unit may converge; otherwise keep
	// last-good and refuse (loopback/unix listeners stay
	// unrestricted — the socket never leaves the host). Gate runs
	// BEFORE anything is written: a refused converge leaves both the
	// env file and the unit untouched.
	if hp := strings.TrimPrefix(listen, "tcp://"); hp != listen {
		host := hp
		if i := strings.LastIndex(host, ":"); i >= 0 {
			host = host[:i]
		}
		host = strings.Trim(host, "[]")
		// Loopback stays unrestricted in every spelling — v4
		// literal, name and the IPv6 loopback the mTLS cutover
		// binds ([::1]:2379 parses to "::1" after the bracket trim).
		if host != "127.0.0.1" && host != "localhost" && host != "::1" {
			missing := make([]string, 0, 3)
			for _, name := range []string{
				"kine_ca_file", "kine_server_cert_file", "kine_server_key_file",
			} {
				s := c.t.Vars.StrDef(name, "")
				switch {
				case s == "":
					missing = append(missing, name+" (not configured)")
				case !r.fileExists(s):
					missing = append(missing, name+" (missing on disk: "+s+")")
				}
			}
			if len(missing) > 0 {
				c.err("kine.service: tcp listener on non-loopback host requires full mTLS — refusing to converge (an unencrypted Kine datastore must never listen on the network)",
					"listen", listen, "missing", strings.Join(missing, ", "))
				return
			}
		}
	}

	// Render-bound kine_* gates — every value that lands in
	// kine.env or the unit's Exec lines must fit its sink's
	// charset BEFORE the binary download runs, so a refused var
	// keeps last-good unit+env (same fail-closed contract as the
	// mTLS guard above). The TLS paths are optional — empty passes
	// and renders no flag; the required scalars cannot be empty
	// here (ep=="" returned above, defStr defaults the rest).
	// kine_bin_{url,sha256} and kine_service_hosts stay ungated:
	// they feed the sha256-verified HTTP transport and a list
	// membership compare, never a render — a hostile value there
	// fails the download or matches nothing.
	metrics := defStr(c.v("kine_metrics_bind_address"), ":2380")
	caFile := c.t.Vars.StrDef("kine_ca_file", "")
	certFile := c.t.Vars.StrDef("kine_server_cert_file", "")
	keyFile := c.t.Vars.StrDef("kine_server_key_file", "")
	if !c.cfgEnvVal("kine_endpoint", ep) ||
		!c.shExecToken("kine_listen_address", listen) ||
		!c.shExecToken("kine_metrics_bind_address", metrics) {
		return
	}
	for _, kv := range []struct{ name, val string }{
		{"kine_ca_file", caFile},
		{"kine_server_cert_file", certFile},
		{"kine_server_key_file", keyFile},
	} {
		if kv.val != "" && !c.shExecToken(kv.name, kv.val) {
			return
		}
	}

	// /usr/local/bin/kine is sha256-pinned — a missing pin fails
	// closed even when the file already exists (never start a binary
	// that cannot be verified).
	binPath := "/usr/local/bin/kine"
	url := c.t.Vars.StrDef("kine_bin_url", "")
	sum := c.t.Vars.StrDef("kine_bin_sha256", "")
	if url == "" || sum == "" {
		c.err("kine.service: missing kine_bin_url+kine_bin_sha256 pins — not converging")
		return
	}
	// The dest file itself is the staging slot: a copy matching the
	// pin skips the download, anything else is (re)downloaded straight
	// onto it — no separate staged tarball to refuse.
	binChanged, binOK := c.installManagedBinary(managedBinarySpec{
		name: "kine.service",
		probe: func(c *cyc) bool {
			return r.fileExists(binPath) && sha256FileOK(r.hp(binPath), sum)
		},
		url:    url,
		sum:    sum,
		staged: r.hp(binPath),
		downloadErr: func(c *cyc, err error) {
			c.err("kine.service: kine binary download", "url", url, "error", err)
		},
	})
	if !binOK {
		return
	}
	// Enforce mode drift even when the hash already matches — a 0644
	// binary cannot exec.
	if err := os.Chmod(r.hp(binPath), 0o755); err != nil {
		c.err("kine.service: chmod kine binary", "path", binPath, "error", err)
		return
	}

	// /etc/kine 0700 + kine.env 0600 — the DSN carries the DB password
	// so it must not be embedded in the unit file (a 0644 unit is
	// readable by every user).
	_ = r.ensureDir("/etc/kine", 0o700)
	if err := os.Chmod(r.hp("/etc/kine"), 0o700); err != nil {
		c.err("kine.service: chmod 0700 /etc/kine — endpoint dir left readable",
			"path", "/etc/kine", "error", err)
	}
	envChanged, _ := r.writeManaged("/etc/kine/kine.env",
		[]byte("# Managed by node-config-agent - kine datastore endpoint (KINE_ENDPOINT)\n"+
			"KINE_ENDPOINT="+ep+"\n"), 0o600)
	// writeManaged preserves an existing file's mode — kine.env holds
	// a password so always re-enforce 0600.
	if err := os.Chmod(r.hp("/etc/kine/kine.env"), 0o600); err != nil {
		c.err("kine.service: chmod 0600 kine.env — DB password file left readable",
			"path", "/etc/kine/kine.env", "error", err)
	}

	// Defaults mirror the invocation k0s uses for embedded kine:
	// --listen-address=unix://<KineSocketPath> + --metrics-bind-address
	// =:2380 (HUBMETRICS whitelist + hub-kine-metrics ServiceMonitor).
	// metrics/caFile/certFile/keyFile were read and gated above —
	// before the binary download — so the render reuses those locals.
	// Phase-3 mTLS cutover (spec.storage.etcd.externalCluster over
	// TCP :2379): when the cert vars are declared they become kine's
	// etcd-client TLS flags — unset vars render no flag at all, so a
	// plaintext-TCP or unix-socket deployment stays byte-identical.
	tls := ""
	if caFile != "" {
		tls += " --ca-file=" + caFile
	}
	if certFile != "" {
		tls += " --server-cert-file=" + certFile
	}
	if keyFile != "" {
		tls += " --server-key-file=" + keyFile
	}
	// unix socket: /run is tmpfs — create the parent dir before start
	// (k0scontroller creates that dir, but it starts AFTER because of
	// Before=), and wait for the socket bind before Before= is
	// satisfied (Type=simple counts "started" at exec -> k0scontroller
	// could start while the socket does not exist yet). The wait
	// loop's trailing [ -S ] exit check makes a 30s socket no-show
	// FAIL the ExecStartPost — and the unit — so Restart=always
	// retries; an exit-0 timeout would start the apiserver against
	// a dead endpoint.
	execPre, execPost := "", ""
	if sock := strings.TrimPrefix(listen, "unix://"); sock != listen {
		execPre = "ExecStartPre=/usr/bin/mkdir -p " + filepath.Dir(sock) + "\n"
		execPost = "ExecStartPost=/bin/sh -c 'i=0; while [ ! -S " + sock +
			" ] && [ $i -lt 30 ]; do sleep 1; i=$((i+1)); done; [ -S " + sock + " ]'\n"
	} else if hp := strings.TrimPrefix(listen, "tcp://"); hp != listen {
		// tcp://host:port — the mTLS cutover shape: Before= must also
		// hold until the TCP listener actually accepts, or
		// k0scontroller starts against a port that is not accepting
		// yet. bash /dev/tcp probes the accept path (a listener that
		// exists but is wedged still fails open/timeout). Same
		// fail-the-unit contract as the unix wait: a 30s no-show
		// exits non-zero so Restart=always retries instead of
		// booting the apiserver on a dead endpoint.
		//
		// IPv6: net.SplitHostPort strips the [::1] brackets and
		// bash /dev/tcp accepts the bare v6 literal (the LAST '/'
		// separates host from port, colons inside are fine) — the
		// old strings.Replace(hp, ":", "/", 1) turned
		// "[::1]:2379" into "[/:1]:2379" and the wait-loop could
		// never succeed.
		tcpHost, tcpPort := hp, ""
		if h, p, err := net.SplitHostPort(hp); err == nil {
			tcpHost, tcpPort = h, p
		} else if h, p, _ := strings.Cut(hp, ":"); h != "" && p != "" {
			tcpHost, tcpPort = h, p
		}
		devtcp := "/dev/tcp/" + tcpHost + "/" + tcpPort
		execPost = "ExecStartPost=/bin/bash -c 'i=0; while ! (echo > " + devtcp +
			") 2>/dev/null && [ $i -lt 30 ]; do sleep 1; i=$((i+1)); done; (echo > " +
			devtcp + ") 2>/dev/null'\n"
	}
	// unit file rendered from templates/kine.service.j2 — the
	// ExecStart line concatenates the optional ExecStartPre/Post
	// wait-loops (each carries its own trailing newline) so the
	// rendered bytes stay identical to the pre-template Sprintf.
	rendered, err := r.render("kine.service.j2", map[string]any{
		"exec_pre":  execPre,
		"exec_post": execPost,
		"listen":    listen,
		"metrics":   metrics,
		"tls":       tls,
	})
	if err != nil {
		c.err("kine.service: render unit", "error", err)
		return
	}
	unitChanged, _ := r.writeManaged("/etc/systemd/system/kine.service", rendered, 0o644)
	if unitChanged {
		r.daemonReload(ctx)
	}
	r.ensureService(ctx, "kine.service", true, true)
	// start is a no-op on a running unit — a new binary/env/unit only
	// takes effect after restart, so every input change restarts
	// (same pattern as groupAPILB cfgChanged||nftChanged).
	if binChanged || envChanged || unitChanged {
		r.restartService(ctx, "kine.service")
	}
}
