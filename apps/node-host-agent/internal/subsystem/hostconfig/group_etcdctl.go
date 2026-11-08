// group_etcdctl.go — hub_converge.yaml etcd/kine splits: the pinned
// etcdctl binary for embedded-etcd controllers and the Phase-3
// kine.service split-out (own cgroup boundary so a kine OOM cannot
// drag the apiserver down).
package hostconfig

import (
	"fmt"
	"os"
	pathpkg "path"
	"path/filepath"
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
// pattern: <bin> version probe -> sha256-pinned tarball (staged or
// downloaded) -> untarInstall (tmp+rename).
func (c *cyc) etcdctlInstallBinary() {
	r, ctx := c.r, c.ctx
	ver, sum, url := c.v("etcdctl_version"), c.v("etcdctl_tgz_sha256"), c.v("etcdctl_tgz_url")
	tgz := defStr(c.v("etcdctl_tgz_file"), pathpkg.Base(url))
	if ver == "" || ver == "None" || url == "" || url == "None" ||
		sum == "" || sum == "None" {
		c.err("etcdctl: missing etcdctl_version+etcdctl_tgz_{url,sha256} pins — not converging")
		return
	}
	bin := "/var/lib/k0s/bin/etcdctl"
	if out, err := r.run(ctx, bin, "version"); err == nil &&
		strings.Contains(out, ver) {
		return
	}
	local := filepath2(r.cfg.DownloadDir, tgz)
	if fileExistsNoRoot(local) {
		// same contract as T5b/T9: verify the STAGED file every run —
		// a corrupted/operator-swapped tarball must not install.
		if !sha256FileOK(local, sum) {
			c.err("etcdctl: staged tgz sha256 mismatch — not installing",
				"file", local, "sha256", sum)
			return
		}
	} else if err := r.download(ctx, url, local, sum); err != nil {
		c.err("etcdctl: tgz download", "url", url, "file", local, "error", err)
		return
	}
	// /var/lib/k0s/bin exists on every k0s host, but untarInstall does
	// not create parents — keep the install self-contained.
	if err := r.ensureDir("/var/lib/k0s/bin", 0o755); err != nil {
		// ensureDir already counted the failure via noteErr — log
		// context only, do not count the same fault twice.
		logger().Error("etcdctl: ensure k0s bin dir", "error", err)
		return
	}
	if err := untarInstall(local, "etcdctl", r.hp(bin), 0o755); err != nil {
		c.err("etcdctl: install", "file", local, "dst", bin, "error", err)
	}
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
	if !containsSS(c.vs("kine_service_hosts"), r.cfg.NodeName) {
		// NB: no rollback — unlisting a host only stops converge, a
		// running unit keeps running (deliberate: never kill the
		// apiserver datastore just because a host left the list).
		return
	}

	// defaults.yaml contract: empty kine_endpoint = do not render the
	// unit. A kine with no DSN falls back to sqlite on the unix socket
	// the apiserver points at -> empty datastore (data loss). Fail
	// closed: keep last-good, warn so the operator fixes the vars.
	ep := c.v("kine_endpoint")
	if ep == "" || ep == "None" {
		c.err("kine.service: kine_endpoint not configured — skipping converge")
		return
	}

	// /usr/local/bin/kine is sha256-pinned — a missing pin fails
	// closed even when the file already exists (never start a binary
	// that cannot be verified).
	binPath := "/usr/local/bin/kine"
	url, sum := c.v("kine_bin_url"), c.v("kine_bin_sha256")
	if url == "" || url == "None" || sum == "" || sum == "None" {
		c.err("kine.service: missing kine_bin_url+kine_bin_sha256 pins — not converging")
		return
	}
	binChanged := false
	if !r.fileExists(binPath) || !sha256FileOK(r.hp(binPath), sum) {
		if err := r.download(ctx, url, r.hp(binPath), sum); err != nil {
			c.err("kine.service: kine binary download", "url", url, "error", err)
			return
		}
		binChanged = true
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
	listen := defStr(c.v("kine_listen_address"), "unix:///run/k0s/kine.sock")
	metrics := defStr(c.v("kine_metrics_bind_address"), ":2380")
	// Phase-3 mTLS cutover (spec.storage.etcd.externalCluster over
	// TCP :2379): when the cert vars are declared they become kine's
	// etcd-client TLS flags — unset vars render no flag at all, so a
	// plaintext-TCP or unix-socket deployment stays byte-identical.
	tls := ""
	if s := c.v("kine_ca_file"); s != "" && s != "None" {
		tls += " --ca-file=" + s
	}
	if s := c.v("kine_server_cert_file"); s != "" && s != "None" {
		tls += " --server-cert-file=" + s
	}
	if s := c.v("kine_server_key_file"); s != "" && s != "None" {
		tls += " --server-key-file=" + s
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
		execPost = "ExecStartPost=/bin/bash -c 'i=0; while ! (echo > /dev/tcp/" +
			strings.Replace(hp, ":", "/", 1) +
			") 2>/dev/null && [ $i -lt 30 ]; do sleep 1; i=$((i+1)); done; (echo > /dev/tcp/" +
			strings.Replace(hp, ":", "/", 1) + ") 2>/dev/null'\n"
	}
	unitChanged, _ := r.writeManaged("/etc/systemd/system/kine.service", []byte(fmt.Sprintf(`# Managed by node-config-agent - Phase 3: kine split out of k0scontroller.
# SEPARATE cgroup boundary: a kine OOM does not drag apiserver into
# the OOM loop (incident 2026-10-02). GOMEMLIMIT 1500MiB < MemoryMax 2G
# so Go GC fires before hitting the cgroup limit; GOGC=50 slows heap
# growth between cycles.
[Unit]
Description=kine (etcd3 API shim -> external datastore)
Documentation=file:/etc/kine/kine.env
After=network-online.target
Wants=network-online.target
# Storage must come up BEFORE k0scontroller — apiserver will not boot
# with a dead endpoint.
Before=k0scontroller.service

[Service]
Environment=GOMEMLIMIT=1500MiB
Environment=GOGC=50
# KINE_ENDPOINT lives in /etc/kine/kine.env (0600, holds DB password).
EnvironmentFile=/etc/kine/kine.env
%s%sExecStart=/usr/local/bin/kine --listen-address=%s --metrics-bind-address=%s%s
MemoryMax=2G
# OOMScoreAdjust negative: the kernel kills other processes before
# kine (apiserver data-path); high CPUWeight protects kine under CPU
# pressure.
OOMScoreAdjust=-500
CPUWeight=2000
Restart=always
RestartSec=5

[Install]
WantedBy=multi-user.target
`, execPre, execPost, listen, metrics, tls)), 0o644)
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
