// collect_pki.go — on-disk PKI cert expiry (2.4): days-left per
// *.crt/*.pem under the k0s/kine PKI dirs, plus the sa-pub-key-fingerprint
// ServiceAccount token signer key fingerprint (sa.pub SHA-256) on
// control-plane nodes. Split out of hostmetrics.go.
package hostmetrics

import (
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"encoding/pem"
	"math"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/prometheus/client_golang/prometheus"
)

// defaultPKIHostPaths are the PKI sources scanned for *.crt/*.pem —
// host-relative, joined under HostRoot: the k0s apiserver+etcd cert
// dirs, the kubelet client bundle (a single file), and the kine
// etcd-pki dir on standalone DB VMs.
var defaultPKIHostPaths = []string{
	"var/lib/k0s/pki",
	"var/lib/k0s/pki/etcd",
	"var/lib/k0s/kubelet/pki/kubelet-client-current.pem",
	"etc/kine/pki",
}

// --- 2.4: on-disk PKI cert expiry ---

var descPKIDays = prometheus.NewDesc(
	"node_host_agent_pki_cert_days_left",
	"Days until the earliest notAfter of the on-disk PKI cert at this path (emitted only when a cert parses).",
	[]string{"node", "path"}, nil)

// defaultSAPubHostPath is the sa.pub path relative to HostRoot —
// the ServiceAccount token signer public key every control-plane
// node must share byte-for-byte (sa-pub-key-fingerprint).
const defaultSAPubHostPath = "var/lib/k0s/pki/sa.pub"

// saPubHashHelp is the HELP text shared with the controllerhygiene
// textfile writer — the textfile collector rejects a family whose
// HELP lines disagree across .prom files, so both emitters must
// carry the identical sentence.
const saPubHashHelp = "SHA-256 fingerprint of the k0s ServiceAccount " +
	"token signer public key (sa.pub) — a differing hash across " +
	"control-plane nodes is signer key skew (TokenRequest 401s)."

var descSAPubHash = prometheus.NewDesc(
	"node_k0s_sa_pub_fingerprint_hash",
	saPubHashHelp,
	[]string{"node", "sha256"}, nil)

// sha256FileHex returns the hex SHA-256 of a file's raw bytes —
// sa.pub is hashed whole (not parsed): a drifted file must change
// the fingerprint even when the drift is a stray byte, not a
// different key.
func sha256FileHex(path string) (string, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return "", err
	}
	sum := sha256.Sum256(data)
	return hex.EncodeToString(sum[:]), nil
}

// collectSAPubFingerprint emits node_k0s_sa_pub_fingerprint_hash on
// control-plane nodes — sa-pub-key-fingerprint: when one CP node's sa.pub diverges
// (rotation not propagated, or the file never reloaded), tokens the
// TokenRequest API mints there 401 on the other apiservers (~33/66%
// of requests behind the CP load balancer). The hash rides a label
// so `count by (sha256)` across nodes exposes the skew directly.
// Same emission policy as collectK0sDrift: gated on the
// k0scontroller unit file, absent (no series) when the file can't
// be read — never a fabricated value.
func (c *Collector) collectSAPubFingerprint(ch chan<- prometheus.Metric) {
	if _, err := os.Stat(c.cfg.K0sUnitFile); err != nil {
		return // not a k0s controller → no series
	}
	sum, err := sha256FileHex(filepath.Join(
		c.cfg.HostRoot, defaultSAPubHostPath))
	if err != nil {
		return
	}
	ch <- prometheus.MustNewConstMetric(descSAPubHash,
		prometheus.GaugeValue, 1, c.cfg.NodeName, sum)
}

// pkiCertFiles expands one PKICertPaths entry: a directory yields
// its *.crt/*.pem children one level deep, a regular file is taken
// as-is.
func pkiCertFiles(path string) []string {
	fi, err := os.Stat(path)
	if err != nil {
		return nil
	}
	if !fi.IsDir() {
		return []string{path}
	}
	entries, err := os.ReadDir(path)
	if err != nil {
		return nil
	}
	var files []string
	for _, e := range entries {
		if e.IsDir() {
			continue
		}
		if n := e.Name(); strings.HasSuffix(n, ".crt") || strings.HasSuffix(n, ".pem") {
			files = append(files, filepath.Join(path, n))
		}
	}
	sort.Strings(files)
	return files
}

// pemDaysLeft returns days until the EARLIEST notAfter of any cert
// block in the PEM data — a bundle file exports its worst member.
// ok=false when no block parses.
func pemDaysLeft(data []byte, now int64) (float64, bool) {
	var min time.Time
	ok := false
	for rest := data; ; {
		var b *pem.Block
		b, rest = pem.Decode(rest)
		if b == nil {
			break
		}
		cert, err := x509.ParseCertificate(b.Bytes)
		if err != nil {
			continue // a non-cert PEM block must not kill the file
		}
		if !ok || cert.NotAfter.Before(min) {
			min, ok = cert.NotAfter, true
		}
	}
	if !ok {
		return 0, false
	}
	// math.Floor, not truncation: -1.9d must read -2, not -1 — an
	// already-expired cert rounds AWAY from zero like the positive
	// side does toward it.
	return math.Floor(float64(min.Unix()-now) / 86400), true
}

// collectPKICerts emits days-left per cert file — absent when no
// cert under the source parses (same no-fake-0 rule as the nebula
// cert gauge). The path label strips the HostRoot mount prefix so
// pods and standalone hosts emit identical series.
func (c *Collector) collectPKICerts(ch chan<- prometheus.Metric) {
	now := c.cfg.Clock.Now().Unix()
	for _, src := range c.cfg.PKICertPaths {
		for _, f := range pkiCertFiles(src) {
			data, err := os.ReadFile(f)
			if err != nil {
				continue
			}
			days, ok := pemDaysLeft(data, now)
			if !ok {
				continue
			}
			// Keep the leading slash: HostRoot="/" strips it while
			// HostRoot="/host" leaves it — the label must read
			// identically on pods and standalone hosts.
			label := strings.TrimPrefix(f, c.cfg.HostRoot)
			if !strings.HasPrefix(label, "/") {
				label = "/" + label
			}
			ch <- prometheus.MustNewConstMetric(descPKIDays,
				prometheus.GaugeValue, days, c.cfg.NodeName, label)
		}
	}
	// sa-pub-key-fingerprint: the sa.pub fingerprint rides the pki domain — same
	// PKI surface, same control-plane-only emission policy.
	c.collectSAPubFingerprint(ch)
}
