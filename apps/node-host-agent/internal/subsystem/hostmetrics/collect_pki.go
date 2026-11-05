// collect_pki.go — on-disk PKI cert expiry (2.4): days-left per
// *.crt/*.pem under the k0s/kine PKI dirs. Split out of
// hostmetrics.go.
package hostmetrics

import (
	"crypto/x509"
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
	now := c.cfg.nowFn().Unix()
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
			ch <- prometheus.MustNewConstMetric(c.descPKIDays,
				prometheus.GaugeValue, days, c.cfg.NodeName, label)
		}
	}
}
