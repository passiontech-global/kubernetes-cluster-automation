// kubeconfig_cert_expiry.go — kubeconfig-cert-expiry embedded kubeconfig client
// certificate expiry:
//
//	Parses client-certificate-data out of the k0s admin/ccm/
//	scheduler/kubelet kubeconfigs and exports
//	node_agent_kubeconfig_cert_min_days_remaining; inside
//	the warn window it latches
//	state-kubeconfig-cert-expiring.
package pki

import (
	"context"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"math"
	"os"
	"path/filepath"

	"k8s.io/client-go/tools/clientcmd"

	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-host-agent/internal/platform/promfile"
	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-host-agent/internal/subsystem/controllerhygiene/cdeps"
)

// KubeconfigCertMinDays is the kubeconfig-cert-expiry warn window (plan: <14d).
var KubeconfigCertMinDays = 14.0

const (
	// CertDaysMetric is the Prometheus alert key
	// (NodeKubeconfigCertExpiringSoon) — exact series name.
	CertDaysMetric = "node_agent_kubeconfig_cert_min_days_remaining"
)

// kubeconfigCertPaths — the kubeconfigs carrying embedded client
// certs: the k0s admin/ccm/scheduler confs under pki/ plus the
// kubelet's own kubeconfig at the K0sDir root. controller-manager.conf
// is scanned alongside ccm.conf — k0s has shipped both names for the
// KCM identity; missing files are skipped.
func (c *KubeCertCheck) kubeconfigCertPaths() []string {
	k0s := c.d.Cfg.K0sDir
	return []string{
		filepath.Join(k0s, "pki", "admin.conf"),
		filepath.Join(k0s, "pki", "ccm.conf"),
		filepath.Join(k0s, "pki", "controller-manager.conf"),
		filepath.Join(k0s, "pki", "scheduler.conf"),
		filepath.Join(k0s, "kubelet.conf"),
	}
}

// KubeCertCheck is the kubeconfig-cert-expiry embedded kubeconfig client-cert
// expiry check as a Check — stateless (the warn window needs no
// streak bookkeeping). Like kineStorageCheck it rides cpFreezeCheck's
// ungated slot rather than holding its own dispatch-table entry.
type KubeCertCheck struct {
	d *cdeps.Deps
}

// Name returns the check label / log context.
func (c *KubeCertCheck) Name() string { return cdeps.CheckKubeCert }

// Run parses client-certificate-data (and file-referenced client
// certs) out of the k0s kubeconfigs and exports
// node_agent_kubeconfig_cert_min_days_remaining — the minimum
// NotAfter horizon across every embedded client cert. Inside
// KubeconfigCertMinDays it latches state-kubeconfig-cert-expiring
// (surfaces via node_host_agent_watchdog_state) and suspect-logs;
// absent or unparseable files are skipped silently.
func (c *KubeCertCheck) Run(_ context.Context) {
	now := c.d.Cfg.Clock.Now()
	minDays := math.Inf(1)
	seen := 0
	for _, path := range c.kubeconfigCertPaths() {
		certs, err := kubeconfigClientCerts(path)
		if err != nil {
			continue
		}
		for _, c := range certs {
			seen++
			if d := c.NotAfter.Sub(now).Hours() / 24; d < minDays {
				minDays = d
			}
		}
	}
	var p promfile.Builder
	if seen == 0 {
		p.Header(CertDaysMetric,
			"Minimum days until the soonest-expiring embedded client "+
				"certificate across the k0s kubeconfigs (admin/ccm/"+
				"scheduler/kubelet).")
		c.d.StateExit(cdeps.StateKubeCertExpiring) // no certs → nothing to expire
		c.d.Cycles.WithLabelValues(cdeps.CheckKubeCert, "no_certs").Inc()
	} else {
		p.Gauge(CertDaysMetric,
			"Minimum days until the soonest-expiring embedded client "+
				"certificate across the k0s kubeconfigs (admin/ccm/"+
				"scheduler/kubelet).",
			minDays)
		c.d.Cycles.WithLabelValues(cdeps.CheckKubeCert, "ok").Inc()
		if minDays < KubeconfigCertMinDays {
			c.d.State.Enter(cdeps.StateKubeCertExpiring, fmt.Sprintf(
				"client cert expires in %.1fd", minDays))
			c.d.State.SuspectLog(cdeps.StateKubeCertExpiring, fmt.Sprintf(
				"kubeconfig-cert-expiring: embedded client cert "+
					"NotAfter in %.1f days (<%d)",
				minDays, int(KubeconfigCertMinDays)),
				c.d.Cfg.SuspectLogCadence)
		} else {
			c.d.StateExit(cdeps.StateKubeCertExpiring)
		}
	}
	c.d.WriteTextfileProm("node-agent-kubeconfig-cert.prom", p.String())
}

// kubeconfigClientCerts extracts every embedded client certificate
// from a kubeconfig: client-certificate-data fields (base64 PEM,
// clientcmd-decoded) plus file-referenced client-certificate paths
// resolved relative to the kubeconfig dir (loadCreds parity).
// Unparseable files/certs are skipped, never fatal.
func kubeconfigClientCerts(path string) ([]*x509.Certificate, error) {
	kc, err := clientcmd.LoadFromFile(path)
	if err != nil {
		return nil, err
	}
	var certs []*x509.Certificate
	for _, a := range kc.AuthInfos {
		var pemBytes []byte
		switch {
		case len(a.ClientCertificateData) > 0:
			pemBytes = a.ClientCertificateData
		case a.ClientCertificate != "":
			b, rerr := os.ReadFile(cdeps.ResolveRel(path, a.ClientCertificate))
			if rerr != nil {
				continue
			}
			pemBytes = b
		default:
			continue
		}
		for rest := pemBytes; ; {
			var block *pem.Block
			block, rest = pem.Decode(rest)
			if block == nil {
				break
			}
			if block.Type != "CERTIFICATE" {
				continue
			}
			if c, perr := x509.ParseCertificate(block.Bytes); perr == nil {
				certs = append(certs, c)
			}
		}
	}
	return certs, nil
}
