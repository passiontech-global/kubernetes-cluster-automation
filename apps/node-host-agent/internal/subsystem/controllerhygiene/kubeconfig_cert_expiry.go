// kubeconfig_cert_expiry.go — W10-CP5 embedded kubeconfig client
// certificate expiry:
//
//	Parses client-certificate-data out of the k0s admin/ccm/
//	scheduler/kubelet kubeconfigs and exports
//	node_agent_kubeconfig_cert_min_days_remaining; inside
//	the warn window it latches
//	state-kubeconfig-cert-expiring.
package controllerhygiene

import (
	"context"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"math"
	"os"
	"path/filepath"

	"k8s.io/client-go/tools/clientcmd"

	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-host-agent/internal/platform/hoststate"
	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-host-agent/internal/platform/promfile"
)

// checkKubeCert is the prometheus `check` label + log context for
// the embedded kubeconfig client-cert expiry check.
const checkKubeCert = "kubeconfig-cert"

// stateKubeCertExpiring latches while an embedded kubeconfig
// client cert sits inside the warn window — surfaces through
// node_host_agent_watchdog_state{state=...} like every other
// state-* latch.
const stateKubeCertExpiring = hoststate.LatchKubeconfigCertExpiring

// kubeconfigCertMinDays is the W10-CP5 warn window (plan: <14d).
var kubeconfigCertMinDays = 14.0

const (
	// certDaysMetric is the Prometheus alert key
	// (NodeKubeconfigCertExpiringSoon) — exact series name.
	certDaysMetric = "node_agent_kubeconfig_cert_min_days_remaining"
)

// kubeconfigCertPaths — the kubeconfigs carrying embedded client
// certs: the k0s admin/ccm/scheduler confs under pki/ plus the
// kubelet's own kubeconfig at the K0sDir root. controller-manager.conf
// is scanned alongside ccm.conf — k0s has shipped both names for the
// KCM identity; missing files are skipped.
func (h *Hygiene) kubeconfigCertPaths() []string {
	k0s := h.cfg.K0sDir
	return []string{
		filepath.Join(k0s, "pki", "admin.conf"),
		filepath.Join(k0s, "pki", "ccm.conf"),
		filepath.Join(k0s, "pki", "controller-manager.conf"),
		filepath.Join(k0s, "pki", "scheduler.conf"),
		filepath.Join(k0s, "kubelet.conf"),
	}
}

// checkKubeconfigCertExpiry parses client-certificate-data (and
// file-referenced client certs) out of the k0s kubeconfigs and
// exports node_agent_kubeconfig_cert_min_days_remaining — the
// minimum NotAfter horizon across every embedded client cert.
// Inside kubeconfigCertMinDays it latches
// state-kubeconfig-cert-expiring (surfaces via
// node_host_agent_watchdog_state) and suspect-logs; absent or
// unparseable files are skipped silently.
func (h *Hygiene) checkKubeconfigCertExpiry(_ context.Context) {
	now := h.cfg.nowFn()
	minDays := math.Inf(1)
	seen := 0
	for _, path := range h.kubeconfigCertPaths() {
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
		p.Header(certDaysMetric,
			"Minimum days until the soonest-expiring embedded client "+
				"certificate across the k0s kubeconfigs (admin/ccm/"+
				"scheduler/kubelet).")
		h.stateExit(stateKubeCertExpiring) // no certs → nothing to expire
		h.cycles.WithLabelValues(checkKubeCert, "no_certs").Inc()
	} else {
		p.Gauge(certDaysMetric,
			"Minimum days until the soonest-expiring embedded client "+
				"certificate across the k0s kubeconfigs (admin/ccm/"+
				"scheduler/kubelet).",
			minDays)
		h.cycles.WithLabelValues(checkKubeCert, "ok").Inc()
		if minDays < kubeconfigCertMinDays {
			h.state.Enter(stateKubeCertExpiring, fmt.Sprintf(
				"client cert expires in %.1fd", minDays))
			h.state.SuspectLog(stateKubeCertExpiring, fmt.Sprintf(
				"kubeconfig-cert-expiring: embedded client cert "+
					"NotAfter in %.1f days (<%d)",
				minDays, int(kubeconfigCertMinDays)),
				h.cfg.SuspectLogCadence)
		} else {
			h.stateExit(stateKubeCertExpiring)
		}
	}
	h.writeTextfileProm("node-agent-kubeconfig-cert.prom", p.String())
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
			b, rerr := os.ReadFile(resolveRel(path, a.ClientCertificate))
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
