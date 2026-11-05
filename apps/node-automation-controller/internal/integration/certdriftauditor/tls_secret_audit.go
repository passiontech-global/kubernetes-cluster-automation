// tls_secret_audit.go — Check B of cert-drift-auditor: days-until-
// expiry for every kubernetes.io/tls Secret's tls.crt (the paged
// sweep that also feeds the W7-C6 replicator diff in
// replicated_secret_audit.go), plus the linkerd-identity-issuer
// serial fingerprint watch that stamps a rollout restart on
// linkerd-identity when cert-manager rotates the issuer (W8-NM2).
package certdriftauditor

import (
	"context"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"strings"
	"time"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	logf "sigs.k8s.io/controller-runtime/pkg/log"

	"github.com/passiontech-global/kubernetes-node-automation/apps/node-automation-controller/internal/metrics"
	"github.com/passiontech-global/kubernetes-node-automation/apps/node-automation-controller/internal/shared"
)

// ---------------------------------------------------------------------------
// Check B — TLS secret expiry
// ---------------------------------------------------------------------------

func (a *certDriftAuditor) auditTLSSecrets(ctx context.Context) error {
	log := logf.FromContext(ctx)

	// W7-C6 — the sweep collects two extra payloads on the same
	// paged read: tlsData snapshots every TLS secret's raw tls.crt
	// (parseable or not — drift is a byte comparison, not a cert
	// parse), and replicated holds every destination carrying the
	// replicated-from annotation for the source-diff pass.
	tlsData := map[string][]byte{}
	var replicated []replicatedSecretRef
	// Server-side type filter + continue-token pagination: the
	// all-namespaces secret read is the biggest this module makes —
	// page it at certDriftListPage so no single response dominates.
	err := shared.ListEach(ctx, metav1.ListOptions{
		FieldSelector: "type=kubernetes.io/tls",
		Limit:         certDriftListPage,
	}, shared.Secrets(a.cs, metav1.NamespaceAll),
		func(items []corev1.Secret) error {
			for i := range items {
				s := &items[i]
				// Belt-and-suspenders: the type field selector is applied
				// server-side on a real apiserver, but fake clientsets
				// ignore it — an in-code check keeps both honest (same
				// rule as the pod-phase filter in cilium_identity_auditor).
				if s.Type != corev1.SecretTypeTLS {
					continue
				}
				tlsData[s.Namespace+"/"+s.Name] = s.Data["tls.crt"]
				if src := strings.TrimSpace(s.Annotations[replicatedFromAnno]); src != "" {
					replicated = append(replicated, replicatedSecretRef{
						namespace: s.Namespace, name: s.Name,
						source: src, dest: s.Data["tls.crt"],
					})
				}
				block, _ := pem.Decode(s.Data["tls.crt"])
				if block == nil {
					log.Info("skip: tls secret carries no decodable tls.crt PEM",
						"secret", s.Namespace+"/"+s.Name)
					continue
				}
				cert, err := x509.ParseCertificate(block.Bytes)
				if err != nil {
					log.Error(err, "tls.crt parse failed",
						"secret", s.Namespace+"/"+s.Name)
					continue
				}
				key := secretMetricKey{s.Namespace, s.Name}
				a.seenSecrets.Emit(key, s.Namespace, s.Name)
				// Days, not seconds — the alert budget this feeds ("fires
				// <30d, pages <7d") thinks in days; negatives mean expired.
				days := cert.NotAfter.Sub(a.now.Now()).Hours() / 24
				metrics.TLSSecretDaysToExpiry.
					WithLabelValues(s.Namespace, s.Name).Set(days)
			}
			return nil
		})
	if err != nil {
		return fmt.Errorf("list tls secrets: %w", err)
	}

	// Prune series for secrets gone (or no longer parseable) since the
	// last sweep — otherwise /metrics keeps reporting a dead secret.
	a.seenSecrets.Prune(metrics.TLSSecretDaysToExpiry.DeleteLabelValues)

	// W7-C6 — the replicator drift diff rides the same read: every
	// replicated destination's tls.crt is compared against its
	// source (the TLS map first, a direct Get for non-TLS sources).
	a.auditReplicatedSecrets(ctx, tlsData, replicated)
	return nil
}

// auditLinkerdIssuer tracks the linkerd-identity-issuer Secret's
// certificate fingerprint (SerialNumber): a cert-manager rotation
// changes it, and linkerd-identity must re-roll to serve the new
// issuer — a wedged rollout after rotation breaks mTLS mesh-wide.
// First sight only seeds the fingerprint; a CHANGE patches a rollout
// annotation on Deployment/linkerd-identity (30m cooldown).
func (a *certDriftAuditor) auditLinkerdIssuer(ctx context.Context, s *corev1.Secret) {
	log := logf.FromContext(ctx)
	var serial string
	for _, key := range []string{"tls.crt", "crt.pem", "ca.crt"} {
		block, _ := pem.Decode(s.Data[key])
		if block == nil {
			continue
		}
		if cert, err := x509.ParseCertificate(block.Bytes); err == nil {
			serial = cert.SerialNumber.String()
			break
		}
	}
	if serial == "" {
		return
	}
	if !a.linkerdIssuerTracked {
		a.linkerdIssuerTracked = true
		a.linkerdIssuerSerial = serial
		return
	}
	if serial == a.linkerdIssuerSerial {
		return
	}
	a.linkerdIssuerSerial = serial
	now := a.now.Now()
	if now.Sub(a.linkerdIssuerHealed) < linkerdIssuerCooldown {
		log.Info("skip issuer rollout: inside cooldown",
			"ago", now.Sub(a.linkerdIssuerHealed).Truncate(time.Minute))
		return
	}
	payload, err := json.Marshal(map[string]any{
		"spec": map[string]any{"template": map[string]any{
			"metadata": map[string]any{"annotations": map[string]string{
				linkerdIssuerRolloutAnno: now.UTC().Format(time.RFC3339),
			}},
		}},
	})
	if err != nil {
		return
	}
	if _, err := a.cs.AppsV1().Deployments(linkerdNS).Patch(ctx, linkerdIssuerDeploy,
		types.StrategicMergePatchType, payload, metav1.PatchOptions{}); err != nil {
		metrics.IncError(a.queue)
		log.Error(err, "linkerd-identity rollout stamp failed")
		return
	}
	a.linkerdIssuerHealed = now
	metrics.ControlPlanePodHealsTotal.WithLabelValues(linkerdIssuerDeploy).Inc()
	log.Info("ACTION: issuer cert rotated (serial changed) — stamped rollout annotation on linkerd-identity")
}
