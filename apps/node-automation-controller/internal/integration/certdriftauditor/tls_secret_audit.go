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

	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-automation-controller/internal/metrics"
	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-automation-controller/internal/platform/heal"
	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-automation-controller/internal/platform/kube"
)

// ---------------------------------------------------------------------------
// Check B — TLS secret expiry
// ---------------------------------------------------------------------------

func (a *certDriftAuditor) auditTLSSecrets(ctx context.Context) error {
	a.seenSecrets.Begin() // drop any aborted sweep's leftover emissions
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
	// page it at kube.DefaultListPageSize so no single response dominates.
	err := kube.ListEach(ctx, metav1.ListOptions{
		FieldSelector: "type=kubernetes.io/tls",
		Limit:         kube.DefaultListPageSize,
	}, kube.Secrets(a.cs, metav1.NamespaceAll),
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
				// Days, not seconds — the alert budget this feeds ("fires
				// <30d, pages <7d") thinks in days; negatives mean expired.
				untilExpiry := cert.NotAfter.Sub(a.now.Now())
				// Cardinality gate: only Secrets inside the alert window
				// (or already expired) emit — every far-future cert would
				// otherwise open one series per TLS Secret cluster-wide.
				// A Secret rotated back out of the window is simply not
				// re-asserted here, so the Prune below deletes its stale
				// series; the metric name, labels and <30d alert budget
				// are unchanged.
				if untilExpiry > tlsExpiryEmitWindow {
					continue
				}
				a.seenSecrets.Set(metrics.TLSSecretDaysToExpiry,
					untilExpiry.Hours()/24,
					key, s.Namespace, s.Name)
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
	now := a.now.Now()
	// The restart touches a LIVE workload (a Deployment rollout), so
	// it passes the same gates as every pod heal: first the WIDER of
	// the in-RAM ledger and the persisted rollout stamp (the
	// annotation survives an operator restart — an in-RAM-only
	// cooldown refunds the window and double-restarts linkerd-identity),
	// then the fail-closed maintenance mutex (cordon/drain/kured
	// defers the restart; "cannot verify" skips AND IncErrors the
	// queue).
	deploy, err := a.cs.AppsV1().Deployments(kube.LinkerdNS).
		Get(ctx, kube.LinkerdIdentityName, metav1.GetOptions{})
	if err != nil {
		metrics.IncError(a.queue)
		log.Error(err, "linkerd-identity get failed")
		return
	}
	if heal.PersistedCooledDown(&a.linkerdIssuerHeals, deploy,
		kube.AnnoLastLinkerdIssuerRollout, kube.LinkerdIdentityName,
		linkerdIssuerCooldown, now) {
		// Deliberately NOT latching the serial here: sealing the new
		// fingerprint before the rollout is delivered means the next
		// sweep reads serial == linkerdIssuerSerial and returns early
		// — a cooldown-window or transient patch failure would drop
		// the re-roll forever. The fingerprint is stored only after
		// the Patch below succeeds.
		last := now.Add(-linkerdIssuerCooldown) // keep "ago" sane if both clocks somehow read empty
		if t, ok := a.linkerdIssuerHeals.Last(kube.LinkerdIdentityName); ok && t.After(last) {
			last = t
		}
		if t, ok := kube.AnnoTime(deploy, kube.AnnoLastLinkerdIssuerRollout); ok && t.After(last) {
			last = t
		}
		log.Info("skip issuer rollout: inside cooldown",
			"ago", now.Sub(last).Truncate(time.Minute))
		return
	}
	// Fail-closed maintenance mutex — the shared preamble with no
	// additional ledger cooldown (PersistedCooledDown already ran the
	// wider-of check above).
	proceed, unverifiable := heal.Gate(ctx, log, &a.verdict, a.cs, a.dyn,
		kube.LinkerdIdentityName, now)
	switch {
	case unverifiable:
		metrics.IncError(a.queue)
		return
	case !proceed:
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
	if _, err := a.cs.AppsV1().Deployments(kube.LinkerdNS).Patch(ctx, kube.LinkerdIdentityName,
		types.StrategicMergePatchType, payload, metav1.PatchOptions{}); err != nil {
		metrics.IncError(a.queue)
		log.Error(err, "linkerd-identity rollout stamp failed")
		return
	}
	// The rollout is delivered — latch the new fingerprint and the
	// in-RAM half of the cooldown NOW (a failed persisted stamp must
	// not let the next 15m sweep re-roll the Deployment), then stamp
	// the persisted annotation so the window survives an operator
	// restart. StampPersisted only stamps the ledger when its patch
	// lands, so a failed stamp leaves the RAM clock as the sole guard.
	a.linkerdIssuerSerial = serial
	a.linkerdIssuerHeals.Stamp(kube.LinkerdIdentityName, now)
	metrics.ControlPlanePodHealsTotal.WithLabelValues(kube.LinkerdIdentityName).Inc()
	log.Info("ACTION: issuer cert rotated (serial changed) — stamped rollout annotation on linkerd-identity")
	if err := heal.StampPersisted(ctx,
		func(ctx context.Context, data []byte) error {
			_, err := a.cs.AppsV1().Deployments(kube.LinkerdNS).Patch(ctx,
				kube.LinkerdIdentityName, types.StrategicMergePatchType,
				data, metav1.PatchOptions{})
			return err
		},
		kube.AnnoLastLinkerdIssuerRollout, &a.linkerdIssuerHeals,
		kube.LinkerdIdentityName, now); err != nil {
		metrics.IncError(a.queue)
		log.Error(err, "linkerd-identity persisted cooldown stamp failed")
	}
}
