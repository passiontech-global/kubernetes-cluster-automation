// certmanager-reaper — unstucks cert-manager ACME Orders wedged in
// "pending" by the known cert-manager self-check retry-forever bug:
// the http-01 Challenge is presented+processing but the propagation
// self-check keeps failing (e.g. DNS answer changed mid-issue), and
// cert-manager retries the SAME challenge forever instead of
// re-checking. The upstream fix is to delete the Order — cert-manager
// recreates it fresh and issuance proceeds.
//
// Candidacy: a Certificate that is Ready=False or has status.renewalTime
// within the next 7d, owning an Order pending >30m, cross-checked
// against a Challenge that is presented+processing with no state
// transition for >30m. Deleting the Order is the reset.
//
// Safety: per-certificate reset budget — at most 1 Order deletion per
// cert per hour, and at most 3 total per cert; once the budget is
// exhausted the reaper stops acting on that cert and surfaces an error
// (a cert that burns through 3 resets has a config problem — continuing
// would burn the ACME rate limit). Per-item failures log + continue.
//
// Budget persistence: the counter lives in memory AND in the
// passiontech.dev/acme-order-resets annotation ("<total>,<lastRFC3339>") on
// the Certificate itself — a controller restart cannot refund resets
// and hammer the ACME rate limit. A cert that heals (Ready=True and
// no longer a reap candidate) gets both halves wiped so its next
// renewal cycle starts with a full budget.
package certmanagerreaper

import (
	"context"
	"fmt"
	"time"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/client-go/dynamic"
	logf "sigs.k8s.io/controller-runtime/pkg/log"

	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-automation-controller/internal/metrics"
	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-automation-controller/internal/platform/kube"
	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-automation-controller/internal/platform/state"
	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-automation-controller/internal/shared"
)

const (
	orderPendingMinAge = 30 * time.Minute   // order/challenge must be wedged this long
	certRenewalWindow  = 7 * 24 * time.Hour // renewalTime within this window = candidate
	certReaperMinGap   = time.Hour          // max 1 order reset per cert per hour
	certReaperMaxReset = 3                  // stop acting after N resets on the same cert
	// the stuck-CertificateRequest path: a CR wedged Ready=False
	// (Pending/Failed) past crStuckMinAge under a Ready=False or
	// expiring cert gets deleted so cert-manager re-issues it. It
	// draws on the same acme-order-resets budget, on a wider 6h gap.
	crStuckMinAge     = 30 * time.Minute
	crReapMinGap      = 6 * time.Hour
	certExpirySoonWin = 14 * 24 * time.Hour
	// acmeResetsAnno persists the per-cert reset budget on the
	// Certificate — "<total>,<lastRFC3339>" — so the 3-per-cycle cap
	// survives controller restarts.
	acmeResetsAnno = kube.AnnoACMEOrderResets
)

var (
	certificateGVR        = kube.GVRCertificate
	certificateRequestGVR = kube.GVRCertificateRequest
	orderGVR              = kube.GVRACMEOrder
	challengeGVR          = kube.GVRACMEChallenge
)

// certReset is the per-certificate reset budget tracked in memory.
// The passiontech.dev/acme-order-resets annotation on the Certificate is the
// durable half — hydrated into this map on first sight after a
// restart, written back on every reset, and wiped together with the
// map entry when the cert reports Ready=True and is no longer a reap
// candidate (all biases stay conservative).
type certReset struct {
	total  int
	last   time.Time
	gaveUp bool // IncError already fired for the exhausted budget
}

type certManagerReaper struct {
	dyn dynamic.Interface
	// queue is the module's ops name — stamped from Deps.Name (the
	// registry row) so the periodic's name and every IncError label
	// come from one place.
	queue  string
	resets map[string]*certReset
	// now is the clock seam — tests pin it so the pending/wedged
	// windows, the renewal window and the hourly reset gap are
	// deterministic. nil → time.Now.
	now shared.Clock
	// crReaped: cert key → last stuck-CertificateRequest delete —
	// the 6h in-RAM half of the stuck-CR-reap cooldown (the durable
	// half shares passiontech.dev/acme-order-resets). CooldownSet is
	// zero-value ready — no arm needed.
	crReaped state.CooldownSet
	// crCache: per-run CertificateRequest list cache keyed by
	// namespace — the Order-attribution path and the stuck-CR
	// path share ONE list per namespace per sweep (a failed list
	// IncErrors once, not twice).
	crCache map[string]crListResult
	// orderCache: per-run ACME Order list + owner-cert attribution
	// index keyed by namespace — reapCert consumes one entry per
	// namespace per sweep instead of one Order List per cert
	// candidate (same shape and lifecycle as crCache).
	orderCache map[string]*orderIndex
}

// crListResult is the cached outcome of one namespace's CR List.
type crListResult struct {
	list *unstructured.UnstructuredList
	err  error
}

// Setup registers the 15m sweep. Disabled clusters
// (no cert-manager component / no ACME — CERTMANAGER_REAPER_ENABLED is
// opt-in and resolved by setupModules into Deps.Disabled) skip
// registration entirely.
func Setup(d shared.Deps) error {
	mgr, dyn := d.Mgr, d.Dyn
	return shared.SetupNoConfig(d, func() error {
		r := &certManagerReaper{dyn: dyn, queue: d.Name,
			resets: map[string]*certReset{}}
		return shared.AddPeriodic(mgr, r.queue, 15*time.Minute, r.run)
	})
}

func (r *certManagerReaper) run(ctx context.Context) error {
	log := logf.FromContext(ctx)
	// Lazily arm the zero-value struct — unit tests construct the
	// reaper literally without the Setup path. crReaped is a
	// CooldownSet — zero-value ready, no arm.
	if r.resets == nil {
		r.resets = map[string]*certReset{}
	}
	r.crCache = map[string]crListResult{}
	r.orderCache = map[string]*orderIndex{}
	now := r.now.Now()

	certs, err := kube.ListAll(ctx, metav1.ListOptions{Limit: 500},
		kube.DynamicPage(r.dyn.Resource(certificateGVR).Namespace(metav1.NamespaceAll)))
	if err != nil {
		return fmt.Errorf("list certificates: %w", err)
	}
	seen := map[string]bool{}
	candidates, reset := 0, 0
	for i := range certs {
		cert := &certs[i]
		key := cert.GetNamespace() + "/" + cert.GetName()
		seen[key] = true
		needsReap := certNeedsReap(cert, now)
		// A cert back to Ready=True earned a clean slate — drop its
		// reset budget (memory AND persisted annotation) so a few
		// stuck-issuance episodes spread over months cannot refuse it
		// forever without a restart. The needsReap guard is load-
		// bearing: a renewal-window candidate reports Ready=True the
		// whole time its Order wedges (the old cert is still valid),
		// so clearing on Ready alone would wipe the budget every
		// sweep and defeat both the hourly gap and the 3-reset cap.
		// The hasAnno half covers the post-restart case where the
		// memory ledger is empty but the Certificate still carries
		// the annotation.
		_, tracked := r.resets[key]
		hasAnno := cert.GetAnnotations()[acmeResetsAnno] != ""
		if !needsReap && certReady(cert) && (tracked || hasAnno) {
			delete(r.resets, key)
			if hasAnno {
				if err := r.patchResetsAnnotation(ctx, cert, nil); err != nil {
					metrics.IncError(r.queue)
					log.Error(err, "acme-resets annotation clear failed", "cert", key)
				}
			}
		}
		if !needsReap {
			// stuck-CR-reap: a cert that is Ready=False or expires <14d may
			// carry a wedged CertificateRequest even with no stuck
			// Order — the CR path holds its own gates and cooldown.
			if r.reapStuckCR(ctx, cert, now) {
				reset++
			}
			continue
		}
		candidates++
		if r.reapCert(ctx, cert) {
			reset++
		}
		if r.reapStuckCR(ctx, cert, now) {
			reset++
		}
	}
	// Drop budgets for Certificates that vanished — the map is
	// otherwise append-only per cert ever reaped.
	for key := range r.resets {
		if !seen[key] {
			delete(r.resets, key)
		}
	}
	log.Info("sweep done", "candidates", candidates, "ordersReset", reset)
	return nil
}
