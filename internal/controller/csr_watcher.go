// csr-watcher — handles kubelet-serving CertificateSigningRequests
// that sit pending forever. k0s/kubeadm nodes request a serving cert
// via signer kubernetes.io/kubelet-serving on join/rotation; nothing
// in-cluster auto-approves them, so a node whose CSR was missed runs
// with a stale serving cert (metrics-server/kubelet API break).
//
// Detect mode (approve=false — default): warn-logs each pending CSR
// once and takes no action — not an error, never IncError.
//
// Approve mode: validates spec.username is "system:node:<name>" AND a
// Node named <name> exists (the standard kubelet-serving binding —
// same check `kubectl certificate approve`'s RBAC implies), then
// appends an Approved condition via UpdateApproval. Validation
// failures warn+skip and IncError once per CSR. Capped at 5 approvals
// per run to bound a misbehaving flood.
package controller

import (
	"context"
	"strings"
	"time"

	certificatesv1 "k8s.io/api/certificates/v1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
	ctrl "sigs.k8s.io/controller-runtime"
	logf "sigs.k8s.io/controller-runtime/pkg/log"

	"github.com/passiontech-global/node-automation-controller/internal/metrics"
)

const (
	csrWatcherQueue      = "csr-watcher"
	kubeletServingSigner = "kubernetes.io/kubelet-serving"
	nodeUserPrefix       = "system:node:"
	csrMinAge            = 15 * time.Minute // fresh CSRs may still be under review
	csrMaxApprovalsRun   = 5
)

type csrWatcher struct {
	cs       kubernetes.Interface
	approve  bool
	warned   map[string]struct{} // detect mode: warn-logged once per CSR
	reported map[string]struct{} // approve mode: IncError fired once per CSR
}

// SetupCSRWatcher registers the 10m sweep — always runs (detect mode
// still reports pending CSRs); `approve` only controls the action.
func SetupCSRWatcher(mgr ctrl.Manager, cs kubernetes.Interface, approve bool) error {
	w := &csrWatcher{
		cs: cs, approve: approve,
		warned: map[string]struct{}{}, reported: map[string]struct{}{},
	}
	return addPeriodic(mgr, csrWatcherQueue, 10*time.Minute, w.run)
}

func (w *csrWatcher) run(ctx context.Context) error {
	log := logf.FromContext(ctx)

	list, err := w.cs.CertificatesV1().CertificateSigningRequests().
		List(ctx, metav1.ListOptions{})
	if err != nil {
		return err
	}
	approved := 0
	for i := range list.Items {
		csr := &list.Items[i]
		if csr.Spec.SignerName != kubeletServingSigner {
			continue
		}
		if csrDecided(csr) {
			continue
		}
		if time.Since(csr.CreationTimestamp.Time) <= csrMinAge {
			continue
		}
		if !w.approve {
			if _, ok := w.warned[csr.Name]; !ok {
				w.warned[csr.Name] = struct{}{}
				log.Info("WARN: pending kubelet-serving CSR — "+
					"auto-approve disabled, manual `kubectl certificate approve` needed",
					"csr", csr.Name, "username", csr.Spec.Username)
			}
			continue
		}
		if approved >= csrMaxApprovalsRun {
			log.Info("SKIP rest: approval cap reached",
				"cap", csrMaxApprovalsRun)
			break
		}
		if !w.validNodeCSR(ctx, csr) {
			continue
		}
		csr.Status.Conditions = append(csr.Status.Conditions,
			certificatesv1.CertificateSigningRequestCondition{
				Type:           certificatesv1.CertificateApproved,
				Status:         corev1.ConditionTrue,
				Reason:         "NodeOpsAutoApprove",
				Message:        "validated by node-automation-controller",
				LastUpdateTime: metav1.Now(),
			})
		if _, err := w.cs.CertificatesV1().CertificateSigningRequests().
			UpdateApproval(ctx, csr.Name, csr, metav1.UpdateOptions{}); err != nil {
			metrics.IncError(csrWatcherQueue)
			log.Error(err, "CSR approval failed", "csr", csr.Name)
			continue
		}
		approved++
		log.Info("APPROVED kubelet-serving CSR",
			"csr", csr.Name,
			"node", csr.Spec.Username[len(nodeUserPrefix):])
	}
	log.Info("sweep done", "approved", approved)
	return nil
}

// validNodeCSR enforces the kubelet-serving binding: the requester
// must be system:node:<name> and that Node must exist. Failures warn
// every run but IncError only once per CSR.
func (w *csrWatcher) validNodeCSR(ctx context.Context,
	csr *certificatesv1.CertificateSigningRequest) bool {
	log := logf.FromContext(ctx)
	fail := func(reason string) bool {
		if _, ok := w.reported[csr.Name]; !ok {
			w.reported[csr.Name] = struct{}{}
			metrics.IncError(csrWatcherQueue)
		}
		log.Info("WARN: CSR failed validation — skipping",
			"csr", csr.Name, "username", csr.Spec.Username, "reason", reason)
		return false
	}
	nodeName := strings.TrimPrefix(csr.Spec.Username, nodeUserPrefix)
	if nodeName == "" || nodeName == csr.Spec.Username {
		return fail("username is not " + nodeUserPrefix + "<nodeName>")
	}
	if _, err := w.cs.CoreV1().Nodes().Get(ctx, nodeName, metav1.GetOptions{}); err != nil {
		return fail("node does not exist: " + nodeName)
	}
	return true
}

// csrDecided reports whether the CSR already has a terminal
// Approved/Denied condition.
func csrDecided(csr *certificatesv1.CertificateSigningRequest) bool {
	for _, c := range csr.Status.Conditions {
		if c.Type == certificatesv1.CertificateApproved ||
			c.Type == certificatesv1.CertificateDenied {
			return true
		}
	}
	return false
}
