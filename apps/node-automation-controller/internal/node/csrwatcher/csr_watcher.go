// csr-watcher — handles kubelet-serving CertificateSigningRequests
// that sit pending forever. k0s/kubeadm nodes request a serving cert
// via signer kubernetes.io/kubelet-serving on join/rotation; nothing
// in-cluster auto-approves them, so a node whose CSR was missed runs
// with a stale serving cert (metrics-server/kubelet API break).
//
// Detect mode (approve=false — default): warn-logs each pending CSR
// once and takes no action — not an error, never IncError.
//
// Approve mode: runs the same checks a conformant kubelet-serving
// approver does before appending an Approved condition via
// UpdateApproval — spec.username is "system:node:<name>", a Node
// named <name> exists, the requester is in system:nodes, the usages
// are the serving triple only, and the x509 CSR inside spec.request
// names exactly that node (CN, O=system:nodes, SANs ⊆ the node's own
// status.addresses — a serving cert may carry no foreign identity).
// Validation failures warn+skip and IncError once per CSR. Capped at
// 5 approvals per run to bound a misbehaving flood.
package csrwatcher

import (
	"context"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"slices"
	"strings"
	"time"

	certificatesv1 "k8s.io/api/certificates/v1"
	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
	logf "sigs.k8s.io/controller-runtime/pkg/log"

	"github.com/passiontech-global/kubernetes-node-automation/apps/node-automation-controller/internal/metrics"
	"github.com/passiontech-global/kubernetes-node-automation/apps/node-automation-controller/internal/shared"
)

const (
	csrWatcherQueue      = "csr-watcher"
	kubeletServingSigner = "kubernetes.io/kubelet-serving"
	nodeUserPrefix       = "system:node:"
	nodesGroup           = "system:nodes"
	csrMinAge            = 15 * time.Minute // fresh CSRs may still be under review
	csrMaxApprovalsRun   = 5
)

// kubeletServingUsages is the usage set a conformant kubelet-serving
// approver accepts — any other usage (client auth!) would mint a
// credential this signer must never produce.
var kubeletServingUsages = map[certificatesv1.KeyUsage]struct{}{
	certificatesv1.UsageDigitalSignature: {},
	certificatesv1.UsageKeyEncipherment:  {},
	certificatesv1.UsageServerAuth:       {},
}

type csrWatcher struct {
	cs       kubernetes.Interface
	approve  bool
	warned   map[string]struct{} // detect mode: warn-logged once per CSR
	reported map[string]struct{} // approve mode: IncError fired once per CSR
}

// Setup registers the 10m sweep — always runs (detect mode
// still reports pending CSRs); `approve` only controls the action.
func Setup(d shared.Deps) error {
	approve := shared.Gate("CSR_APPROVER_ENABLED", false)
	w := &csrWatcher{
		cs: d.CS, approve: approve,
		warned: map[string]struct{}{}, reported: map[string]struct{}{},
	}
	return shared.AddPeriodic(d.Mgr, csrWatcherQueue, 10*time.Minute, w.run)
}

func (w *csrWatcher) run(ctx context.Context) error {
	log := logf.FromContext(ctx)

	// Paged list — CSRs accumulate forever on clusters where nothing
	// auto-approves them, so bound each apiserver response instead of
	// decoding the whole pile in one shot.
	csrs, err := shared.ListAll(ctx, metav1.ListOptions{Limit: 500},
		shared.CertificateSigningRequests(w.cs))
	if err != nil {
		return fmt.Errorf("list certificatesigningrequests: %w", err)
	}
	approved, pending := 0, 0
	for i := range csrs {
		csr := &csrs[i]
		if csr.Spec.SignerName != kubeletServingSigner {
			continue
		}
		if csrDecided(csr) {
			continue
		}
		if time.Since(csr.CreationTimestamp.Time) <= csrMinAge {
			continue
		}
		pending++
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
				"cap", csrMaxApprovalsRun, "csr", csr.Name, "pending", pending)
			break
		}
		if !w.validNodeCSR(ctx, csr) {
			continue
		}
		// One timestamp for both fields — the in-tree approver sets
		// LastUpdateTime AND LastTransitionTime, and consumers that
		// key on transition time (kubectl certificate, cert-manager's
		// approver parity checks) read it as unset otherwise.
		now := metav1.Now()
		csr.Status.Conditions = append(csr.Status.Conditions,
			certificatesv1.CertificateSigningRequestCondition{
				Type:               certificatesv1.CertificateApproved,
				Status:             corev1.ConditionTrue,
				Reason:             "NodeOpsAutoApprove",
				Message:            "validated by node-automation-controller",
				LastUpdateTime:     now,
				LastTransitionTime: now,
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
	// Prune the warn-once/report-once sets for CSRs that vanished
	// (approved/denied then garbage-collected, or deleted) — keyed by
	// the churn-prone csr-xxxxx names, they would grow forever. The
	// main loop breaks on the approval cap, so this needs its own
	// pass over the full list.
	seen := map[string]struct{}{}
	for i := range csrs {
		seen[csrs[i].Name] = struct{}{}
	}
	for name := range w.warned {
		if _, ok := seen[name]; !ok {
			delete(w.warned, name)
		}
	}
	for name := range w.reported {
		if _, ok := seen[name]; !ok {
			delete(w.reported, name)
		}
	}
	log.Info("sweep done", "pending", pending, "approved", approved)
	return nil
}

// validNodeCSR enforces the kubelet-serving binding a conformant
// approver applies: the requester must be system:node:<name> in
// system:nodes, the Node must exist, the usages must be the serving
// triple only, and the embedded x509 CSR must ask for THIS node's
// identity — CN=system:node:<name>, O=system:nodes, and every SAN
// drawn from the node's own status.addresses (a serving cert naming
// another host/IP is an impersonation attempt). Every rejection path
// fails closed: a malformed or unverifiable CSR is skipped, never
// approved. Failures warn every run but IncError only once per CSR.
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
	// The requester must actually sit in the nodes group — the
	// username string is just a claim, spec.groups is what the
	// apiserver authenticated.
	if !slices.Contains(csr.Spec.Groups, nodesGroup) {
		return fail("requester groups lack " + nodesGroup)
	}
	// The usages must be exactly the serving triple — the in-tree
	// kubelet-serving approver compares SETS, not subsets: a CSR
	// asking for only "server auth" mints a malformed serving cert
	// and is rejected the same as one smuggling "client auth". The
	// len check runs on the de-duplicated set so [x, x, x] cannot
	// sneak past as len 3.
	usageSet := map[certificatesv1.KeyUsage]struct{}{}
	for _, u := range csr.Spec.Usages {
		usageSet[u] = struct{}{}
	}
	if len(usageSet) != len(kubeletServingUsages) {
		return fail("usages are not exactly the kubelet-serving set")
	}
	for u := range usageSet {
		if _, ok := kubeletServingUsages[u]; !ok {
			return fail("usage not allowed for kubelet-serving: " + string(u))
		}
	}
	block, _ := pem.Decode(csr.Spec.Request)
	if block == nil || block.Type != "CERTIFICATE REQUEST" {
		return fail("spec.request is not a PEM certificate request")
	}
	req, err := x509.ParseCertificateRequest(block.Bytes)
	if err != nil {
		return fail("unparseable x509 CSR: " + err.Error())
	}
	if err := req.CheckSignature(); err != nil {
		return fail("CSR signature invalid: " + err.Error())
	}
	// The CSR must ask for the same identity the username claims —
	// not for some other node (and not for a non-node CN at all).
	if req.Subject.CommonName != nodeUserPrefix+nodeName {
		return fail("CSR CN is not " + csr.Spec.Username)
	}
	if !slices.Contains(req.Subject.Organization, nodesGroup) {
		return fail("CSR missing O=" + nodesGroup)
	}
	node, err := w.cs.CoreV1().Nodes().Get(ctx, nodeName, metav1.GetOptions{})
	if err != nil {
		if apierrors.IsNotFound(err) {
			return fail("node does not exist: " + nodeName)
		}
		// A transient Get failure is not proof the node is absent —
		// still fail closed, but record what actually happened.
		return fail("node lookup failed: " + err.Error())
	}
	// Every SAN must resolve to this node's own addresses — a
	// kubelet-serving cert may name only the node it serves.
	// Email/URI SANs have no place in a serving cert at all.
	dnsOK := map[string]struct{}{}
	ipOK := map[string]struct{}{}
	for _, a := range node.Status.Addresses {
		switch a.Type {
		case corev1.NodeInternalDNS, corev1.NodeExternalDNS, corev1.NodeHostName:
			dnsOK[a.Address] = struct{}{}
		case corev1.NodeInternalIP, corev1.NodeExternalIP:
			ipOK[a.Address] = struct{}{}
		}
	}
	if len(req.EmailAddresses) > 0 || len(req.URIs) > 0 {
		return fail("CSR carries non-DNS/IP SANs")
	}
	for _, d := range req.DNSNames {
		if _, ok := dnsOK[d]; !ok {
			return fail("CSR DNS SAN is not a node address: " + d)
		}
	}
	for _, ip := range req.IPAddresses {
		if _, ok := ipOK[ip.String()]; !ok {
			return fail("CSR IP SAN is not a node address: " + ip.String())
		}
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
