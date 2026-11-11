// Package bootwebhooks — the medik8s boot-fail-open duty of
// admission-webhook-guard.
//
// The medik8s operators ensure their default config/template CRs at
// manager startup, and that write is validated by the operator's OWN
// admission webhook (failurePolicy=Fail, from the OLM CSV
// webhookdefinitions — operator v0.13.0, the current release, has no
// upstream fix). When the webhook endpoint set is momentarily wrong the
// manager treats the ensure as fatal (exit 1) and crash-loops until
// endpoint hygiene recovers, taking the node self-remediation stack
// down exactly while the cluster churns hardest. Incident 2026-11-08:
// during the passiontech-dev mass restart the API server dialed a
// stale webhook endpoint pod IP that the CNI had already reassigned to
// a passiontech pod — its network policy blackholed the SYN, the call
// timed out after 10s, and both self-node-remediation managers
// crash-looped for ~3 days.
//
// The duty enforces failurePolicy=Ignore, ONE-WAY, on the validating
// webhook entries that sit on that boot path: every rule of the entry
// must reference one of the medik8s boot groups
// (self-node-remediation.medik8s.io, fence-agents-remediation.medik8s.io,
// remediation.medik8s.io) and only that group's boot CR kinds — the
// self-node-remediation configs/templates, the fence-agents-remediation
// configs/templates, and the node-healthcheck CRs respectively. One-way
// by design — a circuit-breaker-style restore-to-Fail would re-arm the
// boot fatality at the very next operator restart. Scope guards:
// mutating webhook configs are never touched (only the Validating list
// is swept), entries reaching anything beyond the boot CRs keep their
// declared policies (selfnoderemediations — the self-node-remediation
// CR itself — stays fail-closed: flipping it would open validation on
// the remediation CR), and non-medik8s groups are never in scope.
//
// OLM re-asserts Fail from the CSV webhookdefinitions on every
// reconcile and on each operator upgrade — this sweep re-heals that
// drift every cycle, which is the point: the enforcement must outlive
// upgrades.
//
// Gated by MEDIK8S_BOOT_FAIL_OPEN_ENABLED (on unless "false", re-read
// every sweep — the sanctioned hot-reload exception shared with the
// other admission-webhook-guard levers). With the gate off the boot
// fatality returns, so an off state is an explicit operator decision;
// the patch does mutate webhook configs the controller does not own,
// which is why the off lever exists at all.
package bootwebhooks

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	admissionv1 "k8s.io/api/admissionregistration/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	logf "sigs.k8s.io/controller-runtime/pkg/log"

	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-automation-controller/internal/apiserver/webhookguard/guardstate"
	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-automation-controller/internal/metrics"
	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-automation-controller/internal/platform/heal"
	"github.com/passiontech-global/kubernetes-cluster-automation/libs/hostkit/envx"
)

const (
	// FailOpenGate is the sub-feature gate env var (on unless "false").
	FailOpenGate = "MEDIK8S_BOOT_FAIL_OPEN_ENABLED"
)

// bootScope maps each medik8s API group whose webhook-validated CRs
// sit on an operator boot path to the CR kinds those entries may
// cover — bootResources generalized to the three boot paths (W20):
// self-node-remediation's config/template pair (the CRs the manager
// ensures at startup), fence-agents-remediation's remediation/template
// pair, and node-healthcheck's NodeHealthCheck CR. Entries touching
// anything else — above all selfnoderemediations, the
// self-node-remediation CR itself — are out of scope.
var bootScope = map[string]map[string]bool{
	"self-node-remediation.medik8s.io": {
		"selfnoderemediationconfigs":   true,
		"selfnoderemediationtemplates": true,
	},
	"fence-agents-remediation.medik8s.io": {
		"fenceagentsremediations":         true,
		"fenceagentsremediationtemplates": true,
	},
	"remediation.medik8s.io": {
		"nodehealthchecks": true,
	},
}

// Enabled reads the fail-open gate EVERY sweep — the sanctioned
// hot-reload exception (the same deliberate reload the C1 breaker and
// critical-ns levers carry): the lever flips mid-incident without a
// controller restart.
func Enabled() bool {
	return envx.Gate(FailOpenGate, true)
}

// bootWebhook reports whether a validating webhook entry sits on a
// medik8s boot path: at least one rule referencing a bootScope group
// whose resources are exclusively that group's boot CR kinds, and no
// rule — medik8s or otherwise — reaching anything beyond that scope.
// A broader entry (one covering the self-node-remediation CR too, or
// mixing groups) is disqualified whole: flipping it would open
// validation on resources this duty deliberately leaves fail-closed.
func bootWebhook(w admissionv1.ValidatingWebhook) bool {
	onBoot := false
	for _, r := range w.Rules {
		if len(r.Resources) == 0 {
			return false // empty resources = wildcard — never in scope
		}
		// allowed is the union of the boot CR kinds across the rule's
		// boot groups; a rule with no boot group at all disqualifies
		// the entry (the old "any non-medik8s rule" guard, generalized).
		var allowed map[string]bool
		for _, g := range r.APIGroups {
			if res, ok := bootScope[g]; ok {
				if allowed == nil {
					allowed = map[string]bool{}
				}
				for resName := range res {
					allowed[resName] = true
				}
			}
		}
		if allowed == nil {
			return false
		}
		for _, res := range r.Resources {
			if !allowed[res] {
				return false // out-of-scope resource — never flip the entry
			}
		}
		onBoot = true
	}
	return onBoot
}

// webhookPatchEntry is one strategic-merge list item: the list merges
// by name, so only the entries being flipped need to appear.
type webhookPatchEntry struct {
	Name          string                         `json:"name"`
	FailurePolicy *admissionv1.FailurePolicyType `json:"failurePolicy"`
}

type vwcPatch struct {
	Webhooks []webhookPatchEntry `json:"webhooks"`
}

// Sweep enforces failurePolicy=Ignore on every boot-path entry of
// every validating webhook config in the snapshot, building ONE
// strategic-merge patch per config. The metrics trip only after the
// patch landed, so a failed patch retries next sweep without
// double-counting. Snapshot list failures are returned — the duty's
// only input is that list, so an error must surface (fail loud) rather
// than silently skipping the enforcement run.
func Sweep(ctx context.Context, snap *guardstate.Snapshot) error {
	if !Enabled() {
		return nil
	}
	if snap.VWCErr != nil {
		return fmt.Errorf("boot-webhook fail-open: list validating webhook configs: %w", snap.VWCErr)
	}
	if snap.VWC == nil {
		return nil
	}
	var errs []error
	log := logf.Log.WithName("bootwebhooks")
	for i := range snap.VWC.Items {
		cfg := &snap.VWC.Items[i]

		var patch vwcPatch
		for j := range cfg.Webhooks {
			w := &cfg.Webhooks[j]
			// failurePolicy nil is the API default Fail — a
			// boot-path entry that never declared a policy is
			// exactly the fail-closed case this duty exists to
			// soften, so only an explicit Ignore skips the patch.
			if w.FailurePolicy != nil && *w.FailurePolicy == admissionv1.Ignore {
				continue
			}
			if !bootWebhook(*w) {
				continue
			}
			policy := admissionv1.Ignore
			patch.Webhooks = append(patch.Webhooks, webhookPatchEntry{Name: w.Name, FailurePolicy: &policy})
		}
		if len(patch.Webhooks) == 0 {
			continue
		}

		// SSA ping-pong defense: the fail-open flip fights Flux when
		// the config is Git-owned — past the Heal-Revert-Loop
		// threshold the patch skips (the webhook stays fail-closed
		// against Git's wish) and the conflict counter fires so the
		// failurePolicy is fixed at the Git source.
		if !heal.FluxPatchGate(guardstate.KindValidating, cfg,
			guardstate.KindValidating+"/"+cfg.Name, time.Now()) {
			log.Info("skip heal: Flux Heal-Revert Loop detected — boot-webhook fail-open patch deferred",
				"config", cfg.Name)
			continue
		}

		payload, err := json.Marshal(patch)
		if err != nil { // unreachable for this shape, but keep the guard honest
			errs = append(errs, fmt.Errorf("boot-webhook fail-open: marshal patch %s: %w", cfg.Name, err))
			continue
		}
		patched, err := snap.G.CS.AdmissionregistrationV1().ValidatingWebhookConfigurations().Patch(
			ctx, cfg.Name, types.StrategicMergePatchType, payload, metav1.PatchOptions{}, "")
		if err != nil {
			if apierrors.IsNotFound(err) {
				continue // deleted between list and patch — next sweep sees the truth
			}
			errs = append(errs, fmt.Errorf("boot-webhook fail-open: patch %s: %w", cfg.Name, err))
			continue
		}
		// Sync the in-memory snapshot so the critical.Sweep reading
		// snap right after sees the patched FailurePolicy, not the
		// pre-patch Ignore the list returned.
		snap.SetVWC(patched)
		for _, e := range patch.Webhooks {
			metrics.BootWebhookFailOpenTotal.WithLabelValues(cfg.Name, e.Name).Inc()
			log.Info("fail-open enforced", "config", cfg.Name, "webhook", e.Name)
		}
	}
	return errors.Join(errs...)
}
