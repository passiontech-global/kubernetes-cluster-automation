// db_operator_heals.go — the generic db-operator heal of the
// stateful-masterless-services check (W4): a masterless StatefulSet
// owned by a known db operator gets that operator's pod bounced to
// force re-election — dbOperatorFor attributes the STS to its
// operator, dbOperatorPodPrefixes resolves the Deployment/pod-name
// spellings the operator answers to, and healDBOperator deletes the
// oldest Running pod on a per-operator cooldown. Split out of
// stateful_masterless_services.go — see that file for the check.
package datastore

import (
	"context"
	"strings"
	"time"

	"github.com/go-logr/logr"
	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"

	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-automation-controller/internal/platform/heal"
)

// dbOperatorNames are the operators whose role-assignment wedge this
// check heals — matched against the StatefulSet's labels, pod-template
// labels and ownerReferences. The long Percona deployment names sit
// alongside the short chart aliases (W10-FIX4): an STS owned by the
// percona-xtradb-cluster-operator Deployment labels itself with the
// long name, while older charts/labels still carry pxc-operator.
var dbOperatorNames = []string{
	"mariadb-operator", "pxc-operator", "psmdb-operator",
	"pg-operator", "scylla-operator",
	"percona-xtradb-cluster-operator", "percona-server-mongodb-operator",
	"percona-postgresql-operator",
}

// dbOperatorDeploymentAliases groups the Deployment/pod-name spellings
// one logical db operator answers to (W10-FIX4): the short chart alias
// (pxc-operator) and the long upstream Deployment name
// (percona-xtradb-cluster-operator) produce DIFFERENT pod name
// prefixes, so a heal keyed on whichever spelling dbOperatorFor
// matched would miss the real pods.
var dbOperatorDeploymentAliases = map[string][]string{
	"percona-xtradb-cluster-operator": {"percona-xtradb-cluster-operator", "pxc-operator"},
	"percona-server-mongodb-operator": {"percona-server-mongodb-operator", "psmdb-operator"},
	"percona-postgresql-operator":     {"percona-postgresql-operator", "pg-operator"},
}

// dbOperatorPodPrefixes returns every pod-name prefix the logical
// operator may deploy under — the alias group when one exists, else
// the bare operator name. Order is stable: the canonical (key) name
// first, then aliases.
func dbOperatorPodPrefixes(operator string) []string {
	if aliases, ok := dbOperatorDeploymentAliases[operator]; ok {
		return aliases
	}
	for _, aliases := range dbOperatorDeploymentAliases {
		for _, a := range aliases {
			if a == operator {
				return aliases
			}
		}
	}
	return []string{operator}
}

// dbOperatorFor returns the db operator name owning this StatefulSet,
// or "" — matching any label value on the STS or its pod template
// containing the operator name (managed-by/part-of/created-by and
// operator-specific labels all end up containing it), plus
// ownerReference names.
func dbOperatorFor(sts *appsv1.StatefulSet) string {
	for _, lbls := range []map[string]string{sts.Labels, sts.Spec.Template.Labels} {
		for _, v := range lbls {
			for _, op := range dbOperatorNames {
				if strings.Contains(v, op) {
					return op
				}
			}
		}
	}
	for _, ref := range sts.OwnerReferences {
		for _, op := range dbOperatorNames {
			if strings.Contains(ref.Name, op) {
				return op
			}
		}
	}
	return ""
}

// healDBOperator deletes a pod of the responsible db operator to
// force master re-election — only fires while !MaintenanceActive
// (the caller guarantees the >=5m zero-endpoint streak and
// sts.Status.ReadyReplicas > 0; the check itself only reaches here
// for ready STS). 30m per-operator cooldown on the in-RAM ledger.
//
// probefw.BounceOperatorPod carries the whole preamble (per-operator
// cooldown + maintenance mutex fail-closed, cluster-wide paged list —
// the operator pod's namespace is not fixed across installs — and the
// UID-preconditioned delete + census invalidate + heal count under
// the operator name); the pick keeps the oldest-Running-target choice
// and the W10-FIX4 alias-prefix match local.
func (p *statefulMasterlessCheck) healDBOperator(ctx context.Context, log logr.Logger,
	sig masterSvc, operator string, now time.Time) {
	const dbOperatorHealCooldown = 30 * time.Minute
	deleted := p.BounceOperatorPod(ctx, log, operator, "",
		func(pods []corev1.Pod) []*corev1.Pod {
			// The Percona operators answer to two Deployment
			// spellings (W10-FIX4) — every alias prefix is tried so
			// a short-name match still finds the long-named pods.
			target := heal.OldestRunningPod(pods,
				dbOperatorPodPrefixes(operator)...)
			if target == nil {
				return nil
			}
			return []*corev1.Pod{target}
		},
		&p.Heals, operator, dbOperatorHealCooldown, now)
	if deleted == 0 {
		return
	}
	log.Info("DELETE: db operator pod — masterless service, forcing re-election",
		"operator", operator, "service", sig.ns+"/"+sig.svc,
		"statefulset", sig.sts.Name)
}
