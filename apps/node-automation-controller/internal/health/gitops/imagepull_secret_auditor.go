// imagepull_secret_auditor.go — the imagepull-secret-auditor check
// (pullsecret-audit): audits the kubernetes.io/dockerconfigjson Secrets that
// imagePullSecrets actually reference — on Pods, ServiceAccounts and
// Deployment/StatefulSet/DaemonSet pod templates — and flags ones
// that are missing, malformed, the wrong type, or carrying an
// embedded JWT expiring inside 7 days (or already expired). A dead
// pull secret is the quietest ImagePullBackOff cause on the cluster
// — nothing surfaces it until a rollout or reschedule needs the
// image.
package gitops

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	ctrlmetrics "sigs.k8s.io/controller-runtime/pkg/metrics"

	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-automation-controller/internal/platform/kube"
	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-automation-controller/internal/platform/state"
	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-automation-controller/internal/probefw"
)

// imagePullSecretAuditorCheck is the pullsecret-audit pull-secret hygiene
// auditor.
type imagePullSecretAuditorCheck struct {
	*probefw.Deps

	// emitted is the emitted-gauge ledger — a tuple that stops being
	// reported gets DeleteLabelValues'd rather than leaking a stale 1.
	emitted state.GaugeLedger[string]
}

// NewImagePullSecretAuditorCheck builds the pullsecret-audit check — the
// emitted ledger is zero-value usable.
func NewImagePullSecretAuditorCheck(d *probefw.Deps) probefw.Check {
	return &imagePullSecretAuditorCheck{Deps: d}
}

const (
	// CheckNameImagePullSecretAuditor is the check's
	// kuberhealthy_check label value — pullsecret-audit; not a ported
	// HealthCheck but reports under its own check name so the
	// generic FAIL alerting path covers it.
	CheckNameImagePullSecretAuditor = "imagepull-secret-auditor"
	// imagePullJWTSoonWindow is the expiry horizon an embedded JWT
	// must clear — a registry token inside it is already on the
	// path to ImagePullBackOff.
	imagePullJWTSoonWindow = 7 * 24 * time.Hour
)

var (
	// pullsecret-audit — pull-secret hygiene.
	imagePullSecretUnhealthyGauge = prometheus.NewGaugeVec(prometheus.GaugeOpts{
		Name: "node_automation_imagepull_secret_unhealthy",
		Help: "1 while an imagePullSecrets-referenced Secret is missing, malformed, wrong-typed, or carries a JWT expiring <7d — pullsecret-audit.",
	}, []string{"namespace", "secret", "reason"})
)

func init() {
	ctrlmetrics.Registry.MustRegister(
		imagePullSecretUnhealthyGauge)
}

// pullSecretRef is the (namespace, name) identity of a referenced
// pull Secret — a struct key, not a joined string, so the emit path
// never SplitN's it back apart.
type pullSecretRef struct {
	ns, name string
}

// dockerConfig mirrors the .dockerconfigjson document — only the
// fields the audit reads.
type dockerConfig struct {
	Auths map[string]struct {
		Auth          string `json:"auth"`
		IdentityToken string `json:"identitytoken"`
		Password      string `json:"password"`
	} `json:"auths"`
}

// Run enumerates every pull secret in use — pod
// spec.imagePullSecrets (the admission-resolved set, which already
// folds in the ServiceAccount's), ServiceAccount imagePullSecrets,
// and the pod templates of Deployments/StatefulSets/DaemonSets (so a
// scaled-to-zero workload's secret is still audited) — then audits
// each referenced Secret: missing, unexpected type, unparseable
// .dockerconfigjson, or an embedded JWT whose exp lands inside the
// 7-day horizon (or already passed). Any census failure aborts as
// Infra — auditing on a partial reference set risks flagging on
// incomplete data.
func (p *imagePullSecretAuditorCheck) Run(ctx context.Context) probefw.Result {
	now := p.Now()
	refs, err := p.collectPullSecretRefs(ctx)
	if err != nil {
		return probefw.Result{Infra: err}
	}

	// One paginated census of the pull-secret type replaces the
	// per-reference Get storm — the refs set reaches ~150 entries
	// (every pod, ServiceAccount and workload template), and each Get
	// was a separate apiserver round trip. The type field selector
	// keeps the payload to just the secrets this audit reads;
	// references to any OTHER type (missing, kubernetes.io/dockercfg,
	// unexpected_type) fall through to a single Get that resolves
	// which.
	secs, err := kube.ListAll(ctx,
		metav1.ListOptions{
			Limit:         probefw.HealthListPageSize,
			FieldSelector: "type=" + string(corev1.SecretTypeDockerConfigJson),
		},
		kube.Secrets(p.CS, metav1.NamespaceAll))
	if err != nil {
		return probefw.Result{Infra: fmt.Errorf("list pull secrets: %w", err)}
	}
	byRef := make(map[pullSecretRef]*corev1.Secret, len(secs))
	for i := range secs {
		byRef[pullSecretRef{ns: secs[i].Namespace, name: secs[i].Name}] = &secs[i]
	}

	var rep probefw.SweepReport
	for ref := range refs {
		sec, ok := byRef[ref]
		if !ok {
			var err error
			sec, err = p.CS.CoreV1().Secrets(ref.ns).
				Get(ctx, ref.name, metav1.GetOptions{})
			switch {
			case apierrors.IsNotFound(err):
				rep.Emit(imagePullSecretUnhealthyGauge,
					ref.ns+"/"+ref.name+"/missing",
					[]string{ref.ns, ref.name, "missing"},
					fmt.Sprintf("%s/%s(missing)", ref.ns, ref.name))
				continue
			case err != nil:
				// A single unreadable Secret is a tolerated
				// sub-failure: the audit continues on the rest and the
				// sweep still reports the Infra so the error counts.
				rep.InfraErr(fmt.Errorf("get secret %s/%s: %w",
					ref.ns, ref.name, err))
				continue
			}
		}
		reasons := auditPullSecret(sec, now)
		if len(reasons) == 0 {
			continue
		}
		reason := strings.Join(reasons, "+")
		rep.Emit(imagePullSecretUnhealthyGauge,
			ref.ns+"/"+ref.name+"/"+reason,
			[]string{ref.ns, ref.name, reason},
			fmt.Sprintf("%s/%s(%s)", ref.ns, ref.name, reason))
	}
	return rep.Result(&p.emitted, imagePullSecretUnhealthyGauge.DeleteLabelValues,
		"unhealthy image pull secrets: ", ", ")
}

// collectPullSecretRefs gathers the deduped (ns,name) set of every
// pull secret in use — pods (the authoritative runtime reference,
// which already includes ServiceAccount-injected entries), the
// ServiceAccounts themselves, and the pod templates of
// Deployments/StatefulSets/DaemonSets. The workload templates matter
// for the pullsecret-audit scenario specifically: a downscaler-parked
// replicas:0 Deployment has no pods, but its stale secret still
// waits to bite the next scale-up.
func (p *imagePullSecretAuditorCheck) collectPullSecretRefs(ctx context.Context) (map[pullSecretRef]bool, error) {
	refs := map[pullSecretRef]bool{}
	add := func(ns string, lrefs []corev1.LocalObjectReference) {
		for _, r := range lrefs {
			if r.Name != "" {
				refs[pullSecretRef{ns: ns, name: r.Name}] = true
			}
		}
	}

	pods, err := p.AllPods(ctx)
	if err != nil {
		return nil, fmt.Errorf("list pods: %w", err)
	}
	for i := range pods {
		add(pods[i].Namespace, pods[i].Spec.ImagePullSecrets)
	}

	sas, err := kube.ListAll(ctx,
		metav1.ListOptions{Limit: probefw.HealthListPageSize},
		kube.ServiceAccounts(p.CS, metav1.NamespaceAll))
	if err != nil {
		return nil, fmt.Errorf("list serviceaccounts: %w", err)
	}
	for i := range sas {
		add(sas[i].Namespace, sas[i].ImagePullSecrets)
	}

	deps, err := p.AllDeployments(ctx)
	if err != nil {
		return nil, fmt.Errorf("list deployments: %w", err)
	}
	for i := range deps {
		add(deps[i].Namespace, deps[i].Spec.Template.Spec.ImagePullSecrets)
	}

	stss, err := p.AllStatefulSets(ctx)
	if err != nil {
		return nil, fmt.Errorf("list statefulsets: %w", err)
	}
	for i := range stss {
		add(stss[i].Namespace, stss[i].Spec.Template.Spec.ImagePullSecrets)
	}

	dss, err := p.AllDaemonSets(ctx)
	if err != nil {
		return nil, fmt.Errorf("list daemonsets: %w", err)
	}
	for i := range dss {
		add(dss[i].Namespace, dss[i].Spec.Template.Spec.ImagePullSecrets)
	}

	return refs, nil
}

// auditPullSecret classifies one referenced Secret — returns the
// sorted list of reason strings, empty when healthy.
func auditPullSecret(sec *corev1.Secret, now time.Time) []string {
	switch sec.Type {
	case corev1.SecretTypeDockercfg:
		// kubernetes.io/dockercfg is a valid pull-secret type — the
		// legacy single-registry document. No JWT decode (the format
		// predates it); presence and type are the audit.
		return nil
	case corev1.SecretTypeDockerConfigJson:
	default:
		return []string{"unexpected_type"}
	}
	raw, ok := sec.Data[corev1.DockerConfigJsonKey]
	if !ok || len(raw) == 0 {
		return []string{"malformed_json"}
	}
	var cfg dockerConfig
	if err := json.Unmarshal(raw, &cfg); err != nil {
		return []string{"malformed_json"}
	}
	// The earliest embedded credential expiry wins — one auths
	// entry expiring makes the whole secret unreliable.
	var earliest time.Time
	for _, entry := range cfg.Auths {
		for _, token := range pullSecretTokens(entry.Auth, entry.Password, entry.IdentityToken) {
			exp, ok := jwtExpiry(token)
			if !ok {
				continue
			}
			if earliest.IsZero() || exp.Before(earliest) {
				earliest = exp
			}
		}
	}
	switch {
	case earliest.IsZero():
		return nil // no JWTs — opaque passwords carry no clock
	case !earliest.After(now):
		return []string{"jwt_expired"}
	case earliest.Before(now.Add(imagePullJWTSoonWindow)):
		return []string{"jwt_expiring"}
	default:
		return nil
	}
}

// pullSecretTokens collects the credential candidate strings from one
// auths entry: the password half of the base64 "user:pass" auth
// blob, the plaintext password field, and the identitytoken. Not
// every entry carries every field.
func pullSecretTokens(auth, password, identityToken string) []string {
	var out []string
	if auth != "" {
		if decoded, err := base64.StdEncoding.DecodeString(auth); err == nil {
			// "username:password" — the password half may be a JWT;
			// split once so a ':' inside the password survives.
			if _, pass, found := strings.Cut(string(decoded), ":"); found && pass != "" {
				out = append(out, pass)
			}
		}
	}
	if password != "" {
		out = append(out, password)
	}
	if identityToken != "" {
		out = append(out, identityToken)
	}
	return out
}

// jwtExpiry extracts the exp claim from a compact-serialized JWT —
// three base64url segments, the middle one JSON. ok=false on any
// deviation: an opaque password that happens not to be a JWT is not
// evidence, it's just a password.
func jwtExpiry(token string) (time.Time, bool) {
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		return time.Time{}, false
	}
	payload, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return time.Time{}, false
	}
	var claims struct {
		Exp int64 `json:"exp"`
	}
	if err := json.Unmarshal(payload, &claims); err != nil || claims.Exp == 0 {
		return time.Time{}, false
	}
	return time.Unix(claims.Exp, 0), true
}
