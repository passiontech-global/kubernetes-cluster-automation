// imagepull_secret_auditor.go — the imagepull-secret-auditor check
// (pullsecret-audit): audits the kubernetes.io/dockerconfigjson Secrets that
// imagePullSecrets actually reference — on Pods, ServiceAccounts and
// Deployment/StatefulSet/DaemonSet pod templates — and flags ones
// that are missing, malformed, the wrong type, or carrying an
// embedded JWT expiring inside 7 days (or already expired). Also audits
// active Pods and workload templates pulling private-registry images without
// any imagePullSecrets on either the Pod/template or its effective
// ServiceAccount (K8s 1.35+ KubeletEnsureSecretPulledImages readiness).
package gitops

import (
	"context"
	"encoding/base64"
	json "encoding/json/v2"
	"fmt"
	"slices"
	"strings"
	"time"

	"github.com/go-logr/logr"
	"github.com/prometheus/client_golang/prometheus"
	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	logf "sigs.k8s.io/controller-runtime/pkg/log"
	ctrlmetrics "sigs.k8s.io/controller-runtime/pkg/metrics"

	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-automation-controller/internal/platform/kube"
	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-automation-controller/internal/platform/state"
	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-automation-controller/internal/probefw"
)

// imagePullSecretAuditorCheck is the pullsecret-audit pull-secret hygiene
// auditor.
type imagePullSecretAuditorCheck struct {
	*probefw.Deps

	// emitted is the emitted-gauge ledger for unhealthy Secret objects — a
	// tuple that stops being reported gets DeleteLabelValues'd rather than
	// leaking a stale 1.
	emitted state.GaugeLedger[string]

	// missingEmitted is the emitted-gauge ledger for private-registry images
	// lacking imagePullSecrets on Pod/template and ServiceAccount.
	missingEmitted state.GaugeLedger[string]

	// eventCooldown deduplicates MissingImagePullSecret Warning Events.
	eventCooldown state.CooldownSet

	// cycle counts Runs for the HeavyScanCycles cadence — the
	// pull-secret census (pods + ServiceAccounts + every workload
	// pod template, then the typed Secret list) is heavy enough to
	// audit every 6th sweep (~30m); between audits the last tuples
	// and findings carry forward so neither the gauge nor the
	// verdict flaps on "not evaluated this cycle".
	cycle        uint64
	lastFindings []string
}

// NewImagePullSecretAuditorCheck builds the pullsecret-audit check — the
// emitted ledgers are zero-value usable.
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

	imagePullMissingSecretEventReason   = "MissingImagePullSecret"
	imagePullMissingSecretEventCooldown = 6 * time.Hour
)

var (
	// pullsecret-audit — pull-secret hygiene.
	imagePullSecretUnhealthyGauge = prometheus.NewGaugeVec(prometheus.GaugeOpts{
		Name: "node_automation_imagepull_secret_unhealthy",
		Help: "1 while an imagePullSecrets-referenced Secret is missing, malformed, wrong-typed, or carries a JWT expiring <7d — pullsecret-audit.",
	}, []string{"namespace", "secret", "reason"})

	// K8s 1.35+ KubeletEnsureSecretPulledImages readiness.
	imagePullMissingSecretGauge = prometheus.NewGaugeVec(prometheus.GaugeOpts{
		Name: "node_automation_imagepull_missing_secret",
		Help: "1 while an active Pod or workload template pulls a private-registry image without imagePullSecrets on itself or its ServiceAccount (K8s 1.35+ KubeletEnsureSecretPulledImages readiness).",
	}, []string{"namespace", "kind", "name", "registry"})
)

func init() {
	ctrlmetrics.Registry.MustRegister(
		imagePullSecretUnhealthyGauge,
		imagePullMissingSecretGauge,
	)
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
		Auth          string `json:"auth,case:ignore"`
		IdentityToken string `json:"identitytoken,case:ignore"`
		Password      string `json:"password,case:ignore"`
	} `json:"auths,case:ignore"`
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
	log := logf.FromContext(ctx)
	now := p.Now()
	p.eventCooldown.PruneExpired(now, imagePullMissingSecretEventCooldown)

	// Cadence divider: cycles 2..HeavyScanCycles skip the census
	// entirely and carry the last audit's tuples + findings — an
	// unhealthy pull secret does not heal itself in 5 minutes, so a
	// 30-minute detection bound is the right cost/benefit for the
	// heaviest read in the gitops tree. A FAILED audit gives its
	// cadence slot back (cycle--) so the next sweep retries the
	// census — a pass-1 failure must not carry stale tuples through
	// passes 2-6 and mask fresh evidence for 25 minutes.
	p.cycle++
	if p.cycle%probefw.HeavyScanCycles != 1 {
		var carried probefw.SweepReport
		for k, lv := range p.emitted.Last() {
			carried.Carry(k, lv)
		}
		for _, f := range p.lastFindings {
			carried.Find(f)
		}
		carried.Close(&p.emitted, imagePullSecretUnhealthyGauge.DeleteLabelValues)

		var carriedMissing probefw.SweepReport
		for k, lv := range p.missingEmitted.Last() {
			carriedMissing.Carry(k, lv)
		}
		carriedMissing.Close(&p.missingEmitted, imagePullMissingSecretGauge.DeleteLabelValues)

		return carried.Verdict("unhealthy image pull secrets: ", ", ")
	}

	census, err := p.collectPullSecretCensus(ctx)
	if err != nil {
		p.cycle-- // failed audit — retry next sweep, don't consume the slot
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
			Limit:           probefw.HealthListPageSize,
			ResourceVersion: "0",
			FieldSelector:   "type=" + string(corev1.SecretTypeDockerConfigJson),
		},
		kube.Secrets(p.CS, metav1.NamespaceAll))
	if err != nil {
		p.cycle-- // failed audit — retry next sweep, don't consume the slot
		return probefw.Result{Infra: fmt.Errorf("list pull secrets: %w", err)}
	}
	byRef := make(map[pullSecretRef]*corev1.Secret, len(secs))
	for i := range secs {
		byRef[pullSecretRef{ns: secs[i].Namespace, name: secs[i].Name}] = &secs[i]
	}

	var rep probefw.SweepReport
	for ref := range census.refs {
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
				// The ref's last-emitted tuple(s) Carry + re-Find —
				// "can't tell" is not "resolved": dropping them here
				// would prune a live series and read the flap as a
				// healed secret.
				rep.InfraErr(fmt.Errorf("get secret %s/%s: %w",
					ref.ns, ref.name, err))
				for k, lv := range p.emitted.Last() {
					if len(lv) == 3 && lv[0] == ref.ns && lv[1] == ref.name {
						rep.Carry(k, lv)
						rep.Find(fmt.Sprintf("%s/%s(%s)", lv[0], lv[1], lv[2]))
					}
				}
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

	var missingRep probefw.SweepReport
	p.auditMissingPullSecrets(ctx, log, now, census, &rep, &missingRep)
	missingRep.Close(&p.missingEmitted, imagePullMissingSecretGauge.DeleteLabelValues)

	// Snapshot the findings for the carry-forward cycles — rep is
	// per-Run, lastFindings is what the skipped sweeps re-assert.
	p.lastFindings = append([]string(nil), rep.Findings()...)
	return rep.Result(&p.emitted, imagePullSecretUnhealthyGauge.DeleteLabelValues,
		"unhealthy image pull secrets: ", ", ")
}

type pullSecretCensus struct {
	refs             map[pullSecretRef]bool
	saHasPullSecrets map[string]bool
	pods             []corev1.Pod
	deps             []appsv1.Deployment
	stss             []appsv1.StatefulSet
	dss              []appsv1.DaemonSet
}

// collectPullSecretCensus gathers the deduped (ns,name) set of every
// pull secret in use plus the Pod/ServiceAccount/workload lists needed for
// K8s 1.35+ private-registry pull-secret readiness auditing (zero extra API calls).
func (p *imagePullSecretAuditorCheck) collectPullSecretCensus(ctx context.Context) (*pullSecretCensus, error) {
	c := &pullSecretCensus{
		refs:             map[pullSecretRef]bool{},
		saHasPullSecrets: map[string]bool{},
	}
	add := func(ns string, lrefs []corev1.LocalObjectReference) bool {
		hasAny := false
		for _, r := range lrefs {
			if r.Name != "" {
				c.refs[pullSecretRef{ns: ns, name: r.Name}] = true
				hasAny = true
			}
		}
		return hasAny
	}

	pods, err := p.AllPods(ctx)
	if err != nil {
		return nil, fmt.Errorf("list pods: %w", err)
	}
	c.pods = pods
	for i := range pods {
		add(pods[i].Namespace, pods[i].Spec.ImagePullSecrets)
	}

	sas, err := p.AllServiceAccounts(ctx)
	if err != nil {
		return nil, fmt.Errorf("list serviceaccounts: %w", err)
	}
	for i := range sas {
		if add(sas[i].Namespace, sas[i].ImagePullSecrets) {
			c.saHasPullSecrets[sas[i].Namespace+"/"+sas[i].Name] = true
		}
	}

	deps, err := p.AllDeployments(ctx)
	if err != nil {
		return nil, fmt.Errorf("list deployments: %w", err)
	}
	c.deps = deps
	for i := range deps {
		add(deps[i].Namespace, deps[i].Spec.Template.Spec.ImagePullSecrets)
	}

	stss, err := p.AllStatefulSets(ctx)
	if err != nil {
		return nil, fmt.Errorf("list statefulsets: %w", err)
	}
	c.stss = stss
	for i := range stss {
		add(stss[i].Namespace, stss[i].Spec.Template.Spec.ImagePullSecrets)
	}

	dss, err := p.AllDaemonSets(ctx)
	if err != nil {
		return nil, fmt.Errorf("list daemonsets: %w", err)
	}
	c.dss = dss
	for i := range dss {
		add(dss[i].Namespace, dss[i].Spec.Template.Spec.ImagePullSecrets)
	}

	return c, nil
}

var publicImageRegistries = map[string]bool{
	"docker.io":            true,
	"index.docker.io":      true,
	"registry-1.docker.io": true,
	"registry.k8s.io":      true,
	"k8s.gcr.io":           true,
	"mirror.gcr.io":        true,
	"ghcr.io":              true,
	"quay.io":              true,
	"gcr.io":               true,
	"us.gcr.io":            true,
	"eu.gcr.io":            true,
	"asia.gcr.io":          true,
	// Multi-regional Google Artifact Registry hosts used by public OSS
	// registries (e.g. goldilocks, network-problem-detector).
	"us-docker.pkg.dev":          true,
	"europe-docker.pkg.dev":      true,
	"asia-docker.pkg.dev":        true,
	"mcr.microsoft.com":          true,
	"public.ecr.aws":             true,
	"ecr-public.aws.com":         true,
	"cr.l5d.io":                  true,
	"cr.strrl.dev":               true,
	"docker.dragonflydb.io":      true,
	"cgr.dev":                    true,
	"nvcr.io":                    true,
	"docker.elastic.co":          true,
	"registry.access.redhat.com": true,
}

func imageRegistry(image string) (registry string, hasExplicitDomain bool) {
	img := strings.TrimSpace(image)
	if img == "" {
		return "", false
	}
	slash := strings.IndexByte(img, '/')
	if slash < 0 {
		// Short name e.g. "nginx:1.25" -> Docker Hub.
		return "docker.io", false
	}
	first := img[:slash]
	if !strings.ContainsAny(first, ".:") && first != "localhost" {
		// Org/repo e.g. "library/nginx:1.25" -> Docker Hub.
		return "docker.io", false
	}
	return strings.ToLower(first), true
}

func isPrivateRegistryImage(image string) (string, bool) {
	reg, explicit := imageRegistry(image)
	if !explicit || reg == "" {
		return "", false
	}
	host := reg
	if colon := strings.IndexByte(reg, ':'); colon >= 0 {
		host = reg[:colon]
	}
	if host == "localhost" || publicImageRegistries[host] {
		return "", false
	}
	return reg, true
}

func hasEffectivePullSecret(ns, saName string, lrefs []corev1.LocalObjectReference, saHasPullSecrets map[string]bool) bool {
	for _, r := range lrefs {
		if r.Name != "" {
			return true
		}
	}
	if saName == "" {
		saName = "default"
	}
	return saHasPullSecrets[ns+"/"+saName]
}

func privateRegistriesForPodSpec(spec *corev1.PodSpec) []string {
	seen := map[string]bool{}
	check := func(image string) {
		if reg, ok := isPrivateRegistryImage(image); ok {
			seen[reg] = true
		}
	}
	for i := range spec.InitContainers {
		check(spec.InitContainers[i].Image)
	}
	for i := range spec.Containers {
		check(spec.Containers[i].Image)
	}
	for i := range spec.EphemeralContainers {
		check(spec.EphemeralContainers[i].Image)
	}
	if len(seen) == 0 {
		return nil
	}
	out := make([]string, 0, len(seen))
	for reg := range seen {
		out = append(out, reg)
	}
	slices.Sort(out)
	return out
}

func (p *imagePullSecretAuditorCheck) auditMissingPullSecrets(
	ctx context.Context,
	log logr.Logger,
	now time.Time,
	census *pullSecretCensus,
	rep *probefw.SweepReport,
	missingRep *probefw.SweepReport,
) {
	record := func(apiVersion, kind, ns, name string, uid types.UID, spec *corev1.PodSpec, saName string) {
		if hasEffectivePullSecret(ns, saName, spec.ImagePullSecrets, census.saHasPullSecrets) {
			return
		}
		for _, reg := range privateRegistriesForPodSpec(spec) {
			key := ns + "/" + kind + "/" + name + "/" + reg
			missingRep.Flag(imagePullMissingSecretGauge, key, []string{ns, kind, name, reg})
			rep.Find(fmt.Sprintf("%s/%s/%s(missing_pull_secret:%s)", ns, kind, name, reg))
			p.emitMissingPullSecretEvent(ctx, log, now, apiVersion, kind, ns, name, uid, reg)
		}
	}

	for i := range census.pods {
		pod := &census.pods[i]
		if pod.DeletionTimestamp != nil ||
			pod.Status.Phase == corev1.PodSucceeded ||
			pod.Status.Phase == corev1.PodFailed {
			continue
		}
		if pod.Annotations["kubernetes.io/config.mirror"] != "" {
			continue
		}
		saName := pod.Spec.ServiceAccountName
		if saName == "" {
			saName = pod.Spec.DeprecatedServiceAccount
		}
		record("v1", "Pod", pod.Namespace, pod.Name, pod.UID, &pod.Spec, saName)
	}

	for i := range census.deps {
		dep := &census.deps[i]
		if dep.DeletionTimestamp != nil {
			continue
		}
		saName := dep.Spec.Template.Spec.ServiceAccountName
		if saName == "" {
			saName = dep.Spec.Template.Spec.DeprecatedServiceAccount
		}
		record("apps/v1", "Deployment", dep.Namespace, dep.Name, dep.UID, &dep.Spec.Template.Spec, saName)
	}

	for i := range census.stss {
		sts := &census.stss[i]
		if sts.DeletionTimestamp != nil {
			continue
		}
		saName := sts.Spec.Template.Spec.ServiceAccountName
		if saName == "" {
			saName = sts.Spec.Template.Spec.DeprecatedServiceAccount
		}
		record("apps/v1", "StatefulSet", sts.Namespace, sts.Name, sts.UID, &sts.Spec.Template.Spec, saName)
	}

	for i := range census.dss {
		ds := &census.dss[i]
		if ds.DeletionTimestamp != nil {
			continue
		}
		saName := ds.Spec.Template.Spec.ServiceAccountName
		if saName == "" {
			saName = ds.Spec.Template.Spec.DeprecatedServiceAccount
		}
		record("apps/v1", "DaemonSet", ds.Namespace, ds.Name, ds.UID, &ds.Spec.Template.Spec, saName)
	}
}

func (p *imagePullSecretAuditorCheck) emitMissingPullSecretEvent(
	ctx context.Context,
	log logr.Logger,
	now time.Time,
	apiVersion, kind, ns, name string,
	uid types.UID,
	reg string,
) {
	cooldownKey := "missingpullsec." + kind + "." + ns + "." + name + "." + reg
	if p.eventCooldown.CooledDown(cooldownKey, imagePullMissingSecretEventCooldown, now) {
		return
	}
	if err := kube.EmitWarningEvent(ctx, p.CS, kube.WarningEvent{
		Name:      kube.TruncatedEventName(cooldownKey, cooldownKey, now),
		Namespace: ns,
		Regarding: corev1.ObjectReference{
			APIVersion: apiVersion,
			Kind:       kind,
			Namespace:  ns,
			Name:       name,
			UID:        uid,
		},
		Reason:            imagePullMissingSecretEventReason,
		Note:              fmt.Sprintf("%s %s/%s pulls private registry %s without imagePullSecrets on workload or ServiceAccount", kind, ns, name, reg),
		ReportingInstance: p.Name,
		Now:               now,
	}); err != nil {
		log.Info("WARN: MissingImagePullSecret event create failed (RBAC?)",
			"kind", kind, "object", ns+"/"+name, "registry", reg, "error", err)
		return
	}
	p.eventCooldown.Stamp(cooldownKey, now)
	log.Info("EVENT: MissingImagePullSecret", "kind", kind, "object", ns+"/"+name, "registry", reg)
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
