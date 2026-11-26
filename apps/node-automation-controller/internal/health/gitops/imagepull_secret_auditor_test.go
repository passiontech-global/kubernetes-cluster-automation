// imagepull_secret_auditor_test.go — the pullsecret-audit pull-secret hygiene
// auditor driven through the fake clientset.
package gitops

import (
	"context"
	"encoding/base64"
	json "encoding/json/v2"
	"fmt"
	"testing"
	"time"

	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/kubernetes/fake"
	corev1client "k8s.io/client-go/kubernetes/typed/core/v1"

	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-automation-controller/internal/health/probetest"
	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-automation-controller/internal/probefw"
	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-automation-controller/internal/testutil"
)

// ---------------------------------------------------------------------------
// pullsecret-audit — imagepull secret auditor
// ---------------------------------------------------------------------------

// pullPod builds a pod whose spec.imagePullSecrets refs names.
func pullPod(ns, name string, secretNames ...string) *corev1.Pod {
	p := probetest.PodWithPhase(ns, name, corev1.PodRunning, true, time.Hour)
	for _, s := range secretNames {
		p.Spec.ImagePullSecrets = append(p.Spec.ImagePullSecrets,
			corev1.LocalObjectReference{Name: s})
	}
	return p
}

// dockerSecret builds a kubernetes.io/dockerconfigjson Secret from a
// raw document.
func dockerSecret(ns, name, doc string) *corev1.Secret {
	return &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{Namespace: ns, Name: name},
		Type:       corev1.SecretTypeDockerConfigJson,
		Data:       map[string][]byte{corev1.DockerConfigJsonKey: []byte(doc)},
	}
}

// jwtFor builds a compact-serialized JWT carrying exp.
func jwtFor(exp time.Time) string {
	hdr := base64.RawURLEncoding.EncodeToString([]byte(`{"alg":"none"}`))
	pl, _ := json.Marshal(map[string]any{"exp": exp.Unix()})
	return hdr + "." + base64.RawURLEncoding.EncodeToString(pl) + ".sig"
}

// dockerDocWithAuth renders an auths doc with one entry whose auth
// blob is base64("user:<token>").
func dockerDocWithAuth(token string) string {
	auth := base64.StdEncoding.EncodeToString([]byte("user:" + token))
	return fmt.Sprintf(`{"auths":{"registry.local":{"auth":%q}}}`, auth)
}

// A malformed .dockerconfigjson flags malformed_json.
func TestPullSecretMalformed(t *testing.T) {
	cs := fake.NewSimpleClientset(
		pullPod("apps", "web-1", "regcred"),
		dockerSecret("apps", "regcred", `{not-json`),
	)
	p := testProberDyn(cs, probetest.OpDyn())

	res := probetest.MustCheck[*imagePullSecretAuditorCheck](t, p).Run(probetest.SweepCtx(ctx, p.Deps))
	if res.Pass {
		t.Fatal("malformed pull secret must FAIL")
	}
	m := probetest.FindMetric(t, "node_automation_imagepull_secret_unhealthy",
		map[string]string{"namespace": "apps", "secret": "regcred", "reason": "malformed_json"})
	if m == nil || m.GetGauge().GetValue() != 1 {
		t.Fatalf("unhealthy gauge missing: %v", m)
	}
}

// A referenced-but-absent Secret flags missing.
func TestPullSecretMissing(t *testing.T) {
	cs := fake.NewSimpleClientset(pullPod("apps", "web-1", "ghost"))
	p := testProberDyn(cs, probetest.OpDyn())

	res := probetest.MustCheck[*imagePullSecretAuditorCheck](t, p).Run(probetest.SweepCtx(ctx, p.Deps))
	if res.Pass {
		t.Fatal("missing pull secret must FAIL")
	}
	m := probetest.FindMetric(t, "node_automation_imagepull_secret_unhealthy",
		map[string]string{"namespace": "apps", "secret": "ghost", "reason": "missing"})
	if m == nil {
		t.Fatal("missing-reason gauge not emitted")
	}
}

// A JWT expiring inside 7d flags jwt_expiring; a lapsed one flags
// jwt_expired; a long-lived one passes.
func TestPullSecretJWTExpiry(t *testing.T) {
	base := time.Now()
	cases := []struct {
		name     string
		exp      time.Time
		wantFail bool
		reason   string
	}{
		{"expiring", base.Add(3 * 24 * time.Hour), true, "jwt_expiring"},
		{"expired", base.Add(-time.Hour), true, "jwt_expired"},
		{"longlived", base.Add(30 * 24 * time.Hour), false, ""},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			cs := fake.NewSimpleClientset(
				pullPod("apps", "web-1", "regcred"),
				dockerSecret("apps", "regcred", dockerDocWithAuth(jwtFor(tc.exp))),
			)
			p := testProberDyn(cs, probetest.OpDyn())
			p.Now = func() time.Time { return base }

			res := probetest.MustCheck[*imagePullSecretAuditorCheck](t, p).Run(probetest.SweepCtx(ctx, p.Deps))
			if res.Pass == tc.wantFail {
				t.Fatalf("exp=%v pass=%v wantFail=%v", tc.exp, res.Pass, tc.wantFail)
			}
			if tc.wantFail {
				m := probetest.FindMetric(t, "node_automation_imagepull_secret_unhealthy",
					map[string]string{"namespace": "apps", "secret": "regcred", "reason": tc.reason})
				if m == nil {
					t.Fatalf("reason %s gauge not emitted", tc.reason)
				}
			}
		})
	}
}

// depWithPullSecret builds a Deployment whose pod template refs
// names in imagePullSecrets.
func depWithPullSecret(ns, name string, secretNames ...string) *appsv1.Deployment {
	d := &appsv1.Deployment{
		ObjectMeta: metav1.ObjectMeta{Namespace: ns, Name: name},
	}
	for _, s := range secretNames {
		d.Spec.Template.Spec.ImagePullSecrets = append(
			d.Spec.Template.Spec.ImagePullSecrets,
			corev1.LocalObjectReference{Name: s})
	}
	return d
}

// A secret referenced only by a Deployment pod template (scaled-to-0,
// no pods) is still audited — the downscaler path.
func TestPullSecretViaDeploymentTemplate(t *testing.T) {
	cs := fake.NewSimpleClientset(
		depWithPullSecret("apps", "web", "regcred"),
		dockerSecret("apps", "regcred", `{not-json`),
	)
	p := testProberDyn(cs, probetest.OpDyn())

	res := probetest.MustCheck[*imagePullSecretAuditorCheck](t, p).Run(probetest.SweepCtx(ctx, p.Deps))
	if res.Pass {
		t.Fatal("template-referenced malformed secret must FAIL")
	}
}

// A healthy referenced secret and a wrong-typed one exercise the two
// edges; secrets NOT referenced are never audited.
func TestPullSecretHealthyAndType(t *testing.T) {
	cs := fake.NewSimpleClientset(
		pullPod("apps", "web-1", "good", "opaque"),
		dockerSecret("apps", "good", `{"auths":{"r":{"auth":"dXNlcjpwYXNz"}}}`),
		&corev1.Secret{
			ObjectMeta: metav1.ObjectMeta{Namespace: "apps", Name: "opaque"},
			Type:       corev1.SecretTypeOpaque,
			Data:       map[string][]byte{"x": []byte("y")},
		},
		// Referenced-by-nothing malformed secret — must not flag.
		dockerSecret("apps", "unreferenced", `{not-json`),
	)
	p := testProberDyn(cs, probetest.OpDyn())

	res := probetest.MustCheck[*imagePullSecretAuditorCheck](t, p).Run(probetest.SweepCtx(ctx, p.Deps))
	if res.Pass {
		t.Fatal("opaque-typed pull secret must FAIL")
	}
	m := probetest.FindMetric(t, "node_automation_imagepull_secret_unhealthy",
		map[string]string{"namespace": "apps", "secret": "opaque", "reason": "unexpected_type"})
	if m == nil {
		t.Fatal("unexpected_type gauge not emitted")
	}
	if probetest.FindMetric(t, "node_automation_imagepull_secret_unhealthy",
		map[string]string{"namespace": "apps", "secret": "unreferenced", "reason": "malformed_json"}) != nil {
		t.Fatal("unreferenced secret must not be audited")
	}
}

// Quiet: a cluster with no pull-secret references passes.
func TestPullSecretQuiet(t *testing.T) {
	p := testProberDyn(fake.NewSimpleClientset(), probetest.OpDyn())
	if res := probetest.MustCheck[*imagePullSecretAuditorCheck](t, p).Run(probetest.SweepCtx(ctx, p.Deps)); !res.Pass {
		t.Fatalf("no pull secrets must pass: %+v", res)
	}
}

type pullSecretListOptsCS struct {
	kubernetes.Interface
	opts map[string][]metav1.ListOptions
}

func (r *pullSecretListOptsCS) CoreV1() corev1client.CoreV1Interface {
	return &pullSecretCoreV1{CoreV1Interface: r.Interface.CoreV1(), r: r}
}

type pullSecretCoreV1 struct {
	corev1client.CoreV1Interface
	r *pullSecretListOptsCS
}

func (c *pullSecretCoreV1) Secrets(ns string) corev1client.SecretInterface {
	return &pullSecretSecrets{SecretInterface: c.CoreV1Interface.Secrets(ns), r: c.r}
}

func (c *pullSecretCoreV1) ServiceAccounts(ns string) corev1client.ServiceAccountInterface {
	return &pullSecretServiceAccounts{ServiceAccountInterface: c.CoreV1Interface.ServiceAccounts(ns), r: c.r}
}

type pullSecretSecrets struct {
	corev1client.SecretInterface
	r *pullSecretListOptsCS
}

func (s *pullSecretSecrets) List(ctx context.Context, opts metav1.ListOptions) (*corev1.SecretList, error) {
	s.r.opts["secrets"] = append(s.r.opts["secrets"], opts)
	return s.SecretInterface.List(ctx, opts)
}

type pullSecretServiceAccounts struct {
	corev1client.ServiceAccountInterface
	r *pullSecretListOptsCS
}

func (sa *pullSecretServiceAccounts) List(ctx context.Context, opts metav1.ListOptions) (*corev1.ServiceAccountList, error) {
	sa.r.opts["serviceaccounts"] = append(sa.r.opts["serviceaccounts"], opts)
	return sa.ServiceAccountInterface.List(ctx, opts)
}

func TestPullSecretAuditorUsesResourceVersionZero(t *testing.T) {
	rawCS := fake.NewSimpleClientset(
		pullPod("apps", "web-1", "regcred"),
		dockerSecret("apps", "regcred", `{"auths":{"r":{"auth":"dXNlcjpwYXNz"}}}`),
	)
	rec := &pullSecretListOptsCS{
		Interface: rawCS,
		opts:      map[string][]metav1.ListOptions{},
	}
	d := probetest.NewDeps(rec, probetest.OpDyn())
	chk := NewImagePullSecretAuditorCheck(d)
	res := chk.Run(probetest.SweepCtx(ctx, d))
	if !res.Pass || res.Infra != nil {
		t.Fatalf("unexpected audit result: %+v", res)
	}
	for _, resource := range []string{"secrets", "serviceaccounts"} {
		calls := rec.opts[resource]
		if len(calls) != 1 {
			t.Fatalf("%s List call count = %d, want 1", resource, len(calls))
		}
		if calls[0].ResourceVersion != "0" {
			t.Fatalf("%s List ResourceVersion = %q, want \"0\"", resource, calls[0].ResourceVersion)
		}
		if calls[0].Limit != 0 {
			t.Fatalf("%s List Limit = %d, want 0 (cleared by kube.pageOpts when RV=0)", resource, calls[0].Limit)
		}
	}
}

func TestPullSecretPrivateRegistryDetection(t *testing.T) {
	now := time.Date(2026, 11, 22, 10, 0, 0, 0, time.UTC)
	delAt := metav1.NewTime(now.Add(-time.Minute))
	validSecret := dockerSecret("apps", "regcred", `{"auths":{"registry.internal.corp":{"auth":"dXNlcjpwYXNz"}}}`)
	saSecret := dockerSecret("apps", "sa-regcred", `{"auths":{"registry.internal.corp":{"auth":"dXNlcjpwYXNz"}}}`)

	cases := []struct {
		name     string
		objs     []runtime.Object
		wantPass bool
		wantKind string
		wantObj  string
		wantReg  string
	}{
		{
			name: "private registry Pod without pull secret fails",
			objs: []runtime.Object{
				&corev1.Pod{
					ObjectMeta: metav1.ObjectMeta{Namespace: "apps", Name: "priv-pod", UID: "u-priv"},
					Spec:       corev1.PodSpec{Containers: []corev1.Container{{Name: "app", Image: "registry.internal.corp/team/app:v1.2.3"}}},
					Status:     corev1.PodStatus{Phase: corev1.PodRunning},
				},
			},
			wantPass: false,
			wantKind: "Pod",
			wantObj:  "priv-pod",
			wantReg:  "registry.internal.corp",
		},
		{
			name: "private registry initContainer without pull secret fails",
			objs: []runtime.Object{
				&corev1.Pod{
					ObjectMeta: metav1.ObjectMeta{Namespace: "apps", Name: "init-priv", UID: "u-init"},
					Spec: corev1.PodSpec{
						InitContainers: []corev1.Container{{Name: "init", Image: "harbor.internal.local/init:v1"}},
						Containers:     []corev1.Container{{Name: "app", Image: "nginx:1.25"}},
					},
					Status: corev1.PodStatus{Phase: corev1.PodPending},
				},
			},
			wantPass: false,
			wantKind: "Pod",
			wantObj:  "init-priv",
			wantReg:  "harbor.internal.local",
		},
		{
			name: "private registry Deployment scaled to zero without pull secret fails",
			objs: []runtime.Object{
				&appsv1.Deployment{
					ObjectMeta: metav1.ObjectMeta{Namespace: "apps", Name: "priv-dep", UID: "u-dep"},
					Spec: appsv1.DeploymentSpec{
						Template: corev1.PodTemplateSpec{
							Spec: corev1.PodSpec{Containers: []corev1.Container{{Name: "worker", Image: "harbor.internal.local/ops/worker:v2"}}},
						},
					},
				},
			},
			wantPass: false,
			wantKind: "Deployment",
			wantObj:  "priv-dep",
			wantReg:  "harbor.internal.local",
		},
		{
			name: "private registry StatefulSet with port without pull secret fails",
			objs: []runtime.Object{
				&appsv1.StatefulSet{
					ObjectMeta: metav1.ObjectMeta{Namespace: "apps", Name: "priv-sts", UID: "u-sts"},
					Spec: appsv1.StatefulSetSpec{
						Template: corev1.PodTemplateSpec{
							Spec: corev1.PodSpec{Containers: []corev1.Container{{Name: "db", Image: "registry.example.com:8443/team/db:v1"}}},
						},
					},
				},
			},
			wantPass: false,
			wantKind: "StatefulSet",
			wantObj:  "priv-sts",
			wantReg:  "registry.example.com:8443",
		},
		{
			name: "private registry DaemonSet without pull secret fails",
			objs: []runtime.Object{
				&appsv1.DaemonSet{
					ObjectMeta: metav1.ObjectMeta{Namespace: "apps", Name: "priv-ds", UID: "u-ds"},
					Spec: appsv1.DaemonSetSpec{
						Template: corev1.PodTemplateSpec{
							Spec: corev1.PodSpec{Containers: []corev1.Container{{Name: "agent", Image: "123456789012.dkr.ecr.us-east-1.amazonaws.com/agent:v1"}}},
						},
					},
				},
			},
			wantPass: false,
			wantKind: "DaemonSet",
			wantObj:  "priv-ds",
			wantReg:  "123456789012.dkr.ecr.us-east-1.amazonaws.com",
		},
		{
			name: "private registry Pod with Pod.Spec.ImagePullSecrets passes",
			objs: []runtime.Object{
				validSecret,
				&corev1.Pod{
					ObjectMeta: metav1.ObjectMeta{Namespace: "apps", Name: "pod-ok"},
					Spec: corev1.PodSpec{
						ImagePullSecrets: []corev1.LocalObjectReference{{Name: "regcred"}},
						Containers:       []corev1.Container{{Name: "app", Image: "registry.internal.corp/team/app:v1.2.3"}},
					},
					Status: corev1.PodStatus{Phase: corev1.PodRunning},
				},
			},
			wantPass: true,
		},
		{
			name: "private registry Pod covered by named ServiceAccount imagePullSecrets passes",
			objs: []runtime.Object{
				saSecret,
				&corev1.ServiceAccount{
					ObjectMeta:       metav1.ObjectMeta{Namespace: "apps", Name: "app-sa"},
					ImagePullSecrets: []corev1.LocalObjectReference{{Name: "sa-regcred"}},
				},
				&corev1.Pod{
					ObjectMeta: metav1.ObjectMeta{Namespace: "apps", Name: "sa-pod"},
					Spec: corev1.PodSpec{
						ServiceAccountName: "app-sa",
						Containers:         []corev1.Container{{Name: "app", Image: "registry.internal.corp/team/app:v1.2.3"}},
					},
					Status: corev1.PodStatus{Phase: corev1.PodRunning},
				},
			},
			wantPass: true,
		},
		{
			name: "private registry Pod covered by default ServiceAccount imagePullSecrets passes",
			objs: []runtime.Object{
				saSecret,
				&corev1.ServiceAccount{
					ObjectMeta:       metav1.ObjectMeta{Namespace: "apps", Name: "default"},
					ImagePullSecrets: []corev1.LocalObjectReference{{Name: "sa-regcred"}},
				},
				&corev1.Pod{
					ObjectMeta: metav1.ObjectMeta{Namespace: "apps", Name: "def-sa-pod"},
					Spec: corev1.PodSpec{
						Containers: []corev1.Container{{Name: "app", Image: "registry.internal.corp/team/app:v1.2.3"}},
					},
					Status: corev1.PodStatus{Phase: corev1.PodRunning},
				},
			},
			wantPass: true,
		},
		{
			name: "public registries, short DockerHub names, and localhost pass without pull secrets",
			objs: []runtime.Object{
				&corev1.Pod{
					ObjectMeta: metav1.ObjectMeta{Namespace: "apps", Name: "pub-pod"},
					Spec: corev1.PodSpec{
						Containers: []corev1.Container{
							{Name: "a", Image: "nginx:1.25"},
							{Name: "b", Image: "library/nginx:1.25"},
							{Name: "c", Image: "registry.k8s.io/pause:3.10"},
							{Name: "d", Image: "ghcr.io/org/app:v1"},
							{Name: "e", Image: "quay.io/org/app:v1"},
							{Name: "f", Image: "cr.l5d.io/linkerd/proxy:v2"},
							{Name: "g", Image: "public.ecr.aws/org/app:v1"},
							{Name: "h", Image: "localhost:5000/dev/app:v1"},
							{Name: "i", Image: "mirror.gcr.io/aquasec/trivy:0.58"},
							{Name: "j", Image: "docker.dragonflydb.io/dragonflydb/dragonfly:v1.26"},
							{Name: "k", Image: "cr.strrl.dev/strrl/cloudflare-tunnel-ingress-controller:v0.0.19"},
							{Name: "l", Image: "ecr-public.aws.com/org/app:v1"},
						},
					},
					Status: corev1.PodStatus{Phase: corev1.PodRunning},
				},
			},
			wantPass: true,
		},
		{
			name: "terminating, terminal, and mirror Pods ignored",
			objs: []runtime.Object{
				&corev1.Pod{
					ObjectMeta: metav1.ObjectMeta{Namespace: "apps", Name: "term-pod", DeletionTimestamp: &delAt},
					Spec:       corev1.PodSpec{Containers: []corev1.Container{{Name: "a", Image: "registry.internal.corp/app:v1"}}},
					Status:     corev1.PodStatus{Phase: corev1.PodRunning},
				},
				&corev1.Pod{
					ObjectMeta: metav1.ObjectMeta{Namespace: "apps", Name: "done-pod"},
					Spec:       corev1.PodSpec{Containers: []corev1.Container{{Name: "a", Image: "registry.internal.corp/app:v1"}}},
					Status:     corev1.PodStatus{Phase: corev1.PodSucceeded},
				},
				&corev1.Pod{
					ObjectMeta: metav1.ObjectMeta{Namespace: "apps", Name: "failed-pod"},
					Spec:       corev1.PodSpec{Containers: []corev1.Container{{Name: "a", Image: "registry.internal.corp/app:v1"}}},
					Status:     corev1.PodStatus{Phase: corev1.PodFailed},
				},
				&corev1.Pod{
					ObjectMeta: metav1.ObjectMeta{Namespace: "kube-system", Name: "mirror-pod", Annotations: map[string]string{"kubernetes.io/config.mirror": "node-1"}},
					Spec:       corev1.PodSpec{Containers: []corev1.Container{{Name: "a", Image: "registry.internal.corp/app:v1"}}},
					Status:     corev1.PodStatus{Phase: corev1.PodRunning},
				},
			},
			wantPass: true,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			imagePullSecretUnhealthyGauge.Reset()
			imagePullMissingSecretGauge.Reset()
			cs := fake.NewSimpleClientset(tc.objs...)
			p := testProberDyn(cs, probetest.OpDyn())
			probetest.FreezeNow(p.Deps, now)
			chk := probetest.MustCheck[*imagePullSecretAuditorCheck](t, p)

			sctx := probetest.SweepCtx(ctx, chk.Deps)
			res := chk.Run(sctx)
			probetest.VerifySweep(sctx)
			if res.Pass != tc.wantPass || res.Infra != nil {
				t.Fatalf("Run = %+v, want Pass=%v Infra=nil", res, tc.wantPass)
			}
			if !tc.wantPass {
				v, ok := testutil.GaugeSeriesValue(t, "node_automation_imagepull_missing_secret",
					map[string]string{"namespace": "apps", "kind": tc.wantKind, "name": tc.wantObj, "registry": tc.wantReg})
				if !ok || v != 1 {
					t.Fatalf("missing secret gauge = (%v,%v), want (1,true)", v, ok)
				}
				evs, err := cs.EventsV1().Events("apps").List(ctx, metav1.ListOptions{})
				if err != nil || len(evs.Items) != 1 || evs.Items[0].Reason != imagePullMissingSecretEventReason {
					t.Fatalf("events = %+v (err=%v), want 1 MissingImagePullSecret event", evs.Items, err)
				}
			}
		})
	}
}

func TestPullSecretMissingSecretHeavyScanCyclesCarryForward(t *testing.T) {
	imagePullSecretUnhealthyGauge.Reset()
	imagePullMissingSecretGauge.Reset()
	now := time.Date(2026, 11, 22, 10, 0, 0, 0, time.UTC)

	rawCS := fake.NewSimpleClientset(
		&corev1.Pod{
			ObjectMeta: metav1.ObjectMeta{Namespace: "apps", Name: "priv-pod", UID: "u-priv"},
			Spec:       corev1.PodSpec{Containers: []corev1.Container{{Name: "app", Image: "registry.internal.corp/team/app:v1"}}},
			Status:     corev1.PodStatus{Phase: corev1.PodRunning},
		},
	)
	rec := &pullSecretListOptsCS{
		Interface: rawCS,
		opts:      map[string][]metav1.ListOptions{},
	}
	d := probetest.NewDeps(rec, probetest.OpDyn())
	probetest.FreezeNow(d, now)
	chk := NewImagePullSecretAuditorCheck(d).(*imagePullSecretAuditorCheck)

	// Cycle 1: runs census, detects missing secret.
	sctx1 := probetest.SweepCtx(ctx, d)
	if res := chk.Run(sctx1); res.Pass || res.Infra != nil {
		t.Fatalf("cycle 1 = %+v, want FAIL", res)
	}
	probetest.VerifySweep(sctx1)
	if v, ok := testutil.GaugeSeriesValue(t, "node_automation_imagepull_missing_secret",
		map[string]string{"namespace": "apps", "kind": "Pod", "name": "priv-pod", "registry": "registry.internal.corp"}); !ok || v != 1 {
		t.Fatalf("cycle 1 gauge = (%v,%v), want (1,true)", v, ok)
	}

	// Cycles 2..6: carry forward without re-listing ServiceAccounts.
	for cyc := 2; cyc <= probefw.HeavyScanCycles; cyc++ {
		probetest.FreezeNow(d, now.Add(time.Duration(cyc)*5*time.Minute))
		sctx := probetest.SweepCtx(ctx, d)
		res := chk.Run(sctx)
		probetest.VerifySweep(sctx)
		if res.Pass {
			t.Fatalf("cycle %d must carry forward FAIL", cyc)
		}
		if v, ok := testutil.GaugeSeriesValue(t, "node_automation_imagepull_missing_secret",
			map[string]string{"namespace": "apps", "kind": "Pod", "name": "priv-pod", "registry": "registry.internal.corp"}); !ok || v != 1 {
			t.Fatalf("cycle %d carried gauge = (%v,%v), want (1,true)", cyc, v, ok)
		}
	}
	if len(rec.opts["serviceaccounts"]) != 1 {
		t.Fatalf("serviceaccounts list count during cycles 1..6 = %d, want 1", len(rec.opts["serviceaccounts"]))
	}

	// Fix Pod by adding valid pull secret on default SA -> cycle 7 clears gauge and passes.
	_, _ = rawCS.CoreV1().Secrets("apps").Create(ctx,
		dockerSecret("apps", "sa-regcred", `{"auths":{"registry.internal.corp":{"auth":"dXNlcjpwYXNz"}}}`),
		metav1.CreateOptions{})
	_, _ = rawCS.CoreV1().ServiceAccounts("apps").Create(ctx,
		&corev1.ServiceAccount{
			ObjectMeta:       metav1.ObjectMeta{Namespace: "apps", Name: "default"},
			ImagePullSecrets: []corev1.LocalObjectReference{{Name: "sa-regcred"}},
		},
		metav1.CreateOptions{})

	probetest.FreezeNow(d, now.Add(35*time.Minute))
	sctx7 := probetest.SweepCtx(ctx, d)
	res7 := chk.Run(sctx7)
	probetest.VerifySweep(sctx7)
	if !res7.Pass || res7.Infra != nil {
		t.Fatalf("cycle 7 = %+v, want Pass=true", res7)
	}
	if len(rec.opts["serviceaccounts"]) != 2 {
		t.Fatalf("serviceaccounts list count after cycle 7 = %d, want 2", len(rec.opts["serviceaccounts"]))
	}
	if _, ok := testutil.GaugeSeriesValue(t, "node_automation_imagepull_missing_secret",
		map[string]string{"namespace": "apps", "kind": "Pod", "name": "priv-pod", "registry": "registry.internal.corp"}); ok {
		t.Fatal("cycle 7 recovery did not prune node_automation_imagepull_missing_secret")
	}
}
