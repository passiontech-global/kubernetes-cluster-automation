// imagepull_secret_auditor_test.go — the pullsecret-audit pull-secret hygiene
// auditor driven through the fake clientset.
package gitops

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"testing"
	"time"

	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes/fake"

	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-automation-controller/internal/health/probetest"
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

	res := probetest.MustCheck[*imagePullSecretAuditorCheck](t, p).Run(ctx)
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

	res := probetest.MustCheck[*imagePullSecretAuditorCheck](t, p).Run(ctx)
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

			res := probetest.MustCheck[*imagePullSecretAuditorCheck](t, p).Run(ctx)
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

	res := probetest.MustCheck[*imagePullSecretAuditorCheck](t, p).Run(ctx)
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

	res := probetest.MustCheck[*imagePullSecretAuditorCheck](t, p).Run(ctx)
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
	if res := probetest.MustCheck[*imagePullSecretAuditorCheck](t, p).Run(ctx); !res.Pass {
		t.Fatalf("no pull secrets must pass: %+v", res)
	}
}
