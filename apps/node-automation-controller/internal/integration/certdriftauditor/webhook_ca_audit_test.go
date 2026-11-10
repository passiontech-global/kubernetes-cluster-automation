// webhook_ca_audit_test.go — coverage for the injection-source CA
// lookup (secretCA): the ca.crt/tls.crt key fallback cainjector
// reads, and the routine-vs-real failure split (NotFound is quiet,
// any other Get failure is logged — both read "no CA").
package certdriftauditor

import (
	"errors"
	"testing"
	"time"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/client-go/kubernetes/fake"
	ktesting "k8s.io/client-go/testing"
)

// ca.crt is where cainjector reads the bundle; tls.crt is the
// fallback for secrets carrying only the leaf pair. A secret with
// neither yields no CA, and any Get failure — NotFound included —
// resolves the lookup as "no CA" rather than an error.
func TestSecretCAResolution(t *testing.T) {
	now := time.Now()
	cases := []struct {
		name    string
		secret  *corev1.Secret
		listErr bool
		wantCA  []byte
		wantOK  bool
	}{
		{"ca.crt wins", &corev1.Secret{
			ObjectMeta: metav1.ObjectMeta{Namespace: "ns", Name: "s"},
			Data: map[string][]byte{
				"ca.crt": []byte("CA"), "tls.crt": []byte("LEAF")},
		}, false, []byte("CA"), true},
		{"tls.crt is the leaf-pair fallback", &corev1.Secret{
			ObjectMeta: metav1.ObjectMeta{Namespace: "ns", Name: "s"},
			Data:       map[string][]byte{"tls.crt": []byte("LEAF")},
		}, false, []byte("LEAF"), true},
		{"no ca keys is no CA", &corev1.Secret{
			ObjectMeta: metav1.ObjectMeta{Namespace: "ns", Name: "s"},
			Data:       map[string][]byte{"other": []byte("x")},
		}, false, nil, false},
		{"missing secret is routine", nil, false, nil, false},
		{"get failure is no CA too", nil, true, nil, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			var objs []runtime.Object
			if tc.secret != nil {
				objs = append(objs, tc.secret)
			}
			cs := fake.NewSimpleClientset(objs...)
			if tc.listErr {
				cs.PrependReactor("get", "secrets",
					func(ktesting.Action) (bool, runtime.Object, error) {
						return true, nil, errors.New("api down")
					})
			}
			a := newCertDriftAuditor(cs, nil, now)
			ca, ok := a.secretCA(ctx, "ns", "s",
				"MutatingWebhookConfiguration", "cfg")
			if ok != tc.wantOK || string(ca) != string(tc.wantCA) {
				t.Fatalf("secretCA = (%q,%v), want (%q,%v)",
					ca, ok, tc.wantCA, tc.wantOK)
			}
		})
	}
}
