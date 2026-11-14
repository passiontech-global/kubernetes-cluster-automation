// deps_test.go — unit tests for Deps.CachedClient.
package shared

import (
	"testing"

	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/manager"
)

type stubMgrWithClient struct {
	manager.Manager
	c client.Client
}

func (s stubMgrWithClient) GetClient() client.Client { return s.c }

type stubClient struct{ client.Client }

func TestDepsCachedClient(t *testing.T) {
	t.Parallel()

	if got := (Deps{}).CachedClient(); got != nil {
		t.Fatalf("nil Mgr must return nil CachedClient, got %v", got)
	}

	sc := stubClient{}
	d := Deps{Mgr: stubMgrWithClient{c: sc}}
	if got := d.CachedClient(); got != sc {
		t.Fatalf("CachedClient = %v, want %v", got, sc)
	}
}
