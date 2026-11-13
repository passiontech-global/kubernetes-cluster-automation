// crdsize_test.go — the CRD size side table (the informer transform's
// write path + the kine census's read path): RV-keyed overwrite
// semantics, bounded growth, and the byte-identity contract — the
// table's recorded number (json.Marshal length of the TYPED CRD) must
// equal what the legacy live measure (json.Marshal length of the same
// object decoded to an unstructured map) produced, so the
// node_automation_kine_large_object_bytes series is unchanged for
// unchanged objects.
package kube

import (
	"encoding/json"
	"testing"

	apiextensionsv1 "k8s.io/apiextensions-apiserver/pkg/apis/apiextensions/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

func TestCRDSizeTableRecordLookup(t *testing.T) {
	tab := NewCRDSizeTable(16)
	tab.Record("gatekeepers.example.com", "100", 900000)
	if size, ok := tab.Lookup("gatekeepers.example.com", "100"); !ok || size != 900000 {
		t.Fatalf("Lookup = %d,%v want 900000,true", size, ok)
	}
	// A miss on any other RV — a re-created CRD must not inherit the
	// old object's size.
	if _, ok := tab.Lookup("gatekeepers.example.com", "101"); ok {
		t.Fatal("lookup matched a foreign resourceVersion")
	}
	if _, ok := tab.Lookup("other.example.com", "100"); ok {
		t.Fatal("lookup matched a foreign name")
	}
	// Update overwrites in place — the map does not grow per RV churn
	// of the SAME CRD... it keys by RV, so an update lands on a new
	// key and the old one lingers until eviction; the NEW lookup must
	// win.
	tab.Record("gatekeepers.example.com", "101", 42)
	if size, ok := tab.Lookup("gatekeepers.example.com", "101"); !ok || size != 42 {
		t.Fatalf("post-update Lookup = %d,%v want 42,true", size, ok)
	}
}

func TestCRDSizeTableBounded(t *testing.T) {
	tab := NewCRDSizeTable(8)
	for i := range 20 {
		tab.Record("crd"+string(rune('a'+i)), "1", int64(i))
	}
	tab.mu.RLock()
	grown := len(tab.m)
	tab.mu.RUnlock()
	if grown > 8 {
		t.Fatalf("table grew to %d entries past its capacity", grown)
	}
	if grown == 0 {
		t.Fatal("eviction wiped the table instead of halving it")
	}
}

// The byte-identity contract: the transform records json.Marshal
// length of the typed object; the legacy census measured the same CRD
// after a JSON decode into an unstructured map (what the dynamic
// client hands over). Key ORDER differs between the two encodings but
// length does not — this guard fails if any field's JSON length ever
// drifts between the typed struct and its wire form.
func TestCRDJSONSizeTypedMatchesUnstructured(t *testing.T) {
	crd := &apiextensionsv1.CustomResourceDefinition{
		TypeMeta: metav1.TypeMeta{
			APIVersion: "apiextensions.k8s.io/v1", Kind: "CustomResourceDefinition"},
		ObjectMeta: metav1.ObjectMeta{
			Name: "gatekeepers.example.com",
			Annotations: map[string]string{
				"kubectl.kubernetes.io/last-applied-configuration": `{\"big\":\"manifest\"}`,
			},
			ManagedFields: []metav1.ManagedFieldsEntry{{
				Manager: "flux", Operation: "Apply",
				FieldsV1: &metav1.FieldsV1{Raw: []byte(`{"f:spec":{}}`)},
			}},
			CreationTimestamp: metav1.Now(),
			Generation:        7,
			UID:               "9f8b",
			ResourceVersion:   "481516",
		},
		Spec: apiextensionsv1.CustomResourceDefinitionSpec{
			Group: "example.com",
			Names: apiextensionsv1.CustomResourceDefinitionNames{
				Plural: "gatekeepers", Singular: "gatekeeper", Kind: "Gatekeeper",
				ListKind: "GatekeeperList", ShortNames: []string{"gk"},
			},
			Scope: apiextensionsv1.ClusterScoped,
			Versions: []apiextensionsv1.CustomResourceDefinitionVersion{{
				Name: "v1", Served: true, Storage: true,
				Schema: &apiextensionsv1.CustomResourceValidation{
					OpenAPIV3Schema: &apiextensionsv1.JSONSchemaProps{
						Type: "object",
						Properties: map[string]apiextensionsv1.JSONSchemaProps{
							"spec": {Type: "object",
								Properties: map[string]apiextensionsv1.JSONSchemaProps{
									"replicas": {Type: "integer", Minimum: new(0.0)},
									"hosts":    {Type: "array", Items: &apiextensionsv1.JSONSchemaPropsOrArray{Schema: &apiextensionsv1.JSONSchemaProps{Type: "string"}}},
								}},
						},
					},
				},
				Subresources: &apiextensionsv1.CustomResourceSubresources{
					Status: &apiextensionsv1.CustomResourceSubresourceStatus{},
				},
			}},
			Conversion: &apiextensionsv1.CustomResourceConversion{
				Strategy: apiextensionsv1.WebhookConverter,
				Webhook: &apiextensionsv1.WebhookConversion{
					ClientConfig: &apiextensionsv1.WebhookClientConfig{
						Service: &apiextensionsv1.ServiceReference{
							Namespace: "gatekeepers", Name: "converter", Port: new(int32(9443)),
						},
					},
					ConversionReviewVersions: []string{"v1"},
				},
			},
		},
		Status: apiextensionsv1.CustomResourceDefinitionStatus{
			Conditions: []apiextensionsv1.CustomResourceDefinitionCondition{{
				Type:   apiextensionsv1.Established,
				Status: apiextensionsv1.ConditionTrue,
			}},
			StoredVersions: []string{"v1"},
		},
	}
	typedSize, err := JSONSize(crd)
	if err != nil {
		t.Fatalf("typed JSONSize: %v", err)
	}
	// The legacy shape: wire JSON decoded to map[string]any (numbers
	// become float64, key order alphabetical) — what the dynamic
	// client listed and the old census measured.
	wire, err := json.Marshal(crd)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	var asMap map[string]any
	if err := json.Unmarshal(wire, &asMap); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	unstrSize, err := JSONSize(asMap)
	if err != nil {
		t.Fatalf("unstructured JSONSize: %v", err)
	}
	if typedSize != unstrSize {
		t.Fatalf("typed size %d != wire-decoded size %d — the side table would shift the kine gauge bytes", typedSize, unstrSize)
	}
}
