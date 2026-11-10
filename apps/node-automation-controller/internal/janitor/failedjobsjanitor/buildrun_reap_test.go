// buildrun_reap_test.go — coverage for the workspace-PVC run-ref
// resolution table: only the dynamic-client kinds live in
// runRefGVR (Job resolves through the typed clientset and never
// reaches this table), and an unknown kind reads "not a run ref"
// rather than mapping to a phantom GVR.
package failedjobsjanitor

import (
	"testing"

	"k8s.io/apimachinery/pkg/runtime/schema"

	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-automation-controller/internal/platform/kube"
)

func TestRunRefGVR(t *testing.T) {
	cases := []struct {
		kind string
		want schema.GroupVersionResource
		ok   bool
	}{
		{"PipelineRun", kube.GVRTektonPipelineRun, true},
		{"TaskRun", kube.GVRTektonTaskRun, true},
		{"BuildRun", kube.GVRShipwrightBuildRun, true},
		{"Job", schema.GroupVersionResource{}, false},
		{"Workflow", schema.GroupVersionResource{}, false},
	}
	for _, tc := range cases {
		t.Run(tc.kind, func(t *testing.T) {
			gvr, ok := runRefGVR(tc.kind)
			if ok != tc.ok || gvr != tc.want {
				t.Fatalf("runRefGVR(%q) = (%v,%v), want (%v,%v)",
					tc.kind, gvr, ok, tc.want, tc.ok)
			}
		})
	}
}
