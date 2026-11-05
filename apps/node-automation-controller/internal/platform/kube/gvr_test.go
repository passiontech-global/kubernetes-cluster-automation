package kube

import (
	"strings"
	"testing"

	"k8s.io/apimachinery/pkg/runtime/schema"
)

// registryGVRs enumerates every named GVR var for the sanity checks —
// when a var is added to gvr.go it belongs here too (the test is the
// checklist that keeps the registry honest).
var registryGVRs = []schema.GroupVersionResource{
	GVRAPIService,
	GVRHelmReleaseV2, GVRHelmReleaseV2Beta2,
	GVRFluxKustomization, GVRFluxHelmChart, GVRFluxGitRepository,
	GVRFluxHelmRepository, GVRFluxOCIRepository, GVRFluxBucket,
	GVRCertificate, GVRCertificateRequest, GVRACMEOrder, GVRACMEChallenge,
	GVRExternalSecretV1, GVRExternalSecretV1Beta1,
	GVRSecretStoreV1, GVRSecretStoreV1Beta1,
	GVRClusterSecretStoreV1, GVRClusterSecretStoreV1Beta1,
	GVRCiliumIdentity, GVRCiliumEndpoint, GVRCiliumEndpointSlice,
	GVVeleroSchedule, GVVeleroBackup, GVVeleroBackupStorageLocation,
	GVVeleroPodVolumeBackup,
	GVREverestDatabaseCluster, GVREverestDatabaseClusterBackup,
	GVRPerconaXtraDBCluster, GVRPerconaPGCluster, GVRPerconaServerMongoDB,
	GVRNodeHealthCheck, GVRSelfNodeRemediation, GVRFenceAgentsRemediation,
	AutopilotPlanGVR,
	GVRScyllaCluster, GVRDragonfly, GVRRabbitMQCluster,
	GVRArgoCD, GVRArgoCDApplication, GVRKargoStage, GVRKargoWarehouse,
	GVRShipwrightBuild, GVRShipwrightBuildRun, GVRShipwrightOperatorBuild,
	GVRTektonPipelineRun, GVRKedaScaledObject,
	GVROLMClusterServiceVersion, GVROLMSubscription,
	GVRGatewayClass, GVRGateway, GVRHTTPRoute, GVRGRPCRoute,
}

// TestGVRRegistrySanity: every entry must carry a version and a
// lowercase resource; a typo'd group/version would 404 every dynamic
// List that used it (the failure mode the registry exists to kill).
func TestGVRRegistrySanity(t *testing.T) {
	for _, g := range registryGVRs {
		if g.Version == "" {
			t.Errorf("%s: empty version", g.Resource)
		}
		if g.Resource == "" {
			t.Errorf("%s/%s: empty resource", g.Group, g.Version)
		}
		if g.Resource != strings.ToLower(g.Resource) {
			t.Errorf("%s/%s %q: resource must be lowercase",
				g.Group, g.Version, g.Resource)
		}
	}
}

// TestGVRRegistryUnique: two vars aliasing the same GVR would let a
// future "fix" update one literal and silently diverge the other —
// every var must name a distinct group/version/resource triple.
func TestGVRRegistryUnique(t *testing.T) {
	seen := map[schema.GroupVersionResource]bool{}
	for _, g := range registryGVRs {
		if seen[g] {
			t.Errorf("duplicate GVR %s", g)
		}
		seen[g] = true
	}
}

// TestGVRRegistrySlices: the grouped probe slices must reference
// registry vars (not drift into private literals) and list the
// preferred version first.
func TestGVRRegistrySlices(t *testing.T) {
	if len(HelmReleaseGVRs) != 2 ||
		HelmReleaseGVRs[0] != GVRHelmReleaseV2 ||
		HelmReleaseGVRs[1] != GVRHelmReleaseV2Beta2 {
		t.Fatalf("HelmReleaseGVRs = %v", HelmReleaseGVRs)
	}
	for name, s := range map[string][]schema.GroupVersionResource{
		"ExternalSecretGVRs":     ExternalSecretGVRs,
		"SecretStoreGVRs":        SecretStoreGVRs,
		"ClusterSecretStoreGVRs": ClusterSecretStoreGVRs,
		"PerconaClusterGVRs":     PerconaClusterGVRs,
	} {
		if len(s) == 0 {
			t.Errorf("%s is empty", name)
			continue
		}
		for _, g := range s {
			if !seenGVR(g) {
				t.Errorf("%s contains %s which is not a registry var", name, g)
			}
		}
	}
	// Preferred version first: v1 before v1beta1 for external-secrets.
	if ExternalSecretGVRs[0].Version != "v1" {
		t.Fatalf("ExternalSecretGVRs order = %v", ExternalSecretGVRs)
	}
}

func seenGVR(g schema.GroupVersionResource) bool {
	for _, r := range registryGVRs {
		if r == g {
			return true
		}
	}
	return false
}

// TestAutopilotPlanGVRStable pins the moved declaration — consumers
// (MaintenanceActive, concoursejanitor, deschedulerstormgate) must see
// the identical value they had when it lived in helpers.go.
func TestAutopilotPlanGVRStable(t *testing.T) {
	want := schema.GroupVersionResource{
		Group: "autopilot.k0sproject.io", Version: "v1beta2", Resource: "plans"}
	if AutopilotPlanGVR != want {
		t.Fatalf("AutopilotPlanGVR = %v, want %v", AutopilotPlanGVR, want)
	}
}
