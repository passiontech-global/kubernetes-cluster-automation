// helmrelease-unlocker HelmRelease release-identity resolution —
// which release name and which namespaces (storage vs installed) a
// given HR maps to, mirroring upstream flux's own resolvers.
// split from helmrelease_unlocker.go (see its header for the module contract).
package helmreleaseunlocker

import (
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"

	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-automation-controller/internal/platform/kube"
)

// hrReleaseName mirrors upstream flux's GetReleaseName():
// spec.releaseName wins, then "<targetNamespace>-<name>" when a
// targetNamespace is set (flux prefixes the release name to keep
// same-named HRs in different target namespaces distinct), then the
// bare object name. It is the `name=` label helm puts on its release
// secrets.
func hrReleaseName(hr *unstructured.Unstructured) string {
	if n, _ := kube.NestedString(hr.Object, "spec", "releaseName"); n != "" {
		return n
	}
	if ns, _ := kube.NestedString(hr.Object, "spec", "targetNamespace"); ns != "" {
		return ns + "-" + hr.GetName()
	}
	return hr.GetName()
}

// hrReleaseNS resolves where the release is INSTALLED —
// spec.targetNamespace || HR namespace (upstream flux's
// GetReleaseNamespace used to locate hook Jobs, pods, and every
// workload the chart renders). Hook Jobs live here, not in the
// storage namespace.
func hrReleaseNS(hr *unstructured.Unstructured) string {
	if ns, _ := kube.NestedString(hr.Object, "spec", "targetNamespace"); ns != "" {
		return ns
	}
	return hr.GetNamespace()
}

// hrStorageNS mirrors upstream flux's GetStorageNamespace():
// spec.storageNamespace || HR namespace. This is where helm-controller
// writes the sh.helm.release.v1 secrets — spec.targetNamespace is NOT
// part of the chain (it only locates the installed release, not its
// bookkeeping).
func hrStorageNS(hr *unstructured.Unstructured) string {
	if ns, _ := kube.NestedString(hr.Object, "spec", "storageNamespace"); ns != "" {
		return ns
	}
	return hr.GetNamespace()
}
