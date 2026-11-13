// restart_template.go — the rollout-restart patch body. Two modules
// hand-marshal the same nested pod-template restartedAt document
// (system/fluentbitroller's DaemonSet roll, system/corednswatchdog's
// stale-recovery Deployment restart); this is the one shared builder.
// kube.MergePatchAnnos only covers TOP-LEVEL metadata.annotations, so
// the nested pod-template doc must be built here — a stamp on the
// pod template is what triggers the rollout.
package kube

import (
	"encoding/json"
	"time"
)

// RestartedAtAnno is kubectl rollout restart's stamp key — the
// convention every controller honors (the per-module private consts
// spell the same value; adopting call sites switch to this builder).
const RestartedAtAnno = "kubectl.kubernetes.io/restartedAt"

// RestartTemplatePatch renders the pod-template restartedAt
// strategic-merge patch body that triggers a rollout restart:
//
//	{"spec":{"template":{"metadata":{"annotations":
//	 {"kubectl.kubernetes.io/restartedAt":"<ts RFC3339 UTC>"}}}}}
//
// The stamp is always RFC3339 UTC (the same contract StampPersisted
// writes). Marshalling a literal map of strings cannot fail, so the
// []byte-only signature is safe. Callers patch with
// types.StrategicMergePatchType (containers/annotations merge by
// name/key); a caller needing MORE keys in one document (coredns
// adds a metadata-level cooldown stamp) keeps its own outer doc and
// reads this shape as the spec.template half.
func RestartTemplatePatch(ts time.Time) []byte {
	return RestartTemplatePatchAnnos(ts, nil)
}

// RestartTemplatePatchAnnos renders RestartTemplatePatch's shape with
// EXTRA pod-template annotations folded into the same metadata map —
// the callers that used to decode the base doc, walk spec/template/
// metadata/annotations defensively and re-encode (fluent-bit's
// config-hash idempotence stamp, coreDNS's combined doc) render in
// one call now. Annotation keys marshal alphabetically — the same
// deterministic order json.Marshal gave the decode-extend-reencode
// dance. The stamp is always RFC3339 UTC; marshalling a string-only
// map cannot fail, so the []byte-only signature is safe.
func RestartTemplatePatchAnnos(ts time.Time, extra map[string]string) []byte {
	annos := make(map[string]any, len(extra)+1)
	annos[RestartedAtAnno] = ts.UTC().Format(time.RFC3339)
	for k, v := range extra {
		annos[k] = v
	}
	payload, err := json.Marshal(map[string]any{
		"spec": map[string]any{
			"template": map[string]any{
				"metadata": map[string]any{
					"annotations": annos,
				},
			},
		},
	})
	if err != nil {
		// Unreachable for string-only maps; a panic here means the
		// doc above was edited into something json cannot render.
		panic(err)
	}
	return payload
}
