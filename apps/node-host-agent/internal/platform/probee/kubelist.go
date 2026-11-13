// kubelist.go — the apiserver list-envelope decoder behind the RV
// probes: a full-object List and the metadata-only
// PartialObjectMetadataList (`Accept: …as=PartialObjectMetadataList`)
// carry the watch position in the SAME envelope —
// .metadata.resourceVersion — so one pure-stdlib decode serves both
// content types and every caller negotiates the cheap metadata form
// without a second parser.
package probee

import (
	"encoding/json"
	"strconv"
)

// ListResourceVersion extracts the LIST-level resourceVersion from
// one apiserver list response body — api_list_rv parity. ok=false on
// an unparseable body or a missing/non-numeric resourceVersion: an
// RV probe must never fabricate a watch position from a torn or
// foreign payload.
func ListResourceVersion(body []byte) (int64, bool) {
	var list struct {
		Metadata struct {
			ResourceVersion string `json:"resourceVersion"`
		} `json:"metadata"`
	}
	if err := json.Unmarshal(body, &list); err != nil {
		return 0, false
	}
	rv, err := strconv.ParseInt(list.Metadata.ResourceVersion, 10, 64)
	if err != nil {
		return 0, false
	}
	return rv, true
}
