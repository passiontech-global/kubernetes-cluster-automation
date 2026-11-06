// status.go — `endpoint status` plumbing for stages 1/3/4 of the
// rescue flow (the before-snapshot numbers, the online-defrag
// reclaim check, the post-defrag readout): the JSON shape of
// `endpoint status -w json` element[0] plus the fetch helper.
package etcdmaint

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
)

// endpointStatus is the slice of `endpoint status -w json` element[0]
// the script extracted via python3.
type endpointStatus struct {
	DBSize      int64
	DBSizeInUse int64
	Revision    int64
}

// parseStatusJSON decodes `etcdctl endpoint status -w json` (a JSON
// array of per-endpoint entries; the script read [0].Status).
func parseStatusJSON(b []byte) (endpointStatus, error) {
	var arr []struct {
		Status struct {
			Header struct {
				Revision int64 `json:"revision"`
			} `json:"header"`
			DBSize      int64 `json:"dbSize"`
			DBSizeInUse int64 `json:"dbSizeInUse"`
		} `json:"Status"`
	}
	if err := json.Unmarshal(b, &arr); err != nil {
		return endpointStatus{}, fmt.Errorf("parse status json: %w", err)
	}
	if len(arr) == 0 {
		return endpointStatus{}, errors.New("parse status json: empty endpoint list")
	}
	st := arr[0].Status
	return endpointStatus{
		DBSize:      st.DBSize,
		DBSizeInUse: st.DBSizeInUse,
		Revision:    st.Header.Revision,
	}, nil
}

// status fetches `endpoint status -w json` and parses element[0].
func (r *rescuer) status(ctx context.Context) (endpointStatus, error) {
	b, err := r.etcdctl(ctx, "", "endpoint", "status", "-w", "json")
	if err != nil {
		return endpointStatus{}, err
	}
	return parseStatusJSON(b)
}
