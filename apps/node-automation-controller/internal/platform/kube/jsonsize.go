// jsonsize.go — serialized-size measurement without materializing
// the document: json.Marshal allocates the full []byte, which for a
// CRD's OpenAPI schema is tens of MB per object — audits that only
// need the LENGTH (the kine large-object guard) count through an
// io.Writer instead.
package kube

import (
	"encoding/json"

	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
)

// countingWriter is an io.Writer that only counts bytes.
type countingWriter struct{ n int64 }

func (w *countingWriter) Write(p []byte) (int, error) {
	w.n += int64(len(p))
	return len(p), nil
}

// JSONSize returns v's json.Marshal-equivalent byte count — same
// encoder settings (HTML escaping on), minus the trailing newline
// json.Encoder.Encode appends that Marshal output does not carry.
func JSONSize(v any) (int64, error) {
	// *unstructured.Unstructured implements json.Marshaler by
	// marshaling its whole Object into a []byte first — the exact
	// multi-MB allocation this counter exists to avoid. Unwrap to
	// the backing map: the encoder compacts Marshaler output with
	// HTML escaping anyway, so the counted bytes are identical.
	switch u := v.(type) {
	case *unstructured.Unstructured:
		if u != nil {
			v = u.Object
		}
	case unstructured.Unstructured:
		v = u.Object
	}
	w := &countingWriter{}
	if err := json.NewEncoder(w).Encode(v); err != nil {
		return 0, err
	}
	return w.n - 1, nil
}
