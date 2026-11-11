// jsonsize.go — serialized-size measurement without materializing
// the document: json.Marshal allocates the full []byte, which for a
// CRD's OpenAPI schema is tens of MB per object — audits that only
// need the LENGTH (the kine large-object guard) count through an
// io.Writer instead.
package kube

import "encoding/json"

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
	w := &countingWriter{}
	if err := json.NewEncoder(w).Encode(v); err != nil {
		return 0, err
	}
	return w.n - 1, nil
}
