// body.go — bounded HTTP body drain and read helpers shared across
// apps (keep-alive connection reuse without unbounded memory/stream
// stalls).
package httpx

import (
	"io"
	"math"
)

// DrainAndClose reads and discards up to maxBytes from rc before
// closing it so HTTP keep-alive connections can be reused without
// letting an endless peer stream stall the caller. Nil-safe.
func DrainAndClose(rc io.ReadCloser, maxBytes int64) {
	if rc == nil {
		return
	}
	if maxBytes > 0 {
		_, _ = io.Copy(io.Discard, io.LimitReader(rc, maxBytes))
	}
	_ = rc.Close()
}

// ReadBounded reads at most maxBytes from r, probing up to maxBytes+1
// bytes so callers can distinguish an exact-cap payload from a
// truncated/oversized stream cleanly. Returns (data, truncated, err).
// Nil-safe: a nil reader returns (nil, false, nil); negative maxBytes
// is treated as 0.
func ReadBounded(r io.Reader, maxBytes int64) ([]byte, bool, error) {
	if r == nil {
		return nil, false, nil
	}
	if maxBytes < 0 {
		maxBytes = 0
	}
	lr := r
	if maxBytes < math.MaxInt64 {
		lr = io.LimitReader(r, maxBytes+1)
	}
	data, err := io.ReadAll(lr)
	if int64(len(data)) > maxBytes {
		return data[:maxBytes], true, err
	}
	return data, false, err
}
