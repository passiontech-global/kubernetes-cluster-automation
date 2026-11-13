// respond.go — the shared HTTP response + log-safety helpers used
// across the request path: the body-read/status mapping
// (failBodyRead), the well-formed-signature 401 (rejectSignature),
// pre-verification log sanitizing (logSafe) and the JSON writers
// (writeJSON/writeSkipped). Split out of handler.go so the
// ServeHTTP front half stays under the ~500-LOC bar.
package handler

import (
	"encoding/json"
	"errors"
	"net/http"
	"strings"
)

// failBodyRead maps a body-read failure onto the delivery metric and
// the HTTP status — shared by the buffered and streaming verify
// paths so their 413/400 ordering can never drift apart. "Body over
// maxBodyBytes" (the sender's fault -> 413) and a transport failure
// like a client disconnect (-> 400) both surface as a read error —
// split them on MaxBytesError.
func (h *Handler) failBodyRead(w http.ResponseWriter, r *http.Request,
	delivery, event, eventMetric string, err error) {
	var maxErr *http.MaxBytesError
	if errors.As(err, &maxErr) {
		deliveriesTotal.WithLabelValues(eventMetric, "payload_too_large").Inc()
		logger().Warn("webhook rejected: body exceeds size limit",
			"remote_addr", r.RemoteAddr,
			"delivery", delivery, "event", eventMetric, "error", err,
			"status", http.StatusRequestEntityTooLarge)
		http.Error(w, "payload too large", http.StatusRequestEntityTooLarge)
	} else {
		deliveriesTotal.WithLabelValues(eventMetric, "bad_request").Inc()
		logger().Warn("webhook rejected: body read failed",
			"remote_addr", r.RemoteAddr,
			"delivery", delivery, "event", eventMetric, "error", err,
			"status", http.StatusBadRequest)
		http.Error(w, "bad request", http.StatusBadRequest)
	}
}

// rejectSignature is the shared 401 for a well-formed signature that
// does not verify — buffered and streaming paths alike.
func (h *Handler) rejectSignature(w http.ResponseWriter, r *http.Request,
	delivery, eventMetric string) {
	deliveriesTotal.WithLabelValues(eventMetric, "unauthorized").Inc()
	logger().Warn("webhook rejected: signature mismatch",
		"remote_addr", r.RemoteAddr,
		"delivery", delivery, "event", eventMetric,
		"status", http.StatusUnauthorized)
	http.Error(w, "invalid signature", http.StatusUnauthorized)
}

// logSafe bounds an unauthenticated header value for logging: GitHub
// delivery GUIDs are 36-char hex+hyphen UUIDs, so anything outside the
// safe alphabet is dropped and anything longer than a UUID is
// truncated — a hostile peer cannot echo arbitrary (or long, or
// control-laden) bytes into the log stream before the HMAC check
// rejects them. Legit IDs survive intact for correlation.
func logSafe(s string) string {
	const maxLen = 64
	n := len(s)
	if n > maxLen {
		n = maxLen
	}
	// Fast path — the overwhelmingly common case: every byte already
	// sits in the safe ASCII alphabet, so the string can be returned
	// (truncated) with zero allocation instead of strings.Map's rune
	// walk building a fresh string.
	i := 0
	for ; i < n; i++ {
		c := s[i]
		if !(c >= '0' && c <= '9' || c >= 'a' && c <= 'z' ||
			c >= 'A' && c <= 'Z' || c == '-' || c == '.' || c == '_') {
			break
		}
	}
	if i == n {
		return s[:n]
	}
	return strings.Map(func(r rune) rune {
		switch {
		case r >= '0' && r <= '9', r >= 'a' && r <= 'z', r >= 'A' && r <= 'Z',
			r == '-', r == '.', r == '_':
			return r
		default:
			// Invalid UTF-8 decodes to RuneError and lands here too.
			return -1
		}
	}, s[:n])
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

// writeSkipped acknowledges an authenticated delivery that was
// filtered before the index lookup — 200 (not 202) with the skip
// reason so operators can tell "matched nothing" from "never
// checked".
func writeSkipped(w http.ResponseWriter, reason string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	_ = json.NewEncoder(w).Encode(map[string]any{
		"matched": 0,
		"skipped": reason,
	})
}
