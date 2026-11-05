// nebula_cert.go — minimal protobuf wire reader for the
// PEM-wrapped NebulaCertificate: extracts details.not_after
// without pulling in the slackhq/nebula dependency. Pure
// byte-parsing helpers — no Collector methods. Split out of
// hostmetrics.go.
package hostmetrics

// --- minimal protobuf wire reader for NebulaCertificate ---
// host.crt is a PEM block ("-----BEGIN NEBULA CERTIFICATE-----")
// wrapping a protobuf NebulaCertificate. Only two fields matter:
//
//	NebulaCertificate        field 1 "details"  — wire type 2 (LEN)
//	NebulaCertificateDetails field 6 "not_after" — wire type 0 (varint int64)
//
// Any anomaly (truncation, bad wire type, missing field) → ok=false;
// the caller treats the cert as unreadable and emits nothing. This
// avoids pulling in the slackhq/nebula dependency for one field.

// readVarint decodes one protobuf varint; n=0 signals truncation or
// overflow (>10 bytes / >64 bits).
func readVarint(b []byte) (v uint64, n int) {
	for i := 0; i < len(b) && i < 10; i++ {
		c := b[i]
		if i == 9 && c > 1 { // 10th byte may only carry 1 bit
			return 0, 0
		}
		v |= uint64(c&0x7f) << (7 * i)
		if c < 0x80 {
			return v, i + 1
		}
	}
	return 0, 0
}

// skipWire returns the length in bytes of the protobuf value at b[0]
// for the given wire type. Only the four fixed types are supported —
// group wire types (3/4, deprecated) are treated as unparseable.
func skipWire(b []byte, wire int) (int, bool) {
	switch wire {
	case 0: // varint
		_, n := readVarint(b)
		return n, n > 0
	case 1: // fixed64
		if len(b) < 8 {
			return 0, false
		}
		return 8, true
	case 2: // length-delimited
		ln, n := readVarint(b)
		if n == 0 || uint64(len(b)-n) < ln {
			return 0, false
		}
		return n + int(ln), true
	case 5: // fixed32
		if len(b) < 4 {
			return 0, false
		}
		return 4, true
	}
	return 0, false
}

// nebulaCertNotAfter extracts not_after (unix seconds) from the DER
// body of a nebula PEM cert.
func nebulaCertNotAfter(der []byte) (int64, bool) {
	for len(der) > 0 {
		tag, n := readVarint(der)
		if n == 0 {
			return 0, false
		}
		der = der[n:]
		field, wire := int(tag>>3), int(tag&7)
		if field == 1 && wire == 2 {
			ln, m := readVarint(der)
			if m == 0 || uint64(len(der)-m) < ln {
				return 0, false
			}
			return nebulaDetailsNotAfter(der[m : m+int(ln)])
		}
		m, ok := skipWire(der, wire)
		if !ok {
			return 0, false
		}
		der = der[m:]
	}
	return 0, false
}

// nebulaDetailsNotAfter scans a NebulaCertificateDetails body for
// field 6 (not_after, varint int64). Skips every other field by wire
// type so unknown/added fields can't break the parse.
func nebulaDetailsNotAfter(b []byte) (int64, bool) {
	for len(b) > 0 {
		tag, n := readVarint(b)
		if n == 0 {
			return 0, false
		}
		b = b[n:]
		field, wire := int(tag>>3), int(tag&7)
		if field == 6 && wire == 0 {
			v, m := readVarint(b)
			if m == 0 {
				return 0, false
			}
			return int64(v), true
		}
		m, ok := skipWire(b, wire)
		if !ok {
			return 0, false
		}
		b = b[m:]
	}
	return 0, false
}
