package promfile

import (
	"bufio"
	"bytes"
	"io"
	"strings"
)

// ScanLinesWithPrefixes streams a Prometheus /metrics body through a 64 KiB
// bufio.Scanner, keeping only lines that start with one of prefixes, capped at
// maxBytes of kept output so a multi-MiB /metrics response never gets
// materialized in full.
func ScanLinesWithPrefixes(r io.Reader, prefixes [][]byte, maxBytes int) (string, error) {
	sc := bufio.NewScanner(r)
	sc.Buffer(make([]byte, 0, 64<<10), 64<<10)
	var kept []string
	size := 0
	for sc.Scan() {
		ln := sc.Bytes()
		for _, p := range prefixes {
			if bytes.HasPrefix(ln, p) {
				kept = append(kept, string(ln))
				size += len(ln) + 1
				if maxBytes > 0 && size >= maxBytes {
					return strings.Join(kept, "\n"), nil
				}
				break
			}
		}
	}
	if err := sc.Err(); err != nil {
		return "", err
	}
	return strings.Join(kept, "\n"), nil
}
