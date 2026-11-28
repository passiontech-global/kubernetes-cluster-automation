package httpx

import (
	"bytes"
	"errors"
	"io"
	"strings"
	"testing"
)

type trackingReadCloser struct {
	r      io.Reader
	read   int64
	closed bool
}

func (t *trackingReadCloser) Read(p []byte) (int, error) {
	n, err := t.r.Read(p)
	t.read += int64(n)
	return n, err
}

func (t *trackingReadCloser) Close() error {
	t.closed = true
	return nil
}

type errAfterReader struct {
	payload []byte
	off     int
	err     error
}

func (e *errAfterReader) Read(p []byte) (int, error) {
	if e.off < len(e.payload) {
		n := copy(p, e.payload[e.off:])
		e.off += n
		return n, nil
	}
	return 0, e.err
}

func TestDrainAndClose(t *testing.T) {
	// Nil-safe.
	DrainAndClose(nil, 1024)

	// Drains up to maxBytes and closes.
	rc := &trackingReadCloser{r: strings.NewReader("0123456789abcdef")}
	DrainAndClose(rc, 6)
	if !rc.closed {
		t.Fatal("DrainAndClose did not close body")
	}
	if rc.read != 6 {
		t.Fatalf("DrainAndClose read %d bytes, want 6", rc.read)
	}

	// Non-positive maxBytes closes without reading.
	rcZero := &trackingReadCloser{r: strings.NewReader("012345")}
	DrainAndClose(rcZero, 0)
	if !rcZero.closed || rcZero.read != 0 {
		t.Fatalf("DrainAndClose(0) closed=%v read=%d, want closed=true read=0", rcZero.closed, rcZero.read)
	}
}

func TestReadBounded(t *testing.T) {
	// Nil reader is safe.
	data, truncated, err := ReadBounded(nil, 10)
	if data != nil || truncated || err != nil {
		t.Fatalf("ReadBounded(nil) = (%v, %v, %v), want (nil, false, nil)", data, truncated, err)
	}

	// Exact fit is NOT truncated.
	data, truncated, err = ReadBounded(strings.NewReader("hello"), 5)
	if err != nil || truncated || string(data) != "hello" {
		t.Fatalf("exact fit = (%q, %v, %v), want (hello, false, nil)", data, truncated, err)
	}

	// 1 byte over cap IS truncated, returning exactly maxBytes.
	data, truncated, err = ReadBounded(strings.NewReader("hello!"), 5)
	if err != nil || !truncated || string(data) != "hello" {
		t.Fatalf("over cap = (%q, %v, %v), want (hello, true, nil)", data, truncated, err)
	}

	// Zero / negative cap detects non-empty stream truncation cleanly.
	data, truncated, err = ReadBounded(strings.NewReader("x"), 0)
	if err != nil || !truncated || len(data) != 0 {
		t.Fatalf("zero cap non-empty = (%q, %v, %v), want (\"\", true, nil)", data, truncated, err)
	}
	data, truncated, err = ReadBounded(bytes.NewReader(nil), -5)
	if err != nil || truncated || len(data) != 0 {
		t.Fatalf("negative cap empty = (%q, %v, %v), want (\"\", false, nil)", data, truncated, err)
	}

	// Reader error propagates alongside partial bytes.
	wantErr := errors.New("boom")
	data, truncated, err = ReadBounded(&errAfterReader{payload: []byte("abc"), err: wantErr}, 10)
	if !errors.Is(err, wantErr) || truncated || string(data) != "abc" {
		t.Fatalf("errAfterReader = (%q, %v, %v), want (abc, false, boom)", data, truncated, err)
	}
}
