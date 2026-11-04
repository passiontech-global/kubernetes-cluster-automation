package hubsync

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"path"
	"sort"
	"strings"
	"sync"
)

// exitErr simulates a non-zero remote exit (ExitError contract).
type exitErr struct{ status int }

func (e exitErr) Error() string   { return fmt.Sprintf("exit status %d", e.status) }
func (e exitErr) ExitStatus() int { return e.status }

// fakeConn is a Conn recording every operation in ops and emulating a
// tiny shell over the files map (sha256sum/mv/chmod/mkdir/systemctl).
// sudo mirrors sshConn.sudo: run ops are prefixed `sudo -n ` exactly
// like the real conn (the emulation strips it again).
type fakeConn struct {
	mu    sync.Mutex
	files map[string][]byte
	dirs  map[string]bool // seeded remote dirs (empty dirs the files map can't hold)
	ops   []string        // ordered op log: "run:<cmd>" | "write:<path>"
	sudo  bool            // non-root resolved user → sudo -n prefix

	runHook func(cmd string) (string, error) // optional override
	closed  bool
}

func newFakeConn() *fakeConn {
	return &fakeConn{files: map[string][]byte{}, dirs: map[string]bool{}}
}

// seedFile plants remote content (pre-converged state).
func (f *fakeConn) seedFile(p string, data []byte) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.files[p] = data
}

// seedDir plants a remote directory — `test -d`/`ls` consult it.
func (f *fakeConn) seedDir(p string) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.dirs[p] = true
}

// isDirLocked reports whether p is a remote directory: an explicit
// seedDir, or a path prefix over the files map. Caller holds mu.
func (f *fakeConn) isDirLocked(p string) bool {
	if f.dirs[p] {
		return true
	}
	for fpath := range f.files {
		if path.Dir(fpath) == p || strings.HasPrefix(fpath, p+"/") {
			return true
		}
	}
	return false
}

func (f *fakeConn) opsLog() []string {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]string(nil), f.ops...)
}

func (f *fakeConn) fileContent(p string) ([]byte, bool) {
	f.mu.Lock()
	defer f.mu.Unlock()
	b, ok := f.files[p]
	return b, ok
}

// unshq strips the single quotes shq adds (test paths never carry quotes).
func unshq(s string) string { return strings.Trim(s, "'") }

func (f *fakeConn) Run(_ context.Context, cmd string) (string, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.sudo {
		cmd = "sudo -n " + cmd
	}
	f.ops = append(f.ops, "run:"+cmd)
	if f.runHook != nil {
		return f.runHook(cmd)
	}
	exec := strings.TrimPrefix(cmd, "sudo -n ")
	switch {
	case strings.HasPrefix(exec, "test -d "):
		p := unshq(strings.TrimPrefix(exec, "test -d "))
		if f.isDirLocked(p) {
			return "", nil
		}
		return "", exitErr{1}
	case strings.HasPrefix(exec, "sha256sum "):
		p := unshq(strings.TrimPrefix(exec, "sha256sum "))
		b, ok := f.files[p]
		if !ok {
			return "", exitErr{1}
		}
		sum := sha256.Sum256(b)
		return hex.EncodeToString(sum[:]) + "  " + p, nil
	case strings.HasPrefix(exec, "mv "):
		rest := strings.TrimPrefix(exec, "mv ")
		// two shq-quoted args
		src := unshq(rest[:strings.Index(rest, "' '")+1])
		dst := unshq(rest[strings.Index(rest, "' '")+3:])
		if b, ok := f.files[src]; ok {
			f.files[dst] = b
			delete(f.files, src)
		}
		return "", nil
	case strings.HasPrefix(exec, "ls -1p"):
		// `ls -1pA <dir>` — basenames incl. dotfiles; dirs get a
		// trailing '/' like the real -p flag.
		p := unshq(strings.TrimPrefix(strings.TrimPrefix(exec, "ls -1p"), "A "))
		var ns []string
		for fpath := range f.files {
			if path.Dir(fpath) == p {
				ns = append(ns, path.Base(fpath))
			}
		}
		for d := range f.dirs {
			if path.Dir(d) == p {
				ns = append(ns, path.Base(d)+"/")
			}
		}
		sort.Strings(ns)
		return strings.Join(ns, "\n"), nil
	case strings.HasPrefix(exec, "rm -f "):
		p := unshq(strings.TrimPrefix(exec, "rm -f "))
		delete(f.files, p)
		return "", nil
	default:
		// mkdir/chmod/systemctl/daemon-reload → success no-op.
		return "", nil
	}
}

func (f *fakeConn) Write(_ context.Context, remotePath string, r io.Reader) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.ops = append(f.ops, "write:"+remotePath)
	b, err := io.ReadAll(r)
	if err != nil {
		return err
	}
	f.files[remotePath] = b
	return nil
}

func (f *fakeConn) Close() error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.closed = true
	return nil
}

// fakeDialer hands out seeded conns per target IP and records dials.
type fakeDialer struct {
	mu      sync.Mutex
	conns   map[string]*fakeConn // by target IP — created lazily
	dialSeq []string             // IPs in dial order
	err     map[string]error     // optional per-IP dial failure
}

func newFakeDialer() *fakeDialer {
	return &fakeDialer{conns: map[string]*fakeConn{}}
}

func (d *fakeDialer) Dial(_ context.Context, t Target) (Conn, error) {
	d.mu.Lock()
	defer d.mu.Unlock()
	if err, ok := d.err[t.IP]; ok {
		return nil, err
	}
	d.dialSeq = append(d.dialSeq, t.IP)
	c, ok := d.conns[t.IP]
	if !ok {
		c = newFakeConn()
		user := t.SSHUser
		if user == "" {
			user = "root"
		}
		c.sudo = needsSudo(user)
		d.conns[t.IP] = c
	}
	return c, nil
}

func (d *fakeDialer) conn(t Target) *fakeConn {
	d.mu.Lock()
	defer d.mu.Unlock()
	return d.conns[t.IP]
}

func (d *fakeDialer) dials() []string {
	d.mu.Lock()
	defer d.mu.Unlock()
	return append([]string(nil), d.dialSeq...)
}
