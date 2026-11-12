// certcache.go — stat-key memoization for the X.509 expiry probes.
// PKI bundle files and the nebula host cert are rewritten ~yearly,
// yet every 15s scrape used to re-read + pem.Decode +
// x509.ParseCertificate / protobuf-walk them. fsx.FileStatKey
// fingerprints dev+ino+size+mtime_nsec — every writer here lands
// via atomic rename (new inode), so an unchanged key proves the
// bytes are unchanged and the parse result can be reused. Only the
// FIRST parse of a generation pays the x509 cost.
package hostmetrics

import (
	"os"
	"sync"

	"github.com/passiontech-global/kubernetes-cluster-automation/libs/hostkit/fsx"
)

// certNotAfterCache memoizes "earliest cert notAfter (unix)" per
// file path, keyed by the file's stat fingerprint. ok=false entries
// are cached too — an unparseable cert file stays unparseable until
// its content actually changes (the key covers that).
type certNotAfterCache struct {
	mu sync.Mutex
	m  map[string]certNotAfterEntry
}

type certNotAfterEntry struct {
	key      string
	notAfter int64
	ok       bool
}

// get returns the cached parse for path when its stat key is
// unchanged; otherwise it reads+parses via parse and stores the
// result. A missing/unstatable file returns ok=false WITHOUT
// caching — the file may appear next scrape.
func (c *certNotAfterCache) get(path string,
	parse func(data []byte) (int64, bool)) (int64, bool) {

	key, err := fsx.FileStatKey(path)
	if err != nil {
		return 0, false
	}
	c.mu.Lock()
	if e, hit := c.m[path]; hit && e.key == key {
		c.mu.Unlock()
		return e.notAfter, e.ok
	}
	c.mu.Unlock()

	data, err := os.ReadFile(path)
	if err != nil {
		return 0, false
	}
	notAfter, ok := parse(data)

	c.mu.Lock()
	if c.m == nil {
		c.m = make(map[string]certNotAfterEntry)
	}
	c.m[path] = certNotAfterEntry{key: key, notAfter: notAfter, ok: ok}
	c.mu.Unlock()
	return notAfter, ok
}
