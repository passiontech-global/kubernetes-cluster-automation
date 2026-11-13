// helpers_test.go — the package-wide test context. The pods/eviction
// emulation lives as testutil.EmulateEviction (recover() evicts via
// the PDB-respecting Eviction API).
package corednswatchdog

import "context"

var ctx = context.Background()
