// helpers_test.go — the package-wide test context. The pods/eviction
// emulation lives as testutil.EmulateEviction (the unblock-heal tests
// need it since the heal moved to the policy/v1 Eviction API).
package apiserviceguard

import "context"

var ctx = context.Background()
