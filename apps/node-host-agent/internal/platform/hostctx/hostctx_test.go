// hostctx_test.go — NodeName: the shared identity precedence
// (NODE_HOST_AGENT_NODE_NAME > NODE_NAME > fallback) main.go and the
// ops subcommands used to repeat inline. Sequential t.Setenv only —
// envx reads os.Getenv per call.

package hostctx

import (
	"testing"

	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-host-agent/internal/envnames"
)

func TestNodeNamePrecedence(t *testing.T) {
	t.Setenv(envnames.EnvNodeName, "explicit-node")
	t.Setenv("NODE_NAME", "downward-node")
	if got := NodeName("flag-fallback"); got != "explicit-node" {
		t.Fatalf("NodeName=%q want the NODE_HOST_AGENT_ override", got)
	}

	// Empty (unset in production) → the downward-API name applies.
	t.Setenv(envnames.EnvNodeName, "")
	if got := NodeName("flag-fallback"); got != "downward-node" {
		t.Fatalf("NodeName=%q want NODE_NAME", got)
	}

	// Both empty → the --node-name flag fallback ("" for default-off
	// callers).
	t.Setenv("NODE_NAME", "")
	if got := NodeName("flag-fallback"); got != "flag-fallback" {
		t.Fatalf("NodeName=%q want the fallback", got)
	}
}
