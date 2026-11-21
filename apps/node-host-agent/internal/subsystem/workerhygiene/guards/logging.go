// logging.go — shared subsystem logger for the guards package, keeping the
// parent "workerhygiene" log identity.
package guards

import (
	"log/slog"

	"github.com/passiontech-global/kubernetes-cluster-automation/libs/hostkit/logx"
)

func logger() *slog.Logger { return logx.For("workerhygiene") }
