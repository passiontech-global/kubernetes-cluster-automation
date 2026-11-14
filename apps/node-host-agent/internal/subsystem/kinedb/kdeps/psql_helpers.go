// psql_helpers.go — shared advisory-lock script framing and XID age query.
package kdeps

import (
	"context"
	"fmt"
	"os"
	"strconv"
	"strings"
	"time"
)

// GuardRateTrySpend ensures GuardStateDir exists before RateTrySpend.
func (d *Deps) GuardRateTrySpend(name string, interval time.Duration) bool {
	_ = os.MkdirAll(d.Cfg.GuardStateDir, 0o755)
	return d.State.RateTrySpend(name, interval)
}

// GuardRateSpend ensures GuardStateDir exists before RateSpend.
func (d *Deps) GuardRateSpend(name string) {
	_ = os.MkdirAll(d.Cfg.GuardStateDir, 0o755)
	d.State.RateSpend(name)
}

// WrapAdvisoryLockScript wraps a psql script body in a non-blocking
// pg_try_advisory_lock(lockID) / pg_advisory_unlock(lockID) guard, echoing
// LockBusyMarker when another session holds the lock.
func WrapAdvisoryLockScript(lockID int64, varName, body string) string {
	var b strings.Builder
	fmt.Fprintf(&b,
		"SELECT CASE WHEN pg_try_advisory_lock(%d) THEN 'on' ELSE 'off' END AS %s;\n",
		lockID, varName)
	fmt.Fprintf(&b, "\\gset\n\\if :%s\n", varName)
	b.WriteString(body)
	fmt.Fprintf(&b, "SELECT pg_advisory_unlock(%d);\n", lockID)
	b.WriteString("\\else\n\\echo '" + LockBusyMarker + "'\n\\endif\n")
	return b.String()
}

// QueryXidAge reads COALESCE(MAX(age(datfrozenxid)), 0) across pg_database.
func (d *Deps) QueryXidAge(ctx context.Context, pg, user, pass string) (int64, error) {
	out, err := d.PsqlQuery(ctx, pg, user, pass,
		"SELECT COALESCE(MAX(age(datfrozenxid)),0) FROM pg_database")
	if err != nil {
		return 0, fmt.Errorf("xid-age-fail: %w", err)
	}
	v, perr := strconv.ParseInt(FirstLine(out), 10, 64)
	if perr != nil {
		return 0, fmt.Errorf("xid-age-unparsed: %w", perr)
	}
	return v, nil
}
