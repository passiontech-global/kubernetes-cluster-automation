//go:build timetzdata

// tzdata.go — embeds the IANA tz database into the binary. Only the
// standalone build (moon :build → the systemd units hubsync writes
// onto arbitrary hosts) carries -tags timetzdata: those hosts cannot
// be assumed to ship /usr/share/zoneinfo, and feeder's
// ParseSystemdTimestamp resolves systemd's abbrev stamps through
// time.LoadLocation. The pod image deliberately does NOT set the
// tag — its apk tzdata package already provides the database and
// the ~450KB embed would only bloat the layer.
package main

import _ "time/tzdata"
