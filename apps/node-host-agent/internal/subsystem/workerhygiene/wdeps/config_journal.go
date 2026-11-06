// config_journal.go — the journald blindness-detector inputs:
// JournalConfig and its defaults. The values are shared with
// controllerhygiene via EnvDeps (journal dirs +
// unreadable-streak budget), so the domain has no env rows of its
// own.
package wdeps

// JournalConfig groups the journald blindness-detector inputs shared
// with controllerhygiene via EnvDeps.
type JournalConfig struct {
	// Dirs are the host journal storage roots — the
	// journal-unreadable latch may only fire while at least one
	// exists (a host with no journald at all fails every read by
	// configuration, not by fault).
	Dirs []string
	// UnreadableNeeded is the consecutive-failed-read budget
	// before state-journal-unreadable latches; <=0 → 5.
	UnreadableNeeded int
}

func (j *JournalConfig) applyDefaults() {
	if len(j.Dirs) == 0 {
		// /host mount convention like the other defaults; standalone
		// wiring passes the unprefixed host paths.
		j.Dirs = []string{
			"/host/var/log/journal", "/host/run/log/journal"}
	}
	if j.UnreadableNeeded <= 0 {
		j.UnreadableNeeded = DefaultJournalUnreadableNeeded
	}
}
