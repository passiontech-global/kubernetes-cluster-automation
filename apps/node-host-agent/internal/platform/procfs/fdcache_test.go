package procfs

import (
	"os"
	"path/filepath"
	"reflect"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

func TestScanFDsInotifyAndBPF(t *testing.T) {
	root := t.TempDir()

	// PID 100: one inotify fd with 3 watches, one zero-watch inotify fd (no fdinfo),
	// one bpf-prog fdinfo, one regular file fd (ignored).
	mkDir(t, filepath.Join(root, "100", "fd"))
	mkDir(t, filepath.Join(root, "100", "fdinfo"))
	if err := os.Symlink("anon_inode:inotify", filepath.Join(root, "100", "fd", "3")); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, "100", "fdinfo", "3"),
		[]byte("pos:\t0\ninotify wd:1 ino:10\ninotify wd:2 ino:20\ninotify wd:3 ino:30\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink("anon_inode:inotify", filepath.Join(root, "100", "fd", "4")); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink("anon_inode:bpf-prog", filepath.Join(root, "100", "fd", "5")); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, "100", "fdinfo", "5"),
		[]byte("pos:\t0\nprog_id:\t42\nprog_id:\t17\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink("/dev/null", filepath.Join(root, "100", "fd", "6")); err != nil {
		t.Fatal(err)
	}

	// PID 200: D-state in stat (must still be scanned safely via fd/fdinfo without touching mm)
	// plus bpf-link with duplicate prog_id 42 and two map_ids.
	mkDir(t, filepath.Join(root, "200", "fd"))
	mkDir(t, filepath.Join(root, "200", "fdinfo"))
	if err := os.WriteFile(filepath.Join(root, "200", "stat"), []byte("200 (d-proc) D 1 1 0"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink("anon_inode:bpf-link", filepath.Join(root, "200", "fd", "7")); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, "200", "fdinfo", "7"),
		[]byte("prog_id:\t42\nmap_id:\t100\nmap_id:\t50\n"), 0o644); err != nil {
		t.Fatal(err)
	}

	// Non-numeric dir ignored; missing fd dir tolerated.
	mkDir(t, filepath.Join(root, "self"))
	mkDir(t, filepath.Join(root, "300"))

	snap := New(root).ScanFDs(nil)
	if !snap.ProcOK {
		t.Fatal("ProcOK = false, want true")
	}
	if len(snap.Inotify) != 2 {
		t.Fatalf("Inotify len = %d, want 2: %+v", len(snap.Inotify), snap.Inotify)
	}
	byFD := map[int]int64{}
	for _, entry := range snap.Inotify {
		if entry.PID != 100 {
			t.Fatalf("unexpected PID %d", entry.PID)
		}
		byFD[entry.FD] = entry.Watches
	}
	if byFD[3] != 3 || byFD[4] != 0 {
		t.Fatalf("byFD = %+v, want {3:3, 4:0}", byFD)
	}
	if !reflect.DeepEqual(snap.BPFProgs, []uint64{17, 42}) {
		t.Fatalf("BPFProgs = %v, want [17 42]", snap.BPFProgs)
	}
	if !reflect.DeepEqual(snap.BPFMaps, []uint64{50, 100}) {
		t.Fatalf("BPFMaps = %v, want [50 100]", snap.BPFMaps)
	}

	// Explicit pid subset filters scan.
	subSnap := New(root).ScanFDs([]int{200})
	if len(subSnap.Inotify) != 0 || !reflect.DeepEqual(subSnap.BPFProgs, []uint64{42}) {
		t.Fatalf("subset ScanFDs([200]) = %+v", subSnap)
	}

	// Empty explicit pid slice scans 0 pids.
	emptySnap := New(root).ScanFDs([]int{})
	if !emptySnap.ProcOK || len(emptySnap.Inotify) != 0 || len(emptySnap.BPFProgs) != 0 {
		t.Fatalf("ScanFDs([]) = %+v", emptySnap)
	}

	// Missing proc root reports ProcOK = false.
	missingSnap := New(filepath.Join(t.TempDir(), "missing")).ScanFDs(nil)
	if missingSnap.ProcOK {
		t.Fatal("missing root must report ProcOK = false")
	}
}

func TestCountInotifyWatchesLongLineStreaming(t *testing.T) {
	p := filepath.Join(t.TempDir(), "fdinfo")
	longWatch := "inotify wd:1 " + strings.Repeat("x", 10000) + "\ninotify wd:2 short\n"
	if err := os.WriteFile(p, []byte(longWatch), 0o644); err != nil {
		t.Fatal(err)
	}
	if got, ok := countInotifyWatches(p); !ok || got != 2 {
		t.Fatalf("countInotifyWatches = (%d, %v), want (2, true)", got, ok)
	}
}

func TestFDCacheTTLBackwardClockAndShared(t *testing.T) {
	root := t.TempDir()
	mkDir(t, filepath.Join(root, "10", "fd"))
	if err := os.Symlink("anon_inode:inotify", filepath.Join(root, "10", "fd", "3")); err != nil {
		t.Fatal(err)
	}

	now := time.Date(2026, 1, 1, 12, 0, 0, 0, time.UTC)
	var mu sync.Mutex
	getNow := func() time.Time {
		mu.Lock()
		defer mu.Unlock()
		return now
	}
	setNow := func(t time.Time) {
		mu.Lock()
		now = t
		mu.Unlock()
	}

	c := NewFDCache(root, getNow)
	s1 := c.Snapshot(time.Minute)
	if len(s1.Inotify) != 1 {
		t.Fatalf("s1 Inotify = %+v", s1.Inotify)
	}

	// Mutate proc while within TTL: cached snapshot is returned.
	mkDir(t, filepath.Join(root, "20", "fd"))
	if err := os.Symlink("anon_inode:inotify", filepath.Join(root, "20", "fd", "3")); err != nil {
		t.Fatal(err)
	}
	setNow(now.Add(30 * time.Second))
	s2 := c.Snapshot(time.Minute)
	if s2 != s1 {
		t.Fatal("expected cached snapshot within TTL")
	}

	// TTL expires: fresh walk sees PID 20 too.
	setNow(now.Add(31 * time.Second))
	s3 := c.Snapshot(time.Minute)
	if len(s3.Inotify) != 2 {
		t.Fatalf("after TTL expiry Inotify len = %d, want 2", len(s3.Inotify))
	}

	// Backward clock step (now < snap.At): must force fresh walk instead of sticking.
	mkDir(t, filepath.Join(root, "30", "fd"))
	if err := os.Symlink("anon_inode:inotify", filepath.Join(root, "30", "fd", "3")); err != nil {
		t.Fatal(err)
	}
	setNow(s3.At.Add(-10 * time.Second))
	s4 := c.Snapshot(time.Minute)
	if len(s4.Inotify) != 3 {
		t.Fatalf("after backward clock step Inotify len = %d, want 3", len(s4.Inotify))
	}

	// SharedFDCache returns identical pointer for equivalent paths.
	a := SharedFDCache(root+"/", nil)
	b := SharedFDCache(root, nil)
	if a != b {
		t.Fatal("SharedFDCache did not deduplicate equivalent canonical roots")
	}
}

func TestFDCacheConcurrentSingleflightAndPanicSafety(t *testing.T) {
	root := t.TempDir()
	for i := 1; i <= 5; i++ {
		d := filepath.Join(root, strconv.Itoa(i), "fd")
		mkDir(t, d)
		if err := os.Symlink("anon_inode:inotify", filepath.Join(d, "3")); err != nil {
			t.Fatal(err)
		}
	}

	c := NewFDCache(root, nil)
	var wg sync.WaitGroup
	snaps := make([]*FDSnapshot, 16)
	for i := range 16 {
		wg.Go(func() {
			snaps[i] = c.Snapshot(time.Minute)
		})
	}
	wg.Wait()
	for i := 1; i < len(snaps); i++ {
		if snaps[i] != snaps[0] {
			t.Fatalf("concurrent Snapshot callers did not share singleflight snapshot")
		}
	}

	// Panic safety: if c.now panics on first call, c.inflight is cleared so
	// subsequent calls do not deadlock.
	var calls atomic.Int32
	cPanic := NewFDCache(root, func() time.Time {
		if calls.Add(1) == 2 {
			panic("clock boom")
		}
		return time.Now()
	})
	func() {
		defer func() { _ = recover() }()
		_ = cPanic.Snapshot(time.Minute)
	}()
	snap := cPanic.Snapshot(time.Minute)
	if len(snap.Inotify) != 5 {
		t.Fatalf("post-panic Snapshot Inotify len = %d, want 5", len(snap.Inotify))
	}
}

func TestFDCacheEntryClockPanicDoesNotDeadlock(t *testing.T) {
	root := t.TempDir()
	mkDir(t, filepath.Join(root, "10", "fd"))
	if err := os.Symlink("anon_inode:inotify", filepath.Join(root, "10", "fd", "3")); err != nil {
		t.Fatal(err)
	}

	var calls atomic.Int32
	c := NewFDCache(root, func() time.Time {
		if calls.Add(1) == 1 {
			panic("entry clock boom")
		}
		return time.Now()
	})
	func() {
		defer func() { _ = recover() }()
		_ = c.Snapshot(time.Minute)
	}()

	done := make(chan *FDSnapshot, 1)
	go func() {
		done <- c.Snapshot(time.Minute)
	}()
	select {
	case snap := <-done:
		if len(snap.Inotify) != 1 {
			t.Fatalf("post-entry-panic Snapshot Inotify len = %d, want 1", len(snap.Inotify))
		}
	case <-time.After(2 * time.Second):
		t.Fatal("Snapshot deadlocked after entry c.now() panic")
	}
}

func TestFDCacheDoesNotCacheProcNotOK(t *testing.T) {
	now := time.Date(2026, 1, 1, 12, 0, 0, 0, time.UTC)
	var mu sync.Mutex
	getNow := func() time.Time {
		mu.Lock()
		defer mu.Unlock()
		return now
	}
	advance := func(d time.Duration) {
		mu.Lock()
		now = now.Add(d)
		mu.Unlock()
	}

	t.Run("missing proc root recovers immediately within TTL", func(t *testing.T) {
		root := filepath.Join(t.TempDir(), "proc")
		c := NewFDCache(root, getNow)

		s1 := c.Snapshot(time.Minute)
		if s1.ProcOK {
			t.Fatal("expected ProcOK=false on missing proc root")
		}

		// Create proc root with PID 10 within TTL -> must NOT be pinned to !ProcOK.
		mkDir(t, filepath.Join(root, "10", "fd"))
		if err := os.Symlink("anon_inode:inotify", filepath.Join(root, "10", "fd", "3")); err != nil {
			t.Fatal(err)
		}
		advance(5 * time.Second)

		s2 := c.Snapshot(time.Minute)
		if !s2.ProcOK || s2.Partial || len(s2.Inotify) != 1 {
			t.Fatalf("expected immediate recovery within TTL, got %+v", s2)
		}

		// Complete snapshot is now cached within TTL.
		advance(5 * time.Second)
		if s3 := c.Snapshot(time.Minute); s3 != s2 {
			t.Fatal("expected complete recovered snapshot to be cached within TTL")
		}
	})

	t.Run("proc root EACCES recovers immediately within TTL", func(t *testing.T) {
		if os.Geteuid() == 0 {
			t.Skip("chmod 0111 does not restrict ReadDir under UID 0")
		}
		root := t.TempDir()
		mkDir(t, filepath.Join(root, "10", "fd"))
		if err := os.Symlink("anon_inode:inotify", filepath.Join(root, "10", "fd", "3")); err != nil {
			t.Fatal(err)
		}
		if err := os.Chmod(root, 0o111); err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = os.Chmod(root, 0o755) })

		c := NewFDCache(root, getNow)
		s1 := c.Snapshot(time.Minute)
		if s1.ProcOK {
			t.Fatal("expected ProcOK=false on 0o111 proc root")
		}

		if err := os.Chmod(root, 0o755); err != nil {
			t.Fatal(err)
		}
		advance(5 * time.Second)

		s2 := c.Snapshot(time.Minute)
		if !s2.ProcOK || s2.Partial || len(s2.Inotify) != 1 {
			t.Fatalf("expected immediate recovery after chmod 0755, got %+v", s2)
		}
	})
}

func TestFDCacheDoesNotCachePartialScans(t *testing.T) {
	newClock := func() (func() time.Time, func(time.Duration)) {
		now := time.Date(2026, 1, 1, 12, 0, 0, 0, time.UTC)
		var mu sync.Mutex
		return func() time.Time {
				mu.Lock()
				defer mu.Unlock()
				return now
			}, func(d time.Duration) {
				mu.Lock()
				now = now.Add(d)
				mu.Unlock()
			}
	}

	t.Run("pid fd ENOTDIR not cached and recovers immediately", func(t *testing.T) {
		root := t.TempDir()
		mkDir(t, filepath.Join(root, "10", "fd"))
		if err := os.Symlink("anon_inode:inotify", filepath.Join(root, "10", "fd", "3")); err != nil {
			t.Fatal(err)
		}
		mkDir(t, filepath.Join(root, "20"))
		fdFile := filepath.Join(root, "20", "fd")
		if err := os.WriteFile(fdFile, []byte("not-a-dir"), 0o644); err != nil {
			t.Fatal(err)
		}

		getNow, advance := newClock()
		c := NewFDCache(root, getNow)
		s1 := c.Snapshot(time.Minute)
		if !s1.ProcOK || !s1.Partial || len(s1.Inotify) != 1 {
			t.Fatalf("s1 = %+v, want ProcOK=true Partial=true len(Inotify)=1", s1)
		}

		if err := os.Remove(fdFile); err != nil {
			t.Fatal(err)
		}
		mkDir(t, fdFile)
		if err := os.Symlink("anon_inode:inotify", filepath.Join(fdFile, "3")); err != nil {
			t.Fatal(err)
		}
		advance(5 * time.Second)

		s2 := c.Snapshot(time.Minute)
		if s2 == s1 || !s2.ProcOK || s2.Partial || len(s2.Inotify) != 2 {
			t.Fatalf("expected immediate recovery from ENOTDIR, got %+v", s2)
		}
		advance(5 * time.Second)
		if s3 := c.Snapshot(time.Minute); s3 != s2 {
			t.Fatal("expected complete snapshot s2 to be cached within TTL")
		}
	})

	t.Run("pid fdinfo ENOTDIR not cached for inotify and ebpf", func(t *testing.T) {
		root := t.TempDir()
		mkDir(t, filepath.Join(root, "10", "fd"))
		if err := os.Symlink("anon_inode:inotify", filepath.Join(root, "10", "fd", "3")); err != nil {
			t.Fatal(err)
		}
		if err := os.Symlink("anon_inode:bpf-prog", filepath.Join(root, "10", "fd", "5")); err != nil {
			t.Fatal(err)
		}
		fdinfoPath := filepath.Join(root, "10", "fdinfo")
		if err := os.WriteFile(fdinfoPath, []byte("not-a-dir"), 0o644); err != nil {
			t.Fatal(err)
		}

		getNow, advance := newClock()
		c := NewFDCache(root, getNow)
		s1 := c.Snapshot(time.Minute)
		if !s1.ProcOK || !s1.Partial || len(s1.Inotify) != 1 || s1.Inotify[0].Watches != 0 || len(s1.BPFProgs) != 0 {
			t.Fatalf("s1 = %+v, want ProcOK=true Partial=true Watches=0 BPFProgs=[]", s1)
		}

		if err := os.Remove(fdinfoPath); err != nil {
			t.Fatal(err)
		}
		mkDir(t, fdinfoPath)
		if err := os.WriteFile(filepath.Join(fdinfoPath, "3"), []byte("inotify wd:1 ino:1\ninotify wd:2 ino:2\n"), 0o644); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(fdinfoPath, "5"), []byte("prog_id:\t99\n"), 0o644); err != nil {
			t.Fatal(err)
		}
		advance(5 * time.Second)

		s2 := c.Snapshot(time.Minute)
		if s2 == s1 || !s2.ProcOK || s2.Partial || s2.Inotify[0].Watches != 2 || !reflect.DeepEqual(s2.BPFProgs, []uint64{99}) {
			t.Fatalf("expected immediate recovery from fdinfo ENOTDIR, got %+v", s2)
		}
	})

	t.Run("pid fd and fdinfo EACCES not cached and recover immediately", func(t *testing.T) {
		if os.Geteuid() == 0 {
			t.Skip("chmod 0000 does not block UID 0")
		}
		root := t.TempDir()
		mkDir(t, filepath.Join(root, "10", "fd"))
		mkDir(t, filepath.Join(root, "10", "fdinfo"))
		if err := os.Symlink("anon_inode:inotify", filepath.Join(root, "10", "fd", "3")); err != nil {
			t.Fatal(err)
		}
		fi3 := filepath.Join(root, "10", "fdinfo", "3")
		if err := os.WriteFile(fi3, []byte("inotify wd:1 ino:1\n"), 0o644); err != nil {
			t.Fatal(err)
		}
		mkDir(t, filepath.Join(root, "20", "fd"))
		if err := os.Symlink("anon_inode:inotify", filepath.Join(root, "20", "fd", "3")); err != nil {
			t.Fatal(err)
		}

		// Case A: /proc/20/fd is 0o000 (EACCES).
		fd20 := filepath.Join(root, "20", "fd")
		if err := os.Chmod(fd20, 0o000); err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = os.Chmod(fd20, 0o755) })

		getNow, advance := newClock()
		c := NewFDCache(root, getNow)
		s1 := c.Snapshot(time.Minute)
		if !s1.ProcOK || !s1.Partial || len(s1.Inotify) != 1 {
			t.Fatalf("s1 (fd EACCES) = %+v, want ProcOK=true Partial=true len(Inotify)=1", s1)
		}

		// Restore fd20, but make fdinfo/3 0o000 (EACCES) and exercise concurrent readers under -race.
		if err := os.Chmod(fd20, 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.Chmod(fi3, 0o000); err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = os.Chmod(fi3, 0o644) })
		advance(5 * time.Second)

		var wg sync.WaitGroup
		snaps := make([]*FDSnapshot, 8)
		for i := range snaps {
			wg.Go(func() {
				snaps[i] = c.Snapshot(time.Minute)
			})
		}
		wg.Wait()
		for _, s := range snaps {
			if !s.ProcOK || !s.Partial {
				t.Fatalf("expected Partial=true during fdinfo EACCES, got %+v", s)
			}
		}

		// Restore fdinfo/3 and recover immediately within TTL.
		if err := os.Chmod(fi3, 0o644); err != nil {
			t.Fatal(err)
		}
		advance(5 * time.Second)
		s3 := c.Snapshot(time.Minute)
		if !s3.ProcOK || s3.Partial || len(s3.Inotify) != 2 {
			t.Fatalf("expected immediate recovery after EACCES cleared, got %+v", s3)
		}
		for _, entry := range s3.Inotify {
			if entry.PID == 10 && entry.Watches != 1 {
				t.Fatalf("PID 10 watches = %d, want 1", entry.Watches)
			}
		}

		// Expired warm cache hitting EACCES clears c.snap instead of re-caching partial.
		advance(2 * time.Minute)
		if err := os.Chmod(fd20, 0o000); err != nil {
			t.Fatal(err)
		}
		s4 := c.Snapshot(time.Minute)
		if !s4.Partial {
			t.Fatalf("expected Partial=true after TTL expiry with fd EACCES, got %+v", s4)
		}
		if err := os.Chmod(fd20, 0o755); err != nil {
			t.Fatal(err)
		}
		advance(5 * time.Second)
		s5 := c.Snapshot(time.Minute)
		if s5 == s4 || s5.Partial || len(s5.Inotify) != 2 {
			t.Fatalf("expected immediate recovery after expired partial scan, got %+v", s5)
		}
	})
}

func TestFDCacheTransientExitedPIDENOENTStillCaches(t *testing.T) {
	root := t.TempDir()
	// PID 10: complete inotify fd with fdinfo.
	mkDir(t, filepath.Join(root, "10", "fd"))
	mkDir(t, filepath.Join(root, "10", "fdinfo"))
	if err := os.Symlink("anon_inode:inotify", filepath.Join(root, "10", "fd", "3")); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, "10", "fdinfo", "3"), []byte("inotify wd:1 ino:1\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	// PID 20: exited PID without fd subdir (ENOENT on /proc/20/fd).
	mkDir(t, filepath.Join(root, "20"))
	// PID 30: inotify fd + bpf fd whose fdinfo entries vanished (ENOENT on fdinfo).
	mkDir(t, filepath.Join(root, "30", "fd"))
	if err := os.Symlink("anon_inode:inotify", filepath.Join(root, "30", "fd", "4")); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink("anon_inode:bpf-prog", filepath.Join(root, "30", "fd", "5")); err != nil {
		t.Fatal(err)
	}
	// PID 40: dangling fd link target removed or ENOENT on Readlink (empty symlink name simulated via missing target? os.Readlink reads symlink itself; a dangling symlink still succeeds Readlink, so missing fd dir covers ENOENT).

	now := time.Date(2026, 1, 1, 12, 0, 0, 0, time.UTC)
	c := NewFDCache(root, func() time.Time { return now })
	s1 := c.Snapshot(time.Minute)
	if !s1.ProcOK || s1.Partial || len(s1.Inotify) != 2 {
		t.Fatalf("expected complete cacheable snapshot despite ENOENTs, got %+v", s1)
	}

	// Mutate root within TTL: must return cached s1.
	mkDir(t, filepath.Join(root, "50", "fd"))
	if err := os.Symlink("anon_inode:inotify", filepath.Join(root, "50", "fd", "3")); err != nil {
		t.Fatal(err)
	}
	now = now.Add(15 * time.Second)
	s2 := c.Snapshot(time.Minute)
	if s2 != s1 {
		t.Fatal("expected complete ENOENT-tolerant snapshot to be cached within TTL")
	}
}
