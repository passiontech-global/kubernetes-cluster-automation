// diskprefail_test.go — disk-pre-fail (A5) coverage: the ext4
// errors_count evidence (latch on >0, clear on 0), the packed sysfs
// smart_log page parse and the nvme-cli fallback parse.
package kernelfail

import (
	"context"
	"encoding/binary"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-host-agent/internal/latchdefs"
)

// seedPrefailFixture re-points the engine's sysfs seams at a temp
// tree and returns the tree root.
func seedPrefailFixture(t *testing.T, r *Runner) string {
	t.Helper()
	root := t.TempDir()
	r.deps.Ext4ErrorsGlob = filepath.Join(root, "sys", "fs", "ext4", "*", "errors_count")
	r.deps.NVMeSmartGlob = filepath.Join(root, "sys", "class", "nvme", "nvme*", "smart_log")
	return root
}

func writePrefailFile(t *testing.T, path, content string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}
}

func prefailLatchSet(r *Runner) bool {
	_, err := os.Stat(r.deps.Store.Path(latchdefs.LatchDiskPreFail))
	return err == nil
}

func readPrefailProm(t *testing.T, r *Runner) string {
	t.Helper()
	data, err := os.ReadFile(filepath.Join(r.textfileDir(), diskPreFailPromName))
	if err != nil {
		return ""
	}
	return string(data)
}

func TestDiskPreFailExt4ErrorsCountLatches(t *testing.T) {
	f := kfixture(t)
	root := seedPrefailFixture(t, f.r)
	writePrefailFile(t, filepath.Join(root, "sys", "fs", "ext4", "vda1", "errors_count"), "3\n")
	writePrefailFile(t, filepath.Join(root, "sys", "fs", "ext4", "vdb1", "errors_count"), "0\n")

	f.r.updateDiskPreFailEvidence(context.Background())
	if !prefailLatchSet(f.r) {
		t.Fatal("state-disk-pre-fail not latched on errors_count=3")
	}
	logData, err := os.ReadFile(f.log)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(logData), "disk-pre-fail") ||
		!strings.Contains(string(logData), "ext4 vda1 errors_count=3") {
		t.Fatalf("STATE-ENTER evidence missing:\n%s", logData)
	}
	// vda1's count exports; vdb1 is a REAL readable zero (the count
	// source parsed — emission, not fabrication), so both gauges
	// render.
	prom := readPrefailProm(t, f.r)
	if !strings.Contains(prom, `node_agent_disk_ext4_prefail_errors_count{dev="vda1"} 3`) {
		t.Fatalf("ext4 gauge missing:\n%s", prom)
	}
	if !strings.Contains(prom, `node_agent_disk_ext4_prefail_errors_count{dev="vdb1"} 0`) {
		t.Fatalf("clean filesystem's real-zero gauge missing:\n%s", prom)
	}
}

func TestDiskPreFailCleanExitsLatch(t *testing.T) {
	f := kfixture(t)
	root := seedPrefailFixture(t, f.r)
	writePrefailFile(t, filepath.Join(root, "sys", "fs", "ext4", "vda1", "errors_count"), "3\n")
	f.r.updateDiskPreFailEvidence(context.Background())
	if !prefailLatchSet(f.r) {
		t.Fatal("latch did not arm")
	}
	writePrefailFile(t, filepath.Join(root, "sys", "fs", "ext4", "vda1", "errors_count"), "0\n")
	f.r.updateDiskPreFailEvidence(context.Background())
	if prefailLatchSet(f.r) {
		t.Fatal("latch held on clean evidence")
	}
	// The gauge still reports the real zero; only an UNREADABLE
	// source drops the family (and with no sources at all, no file).
	if prom := readPrefailProm(t, f.r); !strings.Contains(prom, `dev="vda1"} 0`) {
		t.Fatalf("readable zero gauge missing:\n%s", prom)
	}
}

func TestDiskPreFailNVMeSysfsPageEvidence(t *testing.T) {
	f := kfixture(t)
	root := seedPrefailFixture(t, f.r)
	// A packed nvme_smart_log page: critical_warning=0x4 (NVM set),
	// percentage_used=42 (clean), media_errors=7 — media errors
	// alone are the pre-fail signal.
	page := make([]byte, 512)
	page[0] = 0x4
	page[5] = 42
	binary.LittleEndian.PutUint64(page[nvmeMediaErrorsOffset:], 7)
	writePrefailFile(t,
		filepath.Join(root, "sys", "class", "nvme", "nvme0", "smart_log"),
		string(page))
	f.r.updateDiskPreFailEvidence(context.Background())
	if !prefailLatchSet(f.r) {
		t.Fatal("state-disk-pre-fail not latched on nvme media_errors=7")
	}
	logData, err := os.ReadFile(f.log)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(logData),
		"nvme nvme0 critical_warning=4 media_errors=7 percentage_used=42 (sysfs)") {
		t.Fatalf("nvme evidence missing:\n%s", logData)
	}
	prom := readPrefailProm(t, f.r)
	for _, want := range []string{
		`node_agent_nvme_smart_critical_warning{ctrl="nvme0",src="sysfs"} 4`,
		`node_agent_nvme_smart_media_errors{ctrl="nvme0",src="sysfs"} 7`,
		`node_agent_nvme_smart_percentage_used{ctrl="nvme0",src="sysfs"} 42`,
	} {
		if !strings.Contains(prom, want) {
			t.Fatalf("textfile missing %q:\n%s", want, prom)
		}
	}
}

func TestDiskPreFailNVMeCLIFallback(t *testing.T) {
	f := kfixture(t)
	root := seedPrefailFixture(t, f.r)
	// Controller present, sysfs attribute missing (mainline) — the
	// engine must fall back to `nvme smart-log` through the exec
	// seam.
	if err := os.MkdirAll(filepath.Join(root, "sys", "class", "nvme", "nvme0"), 0o755); err != nil {
		t.Fatal(err)
	}
	f.r.deps.RunHostCmd = func(_ context.Context, argv ...string) (string, error) {
		if len(argv) >= 2 && argv[0] == "nvme" && argv[1] == "smart-log" {
			return "Smart Log for NVME device:nvme0\n" +
				"critical_warning                    : 0\n" +
				"percentage_used                     : 95%\n" +
				"media_errors                        : 0\n", nil
		}
		return "", os.ErrNotExist
	}
	f.r.updateDiskPreFailEvidence(context.Background())
	if !prefailLatchSet(f.r) {
		t.Fatal("state-disk-pre-fail not latched on percentage_used=95 (nvme-cli)")
	}
	logData, err := os.ReadFile(f.log)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(logData), "(nvme-cli)") {
		t.Fatalf("evidence must name the nvme-cli source:\n%s", logData)
	}
	prom := readPrefailProm(t, f.r)
	if !strings.Contains(prom, `node_agent_nvme_smart_percentage_used{ctrl="nvme0",src="nvme-cli"} 95`) {
		t.Fatalf("cli gauge missing:\n%s", prom)
	}
}

func TestParseSmartLogPageTruncated(t *testing.T) {
	if _, ok := parseSmartLogPage("nvme0", make([]byte, nvmeSmartLogMinLen-1)); ok {
		t.Fatal("truncated page parsed")
	}
	s, ok := parseSmartLogPage("nvme0", make([]byte, nvmeSmartLogMinLen))
	if !ok || s.criticalWarning != 0 || s.percentageUsed != 0 || s.mediaErrors != 0 {
		t.Fatalf("clean page parse = %+v ok=%v", s, ok)
	}
}

func TestParseSmartLogCLIPartial(t *testing.T) {
	if _, ok := parseSmartLogCLI("nvme0", "critical_warning : 0\n"); ok {
		t.Fatal("partial cli output parsed")
	}
	s, ok := parseSmartLogCLI("nvme0", ""+
		"critical_warning                    : 0x2\n"+
		"percentage_used                     : 91%\n"+
		"media_errors                        : 12\n")
	if !ok || s.criticalWarning != 2 || s.percentageUsed != 91 || s.mediaErrors != 12 || !s.viaCLI {
		t.Fatalf("cli parse = %+v ok=%v", s, ok)
	}
	if !s.ok() {
		t.Fatal("critical_warning=2 + 91% + media 12 must trip the verdict")
	}
}
