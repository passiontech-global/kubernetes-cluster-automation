package procfs

import (
	"os"
	"path/filepath"
	"testing"
)

func TestReadConntrackStat(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "nf_conntrack")
	content := "entries  searched found new invalid ignore delete delete_list insert insert_failed drop early_drop icmp_error  expect_new expect_create expect_delete search_restart\n" +
		"00000010 00000000 00000000 00000000 00000002 00000000 00000000 00000000 00000000 00000003 00000004 00000001 00000000 00000000 00000000 00000000 00000005\n" +
		"00000010 00000000 00000000 00000000 00000001 00000000 00000000 00000000 00000000 00000001 00000002 00000000 00000000 00000000 00000000 00000000 00000001\n"
	if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}
	st, ok := ReadConntrackStat(path)
	if !ok {
		t.Fatal("ReadConntrackStat returned ok=false")
	}
	if st.InsertFailed != 4 || st.Drop != 6 || st.EarlyDrop != 1 || st.SearchRestart != 6 || st.Invalid != 3 {
		t.Fatalf("unexpected ConntrackStat: %+v", st)
	}
	if _, ok := ReadConntrackStat(filepath.Join(dir, "missing")); ok {
		t.Fatal("missing file returned ok=true")
	}
	badPath := filepath.Join(dir, "short")
	_ = os.WriteFile(badPath, []byte("header_only\n"), 0o644)
	if _, ok := ReadConntrackStat(badPath); ok {
		t.Fatal("single-line file returned ok=true")
	}
}

func TestUnescapeMountPath(t *testing.T) {
	in := `/var/lib/kubelet/pods/my\040pod/vol\011a\012b\134c`
	want := "/var/lib/kubelet/pods/my pod/vol\ta\nb\\c"
	if got := UnescapeMountPath(in); got != want {
		t.Fatalf("UnescapeMountPath = %q, want %q", got, want)
	}
}

func TestSysinfoHelpers(t *testing.T) {
	dir := t.TempDir()

	// RuntimeConfigMTU + JSONFindInts
	cfgPath := filepath.Join(dir, "agent-runtime-config.json")
	if err := os.WriteFile(cfgPath, []byte(`{"mtu": 1400, "nested": [{"MTU": 1450}]}`), 0o644); err != nil {
		t.Fatal(err)
	}
	if mtu, ok := RuntimeConfigMTU(cfgPath); !ok || mtu != 1450 {
		t.Fatalf("RuntimeConfigMTU = (%d,%v), want (1450,true)", mtu, ok)
	}
	if _, ok := RuntimeConfigMTU(filepath.Join(dir, "missing.json")); ok {
		t.Fatal("missing json returned ok=true")
	}

	// MTUOfIface + MaxPodLxcMTU (skips lxc_health)
	sysnet := filepath.Join(dir, "net")
	for iface, mtu := range map[string]string{
		"lxc_health": "9000\n",
		"lxc0a1b":    "1420\n",
		"lxcdead":    "1450\n",
		"eth0":       "1500\n",
	} {
		p := filepath.Join(sysnet, iface)
		if err := os.MkdirAll(p, 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(p, "mtu"), []byte(mtu), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	if mtu, ok := MTUOfIface(sysnet, "eth0"); !ok || mtu != 1500 {
		t.Fatalf("MTUOfIface(eth0) = (%d,%v), want (1500,true)", mtu, ok)
	}
	if mtu, ok := MaxPodLxcMTU(sysnet); !ok || mtu != 1450 {
		t.Fatalf("MaxPodLxcMTU = (%d,%v), want (1450,true)", mtu, ok)
	}

	// ParsePSIFull
	psiPath := filepath.Join(dir, "cpu.pressure")
	if err := os.WriteFile(psiPath, []byte("some avg10=1.00 avg60=2.00 avg300=3.00 total=10\nfull avg10=0.50 avg60=12.34 avg300=5.67 total=20\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	a60, a300, ok := ParsePSIFull(psiPath)
	if !ok || a60 != 12.34 || a300 != 5.67 {
		t.Fatalf("ParsePSIFull = (%v,%v,%v), want (12.34,5.67,true)", a60, a300, ok)
	}
	if _, _, ok := ParsePSIFull(filepath.Join(dir, "missing.psi")); ok {
		t.Fatal("missing psi returned ok=true")
	}
}
