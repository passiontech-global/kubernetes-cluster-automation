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
	plain := "/var/lib/kubelet/pods/abc/volumes/kubernetes.io~csi/pvc-123/mount"
	if got := UnescapeMountPath(plain); got != plain {
		t.Fatalf("UnescapeMountPath(plain) = %q, want %q", got, plain)
	}
	if got := UnescapeMountPath(""); got != "" {
		t.Fatalf("UnescapeMountPath(\"\") = %q, want empty", got)
	}
	if got := UnescapeMountPath(`/var/lib/foo\041bar`); got != `/var/lib/foo\041bar` {
		t.Fatalf("UnescapeMountPath(unknown escape) = %q", got)
	}
	if allocs := testing.AllocsPerRun(100, func() {
		if UnescapeMountPath(plain) != plain {
			t.Fatal("mismatch")
		}
	}); allocs != 0 {
		t.Fatalf("plain path allocs = %v, want 0", allocs)
	}
}

var sinkMountPath string

func BenchmarkUnescapeMountPath(b *testing.B) {
	b.Run("Plain", func(b *testing.B) {
		b.ReportAllocs()
		p := "/var/lib/kubelet/pods/11111111-2222-3333-4444-555555555555/volumes/kubernetes.io~csi/pvc-abcdef/mount"
		for b.Loop() {
			sinkMountPath = UnescapeMountPath(p)
		}
	})
	b.Run("Escaped", func(b *testing.B) {
		b.ReportAllocs()
		p := `/var/lib/kubelet/pods/my\040pod/vol\011a\012b\134c`
		for b.Loop() {
			sinkMountPath = UnescapeMountPath(p)
		}
	})
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

func TestParsePSIMemory(t *testing.T) {
	cases := []struct {
		name         string
		body         string
		missing      bool
		want         PSIMemoryStats
		wantOK       bool
		wantFullOK   bool
		wantFullA60  float64
		wantFullA300 float64
	}{
		{
			name: "some_and_full_all_fields",
			body: "some avg10=12.50 avg60=26.25 avg300=18.75 total=100\n" +
				"full avg10=4.10 avg60=9.20 avg300=3.30 total=200\n",
			want: PSIMemoryStats{
				SomeAvg10: 12.50, SomeAvg60: 26.25, SomeAvg300: 18.75,
				FullAvg10: 4.10, FullAvg60: 9.20, FullAvg300: 3.30,
				HasSome: true, HasFull: true,
			},
			wantOK:       true,
			wantFullOK:   true,
			wantFullA60:  9.20,
			wantFullA300: 3.30,
		},
		{
			name: "four_field_omitting_avg300",
			body: "some avg10=60.00 avg60=55.00 total=100\n" +
				"full avg10=45.00 avg60=42.50 total=100\n",
			want: PSIMemoryStats{
				SomeAvg10: 60.00, SomeAvg60: 55.00,
				FullAvg10: 45.00, FullAvg60: 42.50,
				HasSome: true, HasFull: true,
			},
			wantOK:      true,
			wantFullOK:  true,
			wantFullA60: 42.50,
		},
		{
			name: "some_only",
			body: "some avg10=45.00 avg60=30.00 avg300=15.00 total=10\n",
			want: PSIMemoryStats{
				SomeAvg10: 45.00, SomeAvg60: 30.00, SomeAvg300: 15.00,
				HasSome: true,
			},
			wantOK:     true,
			wantFullOK: false,
		},
		{
			name: "full_only",
			body: "full avg10=10.00 avg60=22.00 avg300=11.00 total=10\n",
			want: PSIMemoryStats{
				FullAvg10: 10.00, FullAvg60: 22.00, FullAvg300: 11.00,
				HasFull: true,
			},
			wantOK:       true,
			wantFullOK:   true,
			wantFullA60:  22.00,
			wantFullA300: 11.00,
		},
		{
			name: "some_valid_full_bogus_avg60",
			body: "some avg10=5.00 avg60=12.00 avg300=8.00 total=1\n" +
				"full avg10=1.00 avg60=bogus avg300=3.00 total=2\n",
			want: PSIMemoryStats{
				SomeAvg10: 5.00, SomeAvg60: 12.00, SomeAvg300: 8.00,
				FullAvg10: 1.00, FullAvg300: 3.00,
				HasSome: true, HasFull: false,
			},
			wantOK:     true,
			wantFullOK: false,
		},
		{
			name:   "corrupt_body",
			body:   "corrupt\nother avg10=1.00 avg60=2.00\n",
			wantOK: false,
		},
		{
			name:   "empty_file",
			body:   "",
			wantOK: false,
		},
		{
			name:    "missing_file",
			missing: true,
			wantOK:  false,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "memory.pressure")
			if !tc.missing {
				if err := os.WriteFile(path, []byte(tc.body), 0o644); err != nil {
					t.Fatal(err)
				}
			}
			got, ok := ParsePSIMemory(path)
			if ok != tc.wantOK || got != tc.want {
				t.Fatalf("ParsePSIMemory = (%+v, %v), want (%+v, %v)", got, ok, tc.want, tc.wantOK)
			}
			a60, a300, fullOK := ParsePSIFull(path)
			if fullOK != tc.wantFullOK || (fullOK && (a60 != tc.wantFullA60 || a300 != tc.wantFullA300)) {
				t.Fatalf("ParsePSIFull = (%v, %v, %v), want (%v, %v, %v)",
					a60, a300, fullOK, tc.wantFullA60, tc.wantFullA300, tc.wantFullOK)
			}
		})
	}
}
