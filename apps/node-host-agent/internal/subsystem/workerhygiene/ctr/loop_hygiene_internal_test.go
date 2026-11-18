// loop_hygiene_internal_test.go — package-internal coverage for the
// loop partition glob: on Linux partitions live INSIDE the parent's
// sysfs dir, and only loop<digits> names may enter the pattern.
package ctr

import (
	"os"
	"path/filepath"
	"testing"
)

func TestHasLoopPartitionsParentDirOnly(t *testing.T) {
	root := t.TempDir()
	devDir := filepath.Join(root, "loop0")
	if err := os.MkdirAll(devDir, 0o755); err != nil {
		t.Fatal(err)
	}

	// Clean loop: no partition node anywhere.
	if hasLoopPartitions(devDir, "loop0") {
		t.Fatal("clean loop reported as partitioned")
	}

	// The correct Linux location: /sys/block/loop0/loop0p1.
	if err := os.WriteFile(filepath.Join(devDir, "loop0p1"), nil, 0o644); err != nil {
		t.Fatal(err)
	}
	if !hasLoopPartitions(devDir, "loop0") {
		t.Fatal("partition inside the parent dir was not detected")
	}

	// The old WRONG location: /sys/block/loop2p1 beside a loop2 dir.
	dev2 := filepath.Join(root, "loop2")
	if err := os.MkdirAll(dev2, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, "loop2p1"), nil, 0o644); err != nil {
		t.Fatal(err)
	}
	if hasLoopPartitions(dev2, "loop2") {
		t.Fatal("sibling loop2p1 must not shield loop2")
	}

	// Non-loop<digits> names never enter the glob.
	if err := os.WriteFile(filepath.Join(root, "loop-control1"), nil, 0o644); err != nil {
		t.Fatal(err)
	}
	if hasLoopPartitions(root, "loop-control") {
		t.Fatal("loop-control is not a loop device")
	}
	if !isLoopDevName("loop12") || isLoopDevName("loop") ||
		isLoopDevName("loop0p1") || isLoopDevName("../loop0") {
		t.Fatal("isLoopDevName must accept only loop<digits>")
	}
}
