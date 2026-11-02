package main

import "testing"

func TestGetenv(t *testing.T) {
	const key = "NAC_TEST_GETENV"

	t.Run("unset returns default", func(t *testing.T) {
		t.Setenv(key, "")
		if got := getenv(key, "def"); got != "def" {
			t.Fatalf("getenv=%q, want %q", got, "def")
		}
	})

	t.Run("set returns value", func(t *testing.T) {
		t.Setenv(key, "/custom/labels.txt")
		if got := getenv(key, "def"); got != "/custom/labels.txt" {
			t.Fatalf("getenv=%q, want %q", got, "/custom/labels.txt")
		}
	})
}
