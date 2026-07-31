package binary

import (
	"os"
	"path/filepath"
	"testing"
)

func TestDiscoverSkipsNonExecutablePPPNameWithoutChmod(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "ppp")
	if err := os.WriteFile(path, []byte("not executable"), 0o666); err != nil {
		t.Fatalf("write ppp: %v", err)
	}
	if err := os.Chmod(path, 0o666); err != nil {
		t.Fatalf("chmod ppp: %v", err)
	}

	items, err := NewManager(t.TempDir()).Discover(dir)
	if err != nil {
		t.Fatalf("Discover() error = %v", err)
	}
	if len(items) != 0 {
		t.Fatalf("Discover() returned %d items, want 0", len(items))
	}

	info, err := os.Stat(path)
	if err != nil {
		t.Fatalf("stat ppp: %v", err)
	}
	if got := info.Mode().Perm(); got != 0o666 {
		t.Fatalf("ppp mode = %o, want 666", got)
	}
}

func TestDiscoverIncludesExecutablePPPName(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "ppp")
	content := []byte("#!/bin/sh\n")
	if err := os.WriteFile(path, content, 0o755); err != nil {
		t.Fatalf("write ppp: %v", err)
	}

	items, err := NewManager(t.TempDir()).Discover(dir)
	if err != nil {
		t.Fatalf("Discover() error = %v", err)
	}
	if len(items) != 1 {
		t.Fatalf("Discover() returned %d items, want 1", len(items))
	}
	if items[0].Path != filepath.Clean(path) {
		t.Fatalf("Discover()[0].Path = %q, want %q", items[0].Path, filepath.Clean(path))
	}
	if items[0].Size != int64(len(content)) {
		t.Fatalf("Discover()[0].Size = %d, want %d", items[0].Size, len(content))
	}
}

func TestIsPPPBinaryName(t *testing.T) {
	tests := []struct {
		name string
		want bool
	}{
		{name: "ppp", want: true},
		{name: "PPP", want: true},
		{name: "ppp.exe", want: true},
		{name: "PPP.EXE", want: true},
		{name: "ppp-ci", want: true},
		{name: "ppp-debug", want: true},
		{name: "ppp-ci.exe", want: true},
		{name: "ppp-backdoor.sh", want: false},
		{name: "ppp-ci.bin", want: false},
		{name: "ppp.txt", want: false},
		{name: "not-ppp", want: false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := isPPPBinaryName(tt.name); got != tt.want {
				t.Fatalf("isPPPBinaryName(%q) = %v, want %v", tt.name, got, tt.want)
			}
		})
	}
}
