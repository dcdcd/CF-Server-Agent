//go:build !windows

package cfprobe

import (
	"os"
	"path/filepath"
	"testing"
)

func TestAcquireInstanceLockUsesProtectedPIDDirectory(t *testing.T) {
	dir := t.TempDir()
	paths := Paths{
		ServiceName: "cf-probe-test",
		PIDFile:     filepath.Join(dir, "cf-probe-test.pid"),
		ConfigFile:  filepath.Join(dir, "config.conf"),
	}

	release, err := acquireInstanceLock(paths)
	if err != nil {
		t.Fatalf("acquireInstanceLock returned error: %v", err)
	}
	defer release()

	lockPath := filepath.Join(dir, ".cf-probe-test.lock")
	info, err := os.Stat(lockPath)
	if err != nil {
		t.Fatalf("stat lock file: %v", err)
	}
	if got := info.Mode().Perm(); got != 0o600 {
		t.Fatalf("lock permissions = %o, want 600", got)
	}
	if _, err := acquireInstanceLock(paths); err == nil {
		t.Fatal("second acquireInstanceLock unexpectedly succeeded")
	}
}

func TestAcquireInstanceLockRejectsSymlink(t *testing.T) {
	dir := t.TempDir()
	paths := Paths{
		ServiceName: "cf-probe-test",
		PIDFile:     filepath.Join(dir, "cf-probe-test.pid"),
		ConfigFile:  filepath.Join(dir, "config.conf"),
	}
	target := filepath.Join(dir, "target")
	if err := os.WriteFile(target, []byte("keep"), 0o600); err != nil {
		t.Fatalf("write target: %v", err)
	}
	if err := os.Symlink(target, filepath.Join(dir, ".cf-probe-test.lock")); err != nil {
		t.Fatalf("create symlink: %v", err)
	}

	if _, err := acquireInstanceLock(paths); err == nil {
		t.Fatal("acquireInstanceLock accepted a symlink")
	}
	data, err := os.ReadFile(target)
	if err != nil {
		t.Fatalf("read target: %v", err)
	}
	if string(data) != "keep" {
		t.Fatalf("symlink target changed to %q", data)
	}
}
