//go:build darwin && !windows

package cfprobe

import "testing"

func TestSudoUserHomeDirPrefersSudoUser(t *testing.T) {
	t.Setenv("SUDO_USER", "alice")
	t.Setenv("HOME", "/var/root")

	if got := sudoUserHomeDir(); got != "/Users/alice" {
		t.Fatalf("sudoUserHomeDir = %q, want /Users/alice", got)
	}
}

func TestSystemDefaultPathsDarwinLeavesLaunchdUserFileEmpty(t *testing.T) {
	paths := systemDefaultPaths()
	if paths.LaunchdUserFile != "" {
		t.Fatalf("LaunchdUserFile = %q, want empty for macOS system paths", paths.LaunchdUserFile)
	}
	if paths.LaunchdRootFile == "" {
		t.Fatal("LaunchdRootFile should be set for macOS system paths")
	}
}
