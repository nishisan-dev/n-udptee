//go:build linux

package integration

import (
	"bytes"
	"os"
	"os/exec"
	"path/filepath"
	"syscall"
	"testing"
)

func TestNamespaces(t *testing.T) {
	if os.Getenv("N_UDPTEE_INTEGRATION") != "1" {
		t.Skip("namespace integration not requested; run make integration (requires user/network/mount namespaces, CAP_NET_ADMIN and CAP_NET_RAW inside lab)")
	}
	root, e := filepath.Abs("../..")
	if e != nil {
		t.Fatal(e)
	}
	binary := filepath.Join(t.TempDir(), "n-udptee")
	build := exec.Command("go", "build", "-o", binary, "./cmd/n-udptee")
	build.Dir = root
	if b, e := build.CombinedOutput(); e != nil {
		t.Fatalf("build: %v\n%s", e, b)
	}
	out := os.Getenv("N_UDPTEE_LAB_OUTPUT")
	if out == "" {
		out = t.TempDir()
	}
	cmd := exec.Command(filepath.Join(root, "tests/integration/run.sh"), "--binary", binary, "--output", out)
	cmd.Dir = root
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	var output bytes.Buffer
	cmd.Stdout = &output
	cmd.Stderr = &output
	if e := cmd.Start(); e != nil {
		t.Fatal(e)
	}
	defer syscall.Kill(-cmd.Process.Pid, syscall.SIGKILL)
	e = cmd.Wait()
	b := output.Bytes()
	t.Log(string(b))
	if e != nil {
		t.Fatalf("enabled integration failed (no silent privilege skip): %v", e)
	}
}
