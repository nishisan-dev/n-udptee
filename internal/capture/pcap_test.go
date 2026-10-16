package capture

import (
	"github.com/nishisan-dev/n-udptee/internal/config"
	"strings"
	"testing"
)

func TestInterfaceValidationWithoutPrivileges(t *testing.T) {
	if _, e := Open(config.Capture{Interface: "nut-missing-if"}); e == nil {
		t.Fatal("missing interface accepted")
	}
	if _, e := Open(config.Capture{Interface: "lo"}); e == nil || !strings.Contains(e.Error(), "loopback") {
		t.Fatalf("loopback must fail before activation: %v", e)
	}
}
