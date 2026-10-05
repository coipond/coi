package health

import (
	"strings"
	"syscall"
	"testing"
)

func TestCheckSensitiveFileMonitoring(t *testing.T) {
	orig := fanotifyAvailable
	t.Cleanup(func() { fanotifyAvailable = orig })

	fanotifyAvailable = func() error { return syscall.EPERM }
	got := CheckSensitiveFileMonitoring()
	if got.Status != StatusWarning || !strings.Contains(got.Message, "not detected") {
		t.Errorf("without fanotify: got %s %q, want a warning that says what isn't detected", got.Status, got.Message)
	}

	fanotifyAvailable = func() error { return nil }
	if got := CheckSensitiveFileMonitoring(); got.Status != StatusOK {
		t.Errorf("with fanotify: got %s %q, want ok", got.Status, got.Message)
	}
}
