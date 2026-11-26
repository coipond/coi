package container

import (
	"strings"
	"testing"
)

// A refused device carries Incus's message, not only the exit status.
func TestMountDisk_ErrorCarriesIncusMessage(t *testing.T) {
	fakeIncusScript(t, `echo "Error: The device already exists" >&2; exit 1`)
	err := (&Manager{ContainerName: "c1"}).MountDisk("protect-vscode", "/ws/.vscode", "/workspace/.vscode", false, true)
	if err == nil || !strings.Contains(err.Error(), "The device already exists") {
		t.Fatalf("want an error with the Incus message, got %v", err)
	}
}
