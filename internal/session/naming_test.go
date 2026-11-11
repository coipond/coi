package session

import (
	"crypto/sha256"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
)

func TestWorkspaceHash(t *testing.T) {
	tests := []struct {
		name          string
		workspacePath string
		wantLength    int
	}{
		{
			name:          "simple path",
			workspacePath: "/home/user/project",
			wantLength:    8,
		},
		{
			name:          "complex path",
			workspacePath: "/home/user/my-workspace/project-1",
			wantLength:    8,
		},
		{
			name:          "empty path",
			workspacePath: "",
			wantLength:    8,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			hash := WorkspaceHash(tt.workspacePath)

			if len(hash) != tt.wantLength {
				t.Errorf("WorkspaceHash() returned length %d, want %d", len(hash), tt.wantLength)
			}

			// Verify it's hex
			for _, c := range hash {
				if (c < '0' || c > '9') && (c < 'a' || c > 'f') {
					t.Errorf("WorkspaceHash() contains non-hex character: %c", c)
				}
			}
		})
	}

	// Test deterministic hashing
	path := "/test/path"
	hash1 := WorkspaceHash(path)
	hash2 := WorkspaceHash(path)

	if hash1 != hash2 {
		t.Errorf("WorkspaceHash() not deterministic: %s != %s", hash1, hash2)
	}

	// Test different paths produce different hashes
	hash3 := WorkspaceHash("/different/path")
	if hash1 == hash3 {
		t.Error("WorkspaceHash() produced same hash for different paths")
	}
}

func TestWorkspaceHashFormat(t *testing.T) {
	// Test that the hash matches the expected SHA256 format
	path := "/test/workspace"
	hash := WorkspaceHash(path)

	// Calculate expected hash
	h := sha256.New()
	h.Write([]byte(path))
	expected := fmt.Sprintf("%x", h.Sum(nil))[:8]

	if hash != expected {
		t.Errorf("WorkspaceHash() = %s, want %s", hash, expected)
	}
}

func TestContainerName(t *testing.T) {
	tests := []struct {
		name          string
		workspacePath string
		slot          int
		wantPrefix    string
	}{
		{
			name:          "slot 1",
			workspacePath: "/home/user/project",
			slot:          1,
			wantPrefix:    "coi-",
		},
		{
			name:          "slot 5",
			workspacePath: "/home/user/project",
			slot:          5,
			wantPrefix:    "coi-",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			name := ContainerName(tt.workspacePath, "", tt.slot)

			// Check prefix
			if len(name) < len(tt.wantPrefix) || name[:len(tt.wantPrefix)] != tt.wantPrefix {
				t.Errorf("ContainerName() = %s, want prefix %s", name, tt.wantPrefix)
			}

			// Check format: coi-<hash>-<slot>
			expectedHash := WorkspaceHash(tt.workspacePath)
			expectedName := fmt.Sprintf("coi-%s-%d", expectedHash, tt.slot)

			if name != expectedName {
				t.Errorf("ContainerName() = %s, want %s", name, expectedName)
			}
		})
	}

	// Test deterministic naming
	path := "/test/path"
	slot := 1
	name1 := ContainerName(path, "", slot)
	name2 := ContainerName(path, "", slot)

	if name1 != name2 {
		t.Errorf("ContainerName() not deterministic: %s != %s", name1, name2)
	}
}

func TestContainerNameDifferentSlots(t *testing.T) {
	path := "/test/workspace"
	name1 := ContainerName(path, "", 1)
	name2 := ContainerName(path, "", 2)

	if name1 == name2 {
		t.Error("ContainerName() produced same name for different slots")
	}

	// Check that only the slot number differs
	hash := WorkspaceHash(path)
	expected1 := fmt.Sprintf("coi-%s-1", hash)
	expected2 := fmt.Sprintf("coi-%s-2", hash)

	if name1 != expected1 {
		t.Errorf("ContainerName(slot 1) = %s, want %s", name1, expected1)
	}

	if name2 != expected2 {
		t.Errorf("ContainerName(slot 2) = %s, want %s", name2, expected2)
	}
}

func TestParseContainerName(t *testing.T) {
	tests := []struct {
		name          string
		containerName string
		wantHash      string
		wantSlot      int
		wantErr       bool
	}{
		{
			name:          "valid container name",
			containerName: "coi-abc12345-1",
			wantHash:      "abc12345",
			wantSlot:      1,
			wantErr:       false,
		},
		{
			name:          "valid container name slot 10",
			containerName: "coi-abc12345-10",
			wantHash:      "abc12345",
			wantSlot:      10,
			wantErr:       false,
		},
		{
			name:          "invalid format - no prefix",
			containerName: "container-abc12345-1",
			wantErr:       true,
		},
		{
			name:          "invalid format - short hash",
			containerName: "claude-abc123-1",
			wantErr:       true,
		},
		{
			name:          "invalid format - no slot",
			containerName: "claude-abc12345",
			wantErr:       true,
		},
		{
			name:          "invalid format - non-numeric slot",
			containerName: "claude-abc12345-abc",
			wantErr:       true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			hash, slot, err := ParseContainerName(tt.containerName)

			if tt.wantErr {
				if err == nil {
					t.Errorf("ParseContainerName() expected error, got nil")
				}
				return
			}

			if err != nil {
				t.Errorf("ParseContainerName() unexpected error: %v", err)
				return
			}

			if hash != tt.wantHash {
				t.Errorf("ParseContainerName() hash = %s, want %s", hash, tt.wantHash)
			}

			if slot != tt.wantSlot {
				t.Errorf("ParseContainerName() slot = %d, want %d", slot, tt.wantSlot)
			}
		})
	}
}

// TestAllocateSlot is an integration test that would need container mocking
// Skipping for now as it requires Incus interaction
func TestAllocateSlotLogic(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping integration test in short mode")
	}
	// This would test AllocateSlot but requires mocking Incus commands
	// TODO: Add integration test
}

func TestAllocateSlotFrom(t *testing.T) {
	const workspace = "/workspace/project"

	tests := []struct {
		name    string
		used    []int
		start   int
		want    int
		wantErr string
	}{
		{name: "free slot above start", used: []int{8}, start: 9, want: 9},
		{name: "skips used slots above start", used: []int{8, 9}, start: 9, want: 10},
		{name: "start above max wraps to lowest free", used: []int{10}, start: 11, want: 1},
		{name: "slot above max wraps to lowest free", used: []int{1, 12}, start: 13, want: 2},
		{name: "start to max used wraps to lowest free", used: []int{8, 9, 10}, start: 9, want: 1},
		{name: "wraps to slot 10 when it is the only free slot", used: []int{1, 2, 3, 4, 5, 6, 7, 8, 9, 12}, start: 13, want: 10},
		{name: "all slots used", used: []int{1, 2, 3, 4, 5, 6, 7, 8, 9, 10}, start: 9, wantErr: "all 10 slots are in use"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			orig := listSlotInstances
			t.Cleanup(func() { listSlotInstances = orig })
			listSlotInstances = func() ([]slotInstance, error) {
				out := []slotInstance{{Name: ContainerName("/other", "", 1), Status: "RUNNING"}}
				for _, n := range tt.used {
					out = append(out, slotInstance{Name: ContainerName(workspace, "", n), Status: "RUNNING"})
				}
				return out, nil
			}

			got, err := AllocateSlotFrom(workspace, "", tt.start, MaxSlots)
			if tt.wantErr != "" {
				if err == nil || err.Error() != tt.wantErr {
					t.Fatalf("AllocateSlotFrom() = %d, %v; want error %q", got, err, tt.wantErr)
				}
				return
			}
			if err != nil {
				t.Fatalf("AllocateSlotFrom() error = %v", err)
			}
			if got != tt.want {
				t.Errorf("AllocateSlotFrom() = %d, want %d", got, tt.want)
			}
		})
	}
}

// ListWorkspaceSessions asks Incus for the names of this identity's
// containers only and maps their slots.
func TestListWorkspaceSessions(t *testing.T) {
	t.Setenv("COI_CONTAINER_PREFIX", "")
	hash := IdentityHash("/home/u/proj", "")
	prefix := "coi-" + hash + "-"
	dir := t.TempDir()
	logPath := filepath.Join(dir, "calls")
	script := "#!/bin/sh\necho \"$*\" >> " + logPath + "\nprintf '" +
		prefix + "1\\n" + prefix + "10\\n" + prefix + "x\\n" + prefix + "2-backup\\n'\n"
	if err := os.WriteFile(filepath.Join(dir, "incus"), []byte(script), 0o755); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PATH", dir+string(os.PathListSeparator)+os.Getenv("PATH"))

	got, err := ListWorkspaceSessions("/home/u/proj", "")
	if err != nil {
		t.Fatal(err)
	}
	if want := map[int]string{1: prefix + "1", 10: prefix + "10"}; !reflect.DeepEqual(got, want) {
		t.Errorf("sessions = %v, want %v", got, want)
	}
	b, _ := os.ReadFile(logPath)
	if call := strings.TrimSpace(string(b)); call != "--project default list ^"+prefix+" --format=csv --columns=n" {
		t.Errorf("incus call = %q", call)
	}
}
