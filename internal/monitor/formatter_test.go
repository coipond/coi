package monitor

import (
	"strings"
	"testing"
)

func TestWriteFilesystemReadsScope(t *testing.T) {
	tests := []struct {
		device string
		want   string
	}{
		{"252:1", "  Workspace Reads:     12.00 MB (6.00 MB/sec)\n"},
		{"", "  Container I/O Reads: 12.00 MB (6.00 MB/sec)\n"},
	}
	for _, tt := range tests {
		var sb strings.Builder
		writeFilesystem(&sb, MonitorSnapshot{Filesystem: FilesystemStats{
			Available:        true,
			WorkspaceDevice:  tt.device,
			TotalReadMB:      12,
			ReadRateMBPerSec: 6,
		}})
		if !strings.Contains(sb.String(), tt.want) {
			t.Errorf("device %q: output %q, want line %q", tt.device, sb.String(), tt.want)
		}
	}
}
