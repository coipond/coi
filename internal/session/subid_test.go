package session

import "testing"

func TestSubuidRangeContaining(t *testing.T) {
	// The real-world content from the bug report plus a dedicated size-1 line.
	const content = "root:1000000:1000000000\nubuntu:100000:65536\nlima:501:1\n"

	tests := []struct {
		name      string
		uid       int
		content   string
		wantFound bool
		wantLine  string
	}{
		{
			name:      "UID inside root's multi-ID delegation block (the #838 bug)",
			uid:       411531718,
			content:   content,
			wantFound: true,
			wantLine:  "root:1000000:1000000000",
		},
		{
			name:      "UID covered only by a dedicated size-1 delegation is NOT flagged",
			uid:       501,
			content:   "lima:501:1\n",
			wantFound: false, // count==1 is the working Lima/CI case, not the bug
		},
		{
			name:      "UID inside a smaller multi-ID range still flagged",
			uid:       110000,
			content:   content,
			wantFound: true,
			wantLine:  "ubuntu:100000:65536",
		},
		{
			name:      "UID outside every range",
			uid:       1000,
			content:   content,
			wantFound: false,
		},
		{
			name:      "boundary: start+count is exclusive",
			uid:       165536, // ubuntu:100000:65536 covers 100000..165535
			content:   "ubuntu:100000:65536\n",
			wantFound: false,
		},
		{
			name:      "malformed and empty lines are ignored",
			uid:       411531718,
			content:   "\ngarbage\nroot:notanumber:5\nroot:1000000:1000000000\n",
			wantFound: true,
			wantLine:  "root:1000000:1000000000",
		},
		{
			name:      "empty content",
			uid:       411531718,
			content:   "",
			wantFound: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			line, found := subuidRangeContaining(tt.uid, tt.content)
			if found != tt.wantFound {
				t.Fatalf("found = %v, want %v (line %q)", found, tt.wantFound, line)
			}
			if found && line != tt.wantLine {
				t.Errorf("line = %q, want %q", line, tt.wantLine)
			}
		})
	}
}
