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
			content:   "root:501:1\n",
			wantFound: false, // count==1 is the working Lima/CI case, not the bug
		},
		{
			name:      "UID inside a smaller root multi-ID range still flagged",
			uid:       110000,
			content:   "root:100000:65536\n",
			wantFound: true,
			wantLine:  "root:100000:65536",
		},
		{
			name:      "numeric root owner counts as root",
			uid:       110000,
			content:   "0:100000:65536\n",
			wantFound: true,
			wantLine:  "0:100000:65536",
		},
		{
			// incusd allocates idmaps from root's delegations only; another
			// user's range covering the UID doesn't block raw.idmap.
			name:      "non-root user's range is NOT flagged",
			uid:       110000,
			content:   content,
			wantFound: false,
		},
		{
			// The fix coi prints is `echo "root:$(id -u):1" | sudo tee -a
			// /etc/subuid ...`, which APPENDS the dedicated line after the big
			// block. Health must then stop reporting the UID as unmappable.
			name:      "dedicated root:<uid>:1 after the big block clears the UID",
			uid:       411531718,
			content:   content + "root:411531718:1\n",
			wantFound: false,
		},
		{
			name:      "dedicated line before the big block also clears the UID",
			uid:       411531718,
			content:   "root:411531718:1\n" + content,
			wantFound: false,
		},
		{
			name:      "another user's size-1 line does not clear root's block",
			uid:       411531718,
			content:   content + "alice:411531718:1\n",
			wantFound: true,
			wantLine:  "root:1000000:1000000000",
		},
		{
			name:      "UID outside every range",
			uid:       1000,
			content:   content,
			wantFound: false,
		},
		{
			name:      "boundary: start+count is exclusive",
			uid:       165536, // root:100000:65536 covers 100000..165535
			content:   "root:100000:65536\n",
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
