package session

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

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

// The dedicated root:<uid>:1 line clears the UID only once coi's whole printed
// fix is in effect: present in /etc/subuid AND /etc/subgid, and Incus restarted
// since. Until then the UID stays flagged with what's still missing.
func TestHostUIDSubordinateRange_RequiresWholeFix(t *testing.T) {
	uid := os.Getuid()
	big := fmt.Sprintf("root:%d:1000000000", uid) // a root block covering uid
	if uid > 0 {
		big = fmt.Sprintf("root:%d:1000000000", uid-1)
	}
	dedicated := fmt.Sprintf("root:%d:1", uid)

	dir := t.TempDir()
	write := func(name, content string, mtime time.Time) string {
		p := filepath.Join(dir, name)
		if err := os.WriteFile(p, []byte(content), 0o644); err != nil {
			t.Fatal(err)
		}
		if err := os.Chtimes(p, mtime, mtime); err != nil {
			t.Fatal(err)
		}
		return p
	}
	origU, origG, origStart := subuidPath, subgidPath, incusdStartTime
	t.Cleanup(func() { subuidPath, subgidPath, incusdStartTime = origU, origG, origStart })

	edited := time.Now().Add(-time.Hour)
	restartedAfter := func() (time.Time, bool) { return edited.Add(time.Minute), true }
	restartedBefore := func() (time.Time, bool) { return edited.Add(-time.Minute), true }
	noIncusd := func() (time.Time, bool) { return time.Time{}, false }

	cases := []struct {
		name      string
		subuid    string
		subgid    string
		start     func() (time.Time, bool)
		wantFound bool
		wantHint  string
	}{
		{"no dedicated line", big + "\n", big + "\n", restartedAfter, true, ""},
		{"subuid only", big + "\n" + dedicated + "\n", big + "\n", restartedAfter, true, "missing from /etc/subgid"},
		{"both files, Incus not restarted", big + "\n" + dedicated + "\n", big + "\n" + dedicated + "\n", restartedBefore, true, "restart incus"},
		{"both files, Incus restarted", big + "\n" + dedicated + "\n", big + "\n" + dedicated + "\n", restartedAfter, false, ""},
		{"both files, incusd not visible", big + "\n" + dedicated + "\n", big + "\n" + dedicated + "\n", noIncusd, false, ""},
		{"not inside a root block", "root:1:1\n", "", restartedAfter, false, ""},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			subuidPath = write("subuid", tc.subuid, edited)
			subgidPath = write("subgid", tc.subgid, edited)
			incusdStartTime = tc.start
			line, found := HostUIDSubordinateRange()
			if found != tc.wantFound {
				t.Fatalf("found = %v, want %v (line %q)", found, tc.wantFound, line)
			}
			if tc.wantHint != "" && !strings.Contains(line, tc.wantHint) {
				t.Errorf("line %q should say %q", line, tc.wantHint)
			}
		})
	}
}

// findIncusdStartTime must locate a running incusd via /proc when there is one.
func TestFindIncusdStartTime(t *testing.T) {
	if out, err := exec.Command("pgrep", "-x", "incusd").Output(); err != nil || len(out) == 0 {
		t.Skip("no incusd running here")
	}
	started, ok := findIncusdStartTime()
	if !ok {
		t.Fatal("incusd is running but wasn't found in /proc")
	}
	if started.After(time.Now()) || started.Before(time.Now().Add(-365*24*time.Hour)) {
		t.Errorf("implausible incusd start time %v", started)
	}
}

// Container monitors and fork helpers also have comm "incusd" and outlive an
// Incus restart; the start time must come from the daemon itself.
func TestIncusdStartTimeIn_PicksDaemonNotMonitor(t *testing.T) {
	root := t.TempDir()
	write := func(rel, content string) {
		p := filepath.Join(root, rel)
		if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(p, []byte(content), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	stat := func(pid string, ticks int) string {
		// pid (comm) state + 18 filler fields, then starttime (field 22).
		return pid + " (incusd) S " + strings.Repeat("0 ", 18) + fmt.Sprint(ticks) + " 0 0\n"
	}
	write("stat", "cpu 1 2 3\nbtime 1000000\n")
	// Old monitor and forkproxy sort BEFORE the daemon's pid.
	write("100/cmdline", "[lxc monitor] /var/lib/incus/containers coi-x\x00")
	write("100/stat", stat("100", 100))
	write("150/cmdline", "incusd\x00forkproxy\x00--\x00x\x00")
	write("150/stat", stat("150", 150))
	write("300/cmdline", "/opt/incus/bin/incusd\x00--group\x00incus-admin\x00")
	write("300/stat", stat("300", 50000))
	write("400/cmdline", "bash\x00")
	write("400/stat", "400 (bash) S "+strings.Repeat("0 ", 18)+"1 0 0\n")

	got, ok := incusdStartTimeIn(root)
	if !ok {
		t.Fatal("daemon not found")
	}
	if want := time.Unix(1000000, 0).Add(500 * time.Second); !got.Equal(want) {
		t.Errorf("start = %v, want the daemon's %v (not a monitor's)", got, want)
	}

	// No daemon at all (only a monitor) → not found, rather than a wrong answer.
	root2 := t.TempDir()
	root = root2
	write("stat", "btime 1000000\n")
	write("100/cmdline", "[lxc monitor] /var/lib/incus/containers coi-x\x00")
	write("100/stat", stat("100", 100))
	if _, ok := incusdStartTimeIn(root2); ok {
		t.Error("a lone container monitor must not be taken for the daemon")
	}
}

// btime has 1s resolution: an edit made within a second after the computed
// start must not read as "Incus not restarted since".
func TestHostUIDSubordinateRange_RestartTolerance(t *testing.T) {
	uid := os.Getuid()
	big := fmt.Sprintf("root:%d:1000000000", uid)
	if uid > 0 {
		big = fmt.Sprintf("root:%d:1000000000", uid-1)
	}
	content := big + "\n" + fmt.Sprintf("root:%d:1", uid) + "\n"
	dir := t.TempDir()
	edited := time.Now().Add(-time.Hour)
	for _, name := range []string{"subuid", "subgid"} {
		p := filepath.Join(dir, name)
		if err := os.WriteFile(p, []byte(content), 0o644); err != nil {
			t.Fatal(err)
		}
		if err := os.Chtimes(p, edited, edited); err != nil {
			t.Fatal(err)
		}
	}
	origU, origG, origStart := subuidPath, subgidPath, incusdStartTime
	t.Cleanup(func() { subuidPath, subgidPath, incusdStartTime = origU, origG, origStart })
	subuidPath, subgidPath = filepath.Join(dir, "subuid"), filepath.Join(dir, "subgid")
	incusdStartTime = func() (time.Time, bool) { return edited.Add(-500 * time.Millisecond), true }
	if line, found := HostUIDSubordinateRange(); found {
		t.Errorf("edit within the 1s btime resolution should not flag a missing restart: %q", line)
	}
}
