package vmhost

import (
	"os"
	"path/filepath"
	"reflect"
	"testing"
)

func TestMacHostMounts(t *testing.T) {
	tests := []struct {
		name   string
		mounts string
		want   []string
	}{
		{
			name: "colima virtiofs mac home",
			// Realistic Lima/Colima table: the Mac home is a virtiofs mount under
			// /Users; guest-local filesystems and /tmp/lima must be ignored.
			mounts: "" +
				"proc /proc proc rw,relatime 0 0\n" +
				"/dev/vda1 / ext4 rw,relatime 0 0\n" +
				"mount0 /Users/alice virtiofs rw,relatime 0 0\n" +
				"mount1 /tmp/lima virtiofs rw,relatime 0 0\n",
			want: []string{"/Users/alice"},
		},
		{
			name:   "lima 9p mount type",
			mounts: "share /Users/bob 9p rw,trans=virtio 0 0\n",
			want:   []string{"/Users/bob"},
		},
		{
			name: "whole /Users parent shared",
			mounts: "mount0 /Users virtiofs rw,relatime 0 0\n" +
				"/dev/vda1 / ext4 rw 0 0\n",
			want: []string{"/Users"},
		},
		{
			name: "sorted and deduplicated",
			mounts: "m2 /Users/carol virtiofs rw 0 0\n" +
				"m1 /Users/alice virtiofs rw 0 0\n" +
				"m1b /Users/alice virtiofs rw 0 0\n",
			want: []string{"/Users/alice", "/Users/carol"},
		},
		{
			name: "no mac shares (plain linux)",
			mounts: "proc /proc proc rw 0 0\n" +
				"/dev/sda1 / ext4 rw 0 0\n" +
				"tmpfs /run tmpfs rw 0 0\n",
			want: nil,
		},
		{
			name:   "non-virtiofs under /Users ignored",
			mounts: "tmpfs /Users/eve/scratch tmpfs rw 0 0\n",
			want:   nil,
		},
		{
			name:   "malformed lines skipped",
			mounts: "garbage\nmount0 /Users/frank virtiofs\n \n",
			want:   []string{"/Users/frank"},
		},
		{
			name:   "octal-escaped space in mountpoint decoded",
			mounts: `mount0 /Users/John\040Doe virtiofs rw 0 0` + "\n",
			want:   []string{"/Users/John Doe"},
		},
		{
			name: "escaped tab and backslash decoded",
			mounts: `m0 /Users/a\011b virtiofs rw 0 0` + "\n" +
				`m1 /Users/c\134d virtiofs rw 0 0` + "\n",
			want: []string{"/Users/a\tb", `/Users/c\d`},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := macHostMounts(tt.mounts)
			if !reflect.DeepEqual(got, tt.want) {
				t.Fatalf("macHostMounts()\n got  %#v\n want %#v", got, tt.want)
			}
		})
	}
}

func TestBuildMacHostConfigCandidates(t *testing.T) {
	// listSubdirs stub keyed by directory.
	subdirsOf := func(m map[string][]string) func(string) []string {
		return func(p string) []string { return m[p] }
	}

	tests := []struct {
		name       string
		mounts     string
		configDir  string
		listSubdir func(string) []string
		want       []string
	}{
		{
			name:       "home mount does NOT descend (no whole-home read, no nested strays)",
			mounts:     "m0 /Users/alice virtiofs rw 0 0\n",
			configDir:  ".claude",
			listSubdir: subdirsOf(map[string][]string{"/Users/alice": {"Documents", "Projects"}}),
			want:       []string{"/Users/alice/.claude"},
		},
		{
			name:       "whole /Users parent descends one level",
			mounts:     "m0 /Users virtiofs rw 0 0\n",
			configDir:  ".claude",
			listSubdir: subdirsOf(map[string][]string{"/Users": {"alice", "bob"}}),
			want:       []string{"/Users/alice/.claude", "/Users/bob/.claude"},
		},
		{
			name:       "parent case produces no bogus /Users/.claude candidate",
			mounts:     "m0 /Users virtiofs rw 0 0\n",
			configDir:  ".claude",
			listSubdir: subdirsOf(map[string][]string{"/Users": {"alice"}}),
			want:       []string{"/Users/alice/.claude"},
		},
		{
			name:       "deduplicated across mounts",
			mounts:     "m0 /Users/alice virtiofs rw 0 0\nm1 /Users/alice 9p rw 0 0\n",
			configDir:  ".codex",
			listSubdir: subdirsOf(nil),
			want:       []string{"/Users/alice/.codex"},
		},
		{
			name:       "no mac mounts yields no candidates",
			mounts:     "/dev/sda1 / ext4 rw 0 0\n",
			configDir:  ".claude",
			listSubdir: subdirsOf(nil),
			want:       nil,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := buildMacHostConfigCandidates(tt.mounts, tt.configDir, tt.listSubdir)
			if !reflect.DeepEqual(got, tt.want) {
				t.Fatalf("buildMacHostConfigCandidates()\n got  %#v\n want %#v", got, tt.want)
			}
		})
	}
}

func TestDirHasAnyFile(t *testing.T) {
	dir := t.TempDir()

	// A dir with only a stray, non-config file must NOT count as populated —
	// otherwise a junk guest ~/.claude would shadow a real shared Mac home.
	if err := os.WriteFile(filepath.Join(dir, ".DS_Store"), []byte("x"), 0o644); err != nil {
		t.Fatal(err)
	}
	markers := []string{".credentials.json", "settings.json"}
	if dirHasAnyFile(dir, markers) {
		t.Error("dir with only a stray file should not be reported as having config")
	}

	// Once a marker file is present, it counts.
	if err := os.WriteFile(filepath.Join(dir, ".credentials.json"), []byte("{}"), 0o600); err != nil {
		t.Fatal(err)
	}
	if !dirHasAnyFile(dir, markers) {
		t.Error("dir containing a marker file should be reported as having config")
	}

	// Missing directory is not populated, and never panics.
	if dirHasAnyFile(filepath.Join(dir, "does-not-exist"), markers) {
		t.Error("missing dir should not be reported as having config")
	}
	// No markers to look for -> never populated.
	if dirHasAnyFile(dir, nil) {
		t.Error("empty marker list should report no config")
	}
}

func TestResolveHostConfigDir(t *testing.T) {
	// predicate stub: a path satisfies the predicate iff it's in the set.
	predIn := func(members ...string) func(string) bool {
		set := make(map[string]bool, len(members))
		for _, p := range members {
			set[p] = true
		}
		return func(p string) bool { return set[p] }
	}

	const guest = "/home/lima/.claude"
	const mac = "/Users/alice/.claude"
	const mac2 = "/Users/bob/.claude"

	tests := []struct {
		name            string
		candidates      []string
		guestHasConfig  func(string) bool // strict: guest holds a real config file
		candidateUsable func(string) bool // lax: candidate exists and is non-empty
		want            string
	}{
		{
			name:            "guest holds real config -> guest wins over mac home",
			candidates:      []string{mac},
			guestHasConfig:  predIn(guest),
			candidateUsable: predIn(mac),
			want:            guest,
		},
		{
			// The #1 fix: guest ~/.claude has stray files only (not real config),
			// and the Mac home has NO marker file (Keychain creds) but IS non-empty
			// (settings/state) — it must still be chosen.
			name:            "asymmetric: junk guest loses to non-empty keychain-only mac home",
			candidates:      []string{mac},
			guestHasConfig:  predIn(),    // guest has no real config file
			candidateUsable: predIn(mac), // mac dir merely non-empty
			want:            mac,
		},
		{
			name:            "empty mac home candidate is not chosen; guest default kept",
			candidates:      []string{mac},
			guestHasConfig:  predIn(),
			candidateUsable: predIn(), // mac dir empty/missing
			want:            guest,
		},
		{
			name:            "first usable candidate chosen deterministically",
			candidates:      []string{mac, mac2},
			guestHasConfig:  predIn(),
			candidateUsable: predIn(mac, mac2),
			want:            mac,
		},
		{
			name:            "skips empty candidate to reach a usable one",
			candidates:      []string{mac, mac2},
			guestHasConfig:  predIn(),
			candidateUsable: predIn(mac2),
			want:            mac2,
		},
		{
			name:            "candidate equal to guest path is ignored",
			candidates:      []string{guest},
			guestHasConfig:  predIn(),
			candidateUsable: predIn(guest),
			want:            guest,
		},
		{
			name:            "no candidates returns guest",
			candidates:      nil,
			guestHasConfig:  predIn(),
			candidateUsable: predIn(),
			want:            guest,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := ResolveHostConfigDir(guest, tt.candidates, tt.guestHasConfig, tt.candidateUsable)
			if got != tt.want {
				t.Fatalf("ResolveHostConfigDir() = %q, want %q", got, tt.want)
			}
		})
	}
}

func TestResolveToolConfigDir(t *testing.T) {
	const guestHome = "/home/lima"
	const configDir = ".claude"
	const guestPath = "/home/lima/.claude"
	const macCandidate = "/Users/alice/.claude"
	const mounts = "m0 /Users/alice virtiofs rw 0 0\n"
	configFiles := []string{".credentials.json", "settings.json"}
	noSubdirs := func(string) []string { return nil }

	t.Run("KindUnknown (Linux) is a no-op and never touches the filesystem", func(t *testing.T) {
		got := resolveToolConfigDir(guestHome, configDir, configFiles, KindUnknown, mounts, noSubdirs,
			func(string, []string) bool { t.Fatal("guest check must not run when KindUnknown"); return false },
			func(string) bool { t.Fatal("candidate check must not run when KindUnknown"); return false })
		if got != guestPath {
			t.Fatalf("got %q, want guest %q", got, guestPath)
		}
	})

	t.Run("threads the tool's configFiles into the guest check", func(t *testing.T) {
		var seenFiles []string
		got := resolveToolConfigDir(guestHome, configDir, configFiles, KindLimaLike, mounts, noSubdirs,
			func(dir string, files []string) bool { seenFiles = files; return dir == guestPath },
			func(string) bool { return true })
		if got != guestPath {
			t.Fatalf("got %q, want guest %q (guest reports real config)", got, guestPath)
		}
		if !reflect.DeepEqual(seenFiles, configFiles) {
			t.Fatalf("guest check received configFiles %#v, want threaded %#v", seenFiles, configFiles)
		}
	})

	t.Run("builds the candidate from the mounts blob and falls back to it", func(t *testing.T) {
		got := resolveToolConfigDir(guestHome, configDir, configFiles, KindLimaLike, mounts, noSubdirs,
			func(string, []string) bool { return false },         // guest has no real config
			func(dir string) bool { return dir == macCandidate }) // the /Users/alice candidate is usable
		if got != macCandidate {
			t.Fatalf("got %q, want mac candidate %q built from mounts", got, macCandidate)
		}
	})
}

func TestDirNonEmpty(t *testing.T) {
	empty := t.TempDir()
	if dirNonEmpty(empty) {
		t.Error("empty dir should report non-empty=false")
	}
	if dirNonEmpty(filepath.Join(empty, "missing")) {
		t.Error("missing dir should report non-empty=false")
	}
	// A dir with ANY entry (even a stray/non-config one) counts — this is the
	// lax candidate signal, unlike dirHasAnyFile.
	if err := os.WriteFile(filepath.Join(empty, "history.jsonl"), []byte("x"), 0o644); err != nil {
		t.Fatal(err)
	}
	if !dirNonEmpty(empty) {
		t.Error("dir with an entry should report non-empty=true")
	}
}

func TestMacHostHome(t *testing.T) {
	// "/Users" itself is a directory too, as on a real host: an empty or "."
	// $USER must never resolve to the parent.
	dirs := map[string]bool{"/Users": true, "/Users/alice": true, "/Users/bob": true}
	isDir := func(p string) bool { return dirs[p] }

	tests := []struct {
		name   string
		kind   Kind
		mounts string
		user   string
		want   string
	}{
		{"single home mount", KindLimaLike, "mac /Users/alice virtiofs rw 0 0\n", "alice", "/Users/alice"},
		{"single home mount, guest user differs", KindLimaLike, "mac /Users/alice virtiofs rw 0 0\n", "lima", "/Users/alice"},
		{"9p home mount", KindLimaLike, "mac /Users/alice 9p rw 0 0\n", "alice", "/Users/alice"},
		{"whole /Users shared picks the guest user's home", KindOrbStack, "mac /Users virtiofs rw 0 0\n", "bob", "/Users/bob"},
		// Multi-user Mac: never fall back to another account's home (alice sorts first).
		{"whole /Users shared, no home for the guest user", KindOrbStack, "mac /Users virtiofs rw 0 0\n", "carol", ""},
		{"whole /Users shared, unknown user", KindOrbStack, "mac /Users virtiofs rw 0 0\n", "", ""},
		{"two home mounts, one matches the user", KindLimaLike, "a /Users/alice virtiofs rw 0 0\nb /Users/bob virtiofs rw 0 0\n", "bob", "/Users/bob"},
		{"two home mounts, none matches (ambiguous)", KindLimaLike, "a /Users/alice virtiofs rw 0 0\nb /Users/bob virtiofs rw 0 0\n", "carol", ""},
		{"project mount is not a home", KindLimaLike, "mac /Users/alice/code virtiofs rw 0 0\n", "alice", ""},
		{"non-virtiofs /Users mount ignored", KindLimaLike, "mac /Users/alice ext4 rw 0 0\n", "alice", ""},
		{"traversal in $USER is rejected", KindOrbStack, "mac /Users virtiofs rw 0 0\n", "../bob", ""},
		{"dot $USER is rejected", KindOrbStack, "mac /Users virtiofs rw 0 0\n", ".", ""},
		{"dot-dot $USER is rejected", KindOrbStack, "mac /Users virtiofs rw 0 0\n", "..", ""},
		{"Linux host", KindUnknown, "mac /Users/alice virtiofs rw 0 0\n", "alice", ""},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := macHostHome(tt.kind, tt.mounts, tt.user, isDir); got != tt.want {
				t.Errorf("macHostHome() = %q, want %q", got, tt.want)
			}
		})
	}
}
