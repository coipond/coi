package cli

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

func gitT(t *testing.T, dir string, args ...string) string {
	t.Helper()
	c := exec.Command("git", append([]string{"-C", dir}, args...)...)
	c.Env = append(os.Environ(),
		"GIT_AUTHOR_NAME=t", "GIT_AUTHOR_EMAIL=t@t", "GIT_COMMITTER_NAME=t", "GIT_COMMITTER_EMAIL=t@t",
		"GIT_CONFIG_GLOBAL=/dev/null", "GIT_CONFIG_NOSYSTEM=1")
	out, err := c.CombinedOutput()
	if err != nil {
		t.Fatalf("git %v: %v\n%s", args, err, out)
	}
	return strings.TrimSpace(string(out))
}

// upstreamRepo returns a repo with one commit on its default branch, and its
// file:// URL (a plain path would make git ignore --depth).
func upstreamRepo(t *testing.T) (string, string) {
	t.Helper()
	dir := t.TempDir()
	gitT(t, dir, "init", "-q", "-b", "trunk")
	commitFile(t, dir, "rules/linux/process_creation/r.yml", "v1")
	return dir, "file://" + dir
}

func commitFile(t *testing.T, repo, rel, content string) {
	t.Helper()
	p := filepath.Join(repo, rel)
	if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(p, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}
	gitT(t, repo, "add", "-A")
	gitT(t, repo, "commit", "-q", "-m", content)
}

func readRule(t *testing.T, clone string) string {
	t.Helper()
	b, err := os.ReadFile(filepath.Join(clone, "rules/linux/process_creation/r.yml"))
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}

// Both a new upstream commit and a rewritten upstream history reach an
// existing shallow clone; `pull --ff-only` failed on both.
func TestUpdatePatterns_ExistingCloneFollowsUpstream(t *testing.T) {
	t.Setenv("GIT_CONFIG_GLOBAL", "/dev/null")
	t.Setenv("GIT_CONFIG_NOSYSTEM", "1")
	for name, update := range map[string]func(string, string, bool) error{
		"gtfobins": updateGTFOBins,
		"sigma":    updateSigma,
	} {
		t.Run(name, func(t *testing.T) {
			upstream, url := upstreamRepo(t)
			clone := filepath.Join(t.TempDir(), "db")
			if err := update(clone, url, false); err != nil {
				t.Fatalf("clone: %v", err)
			}
			if got := readRule(t, clone); got != "v1" {
				t.Fatalf("after clone: %q", got)
			}

			commitFile(t, upstream, "rules/linux/process_creation/r.yml", "v2")
			if err := update(clone, url, false); err != nil {
				t.Fatalf("update after a new commit: %v", err)
			}
			if got := readRule(t, clone); got != "v2" {
				t.Fatalf("after a new commit: %q", got)
			}

			// Rewrite history: the clone's commit is no longer upstream.
			gitT(t, upstream, "reset", "-q", "--hard", "HEAD~1")
			commitFile(t, upstream, "rules/linux/process_creation/r.yml", "v3")
			if err := update(clone, url, false); err != nil {
				t.Fatalf("update after a rewrite: %v", err)
			}
			if got := readRule(t, clone); got != "v3" {
				t.Fatalf("after a rewrite: %q", got)
			}
			if gitT(t, clone, "rev-parse", "HEAD") != gitT(t, upstream, "rev-parse", "HEAD") {
				t.Fatal("clone HEAD is not upstream HEAD")
			}
		})
	}
}

// The Sigma clone keeps its sparse checkout across updates.
func TestUpdatePatterns_SigmaStaysSparse(t *testing.T) {
	t.Setenv("GIT_CONFIG_GLOBAL", "/dev/null")
	t.Setenv("GIT_CONFIG_NOSYSTEM", "1")
	upstream, url := upstreamRepo(t)
	commitFile(t, upstream, "other/big.txt", "x")
	clone := filepath.Join(t.TempDir(), "sigma")
	if err := updateSigma(clone, url, false); err != nil {
		t.Fatal(err)
	}
	commitFile(t, upstream, "other/big.txt", "y")
	if err := updateSigma(clone, url, false); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(filepath.Join(clone, "other")); !os.IsNotExist(err) {
		t.Fatalf("other/ should stay outside the sparse checkout: %v", err)
	}
}
