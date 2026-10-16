package session

import (
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/coipond/coi/internal/config"
	"github.com/coipond/coi/internal/container"
	"github.com/coipond/coi/internal/tool"
)

// fakeGrantsManager is a container whose applied state (disks, environment.*
// names, nesting) comes from fields, with a file push that can fail per path.
type fakeGrantsManager struct {
	container.ContainerManager
	disks         map[string]container.DiskDevice
	disksErr      error
	envNames      []string
	nesting       bool
	fromProfile   bool
	sourceUnknown bool // the instance's own config can't be read
	limits        map[string]string
	pushFail      map[string]bool // host paths whose push fails
	mkdirFail     bool
}

func (f *fakeGrantsManager) AppliedState() (container.AppliedState, error) {
	return container.AppliedState{
		Disks: f.disks, EnvNames: f.envNames, Nesting: f.nesting,
		NestingSet: f.nesting || f.fromProfile || f.sourceUnknown, Limits: f.limits,
	}, f.disksErr
}

func (f *fakeGrantsManager) NestingSetLocally() (set, ok bool) {
	return !f.fromProfile, !f.sourceUnknown
}

func (f *fakeGrantsManager) ExecArgs(args []string, _ container.ExecCommandOptions) error {
	if f.mkdirFail && args[0] == "mkdir" {
		return errors.New("mkdir failed")
	}
	return nil
}

func (f *fakeGrantsManager) PushFile(src, _ string) error {
	if f.pushFail[src] {
		return errors.New("push failed")
	}
	return nil
}

func (f *fakeGrantsManager) Chown(string, int, int) error { return nil }

func TestClassifyDisks(t *testing.T) {
	disks := map[string]container.DiskDevice{
		"root":                {Path: "/"}, // pool-backed, no host source
		"workspace":           {Source: "/home/u/proj", Path: "/workspace"},
		"mount-0":             {Source: "/data", Path: "/mnt/data", Readonly: true},
		"git-worktree-common": {Source: "/home/u/repo/.git", Path: "/home/u/repo/.git"},
		"user-added":          {Source: "/srv", Path: "/srv"},
		"cache-volume":        {Source: "cache", Path: "/cache", Pool: "default"},
		"protect-git-hooks":   {Source: "/home/u/proj/.git/hooks", Path: "/workspace/.git/hooks", Readonly: true},
		"gitc-hooks":          {Source: "/home/u/repo/.git/hooks", Path: "/home/u/repo/.git/hooks", Readonly: true},
		"mask-env":            {Source: "/tmp/empty", Path: "/workspace/.env", Readonly: true},
		gitReadonlyDeviceName: {Source: "/home/u/.coi/gitconfig", Path: "/home/code/.gitconfig", Readonly: true},
	}
	ws, mounts, protected, masked := classifyDisks(disks, "/workspace")

	if ws != (MountGrant{HostPath: "/home/u/proj", ContainerPath: "/workspace"}) {
		t.Errorf("workspace = %+v", ws)
	}
	want := []MountGrant{
		{HostPath: "cache", ContainerPath: "/cache", Pool: "default"},
		{HostPath: "/home/u/repo/.git", ContainerPath: "/home/u/repo/.git"},
		{HostPath: "/data", ContainerPath: "/mnt/data", Readonly: true},
		{HostPath: "/srv", ContainerPath: "/srv"},
	}
	if len(mounts) != len(want) {
		t.Fatalf("mounts = %+v, want %+v", mounts, want)
	}
	for i := range want {
		if mounts[i] != want[i] {
			t.Errorf("mounts[%d] = %+v, want %+v", i, mounts[i], want[i])
		}
	}
	if strings.Join(protected, ",") != ".git/hooks,/home/u/repo/.git/hooks" {
		t.Errorf("protected = %v", protected)
	}
	if strings.Join(masked, ",") != ".env" {
		t.Errorf("masked = %v", masked)
	}
}

// The report follows the container's devices, not config: a configured mount
// that was never attached is left out, an untrusted one still attached to a
// reused container is listed, and a protection whose mount failed is absent.
func TestBuildGrants_FromDevices(t *testing.T) {
	mgr := &fakeGrantsManager{
		disks: map[string]container.DiskDevice{
			"workspace":         {Source: "/home/u/proj", Path: "/workspace"},
			"mount-0":           {Source: "/home/u/.aws", Path: "/home/code/.aws"}, // dropped by trust, still attached
			"protect-git-hooks": {Source: "/home/u/proj/.git/hooks", Path: "/workspace/.git/hooks", Readonly: true},
		},
		envNames: []string{"GIT_AUTHOR_NAME"},
		nesting:  false, // created without Docker, though config now enables it
	}
	st := &setupState{
		opts: SetupOptions{
			WorkspacePath: "/home/u/proj",
			MountConfig:   &MountConfig{Mounts: []MountEntry{{HostPath: "/new", ContainerPath: "/new"}}},
			Security:      SecurityOptions{ProtectedPaths: []string{".git/hooks", ".git/config"}, Docker: true},
			Network: NetworkOptions{Config: &config.NetworkConfig{
				Mode:                    config.NetworkModeRestricted,
				AllowLocalNetworkAccess: boolPtr(true),
				BlockMetadataEndpoint:   boolPtr(true),
			}},
		},
		result:           &SetupResult{Manager: mgr},
		forwardedSockets: []SocketEntry{{HostPath: "/run/a.sock", ContainerPath: "/run/a.sock"}},
		// What contextInfoFor reports once it read the container's nesting.
		contextInfo: tool.ContextInfo{WorkspacePath: "/workspace", NetworkMode: "restricted", DockerUnavailable: true},
	}
	g := buildGrants(st)

	if g.DevicesUnread {
		t.Fatal("devices were readable")
	}
	if !g.DockerUnavailable || !g.DockerConfigDiffers || g.DockerSource != dockerSourceInstance {
		t.Errorf("Docker should follow the container's nesting and flag the config: %+v", g)
	}
	if strings.Join(g.Env.Container, ",") != "GIT_AUTHOR_NAME" {
		t.Errorf("container env = %v", g.Env.Container)
	}
	if len(g.Mounts) != 1 || g.Mounts[0].HostPath != "/home/u/.aws" {
		t.Errorf("mounts = %+v, want only the attached ~/.aws", g.Mounts)
	}
	if strings.Join(g.Protected, ",") != ".git/hooks" {
		t.Errorf("protected = %v, want only the mounted .git/hooks", g.Protected)
	}
	if len(g.Sockets) != 1 {
		t.Errorf("sockets = %+v", g.Sockets)
	}
	if len(g.Env.FromHost)+len(g.Env.Minted)+len(g.Env.Configured) != 0 {
		t.Errorf("Env is the caller's to fill (WithEnv), got %+v", g.Env)
	}
	n := g.Network
	if n.Mode != "restricted" || !n.LANAccess || n.LANBlocked || !n.MetadataBlock {
		t.Errorf("network = %+v", n)
	}
}

func TestBuildGrants_DevicesUnreadable(t *testing.T) {
	ws := t.TempDir()
	if err := os.MkdirAll(filepath.Join(ws, ".git", "hooks"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(ws, ".env"), []byte("SECRET=1"), 0o600); err != nil {
		t.Fatal(err)
	}
	mgr := &fakeGrantsManager{disksErr: errors.New("incus down")}
	st := &setupState{
		opts: SetupOptions{
			WorkspacePath: ws,
			MountConfig:   &MountConfig{Mounts: []MountEntry{{HostPath: "/data", ContainerPath: "/data", Readonly: true}}},
			Security: SecurityOptions{
				ProtectedPaths: []string{".git/hooks", ".husky"},
				SecretPaths:    []string{".env", ".missing-secret"},
			},
		},
		result:      &SetupResult{Manager: mgr},
		contextInfo: tool.ContextInfo{WorkspacePath: "/workspace"},
	}
	g := buildGrants(st)

	if !g.DevicesUnread || len(g.Mounts) != 1 || strings.Join(g.Protected, ",") != ".git/hooks" {
		t.Fatalf("fallback grants = %+v", g)
	}
	if strings.Join(g.Masked, ",") != ".env" {
		t.Errorf("fallback masked = %v, want the existing .env", g.Masked)
	}
	out := g.Render()
	if !strings.Contains(out, "(could not read the container's devices; showing what config asks for)") {
		t.Errorf("fallback should be flagged:\n%s", out)
	}
}

// grantsMounter records the disks SetupSecurityMounts adds.
type grantsMounter struct {
	container.ContainerDevices
	mounted []string
}

func (m *grantsMounter) MountDisk(name, _, _ string, _, _ bool) error {
	m.mounted = append(m.mounted, name)
	return nil
}

// The config fallback runs after setup, which materializes a read-only
// placeholder for a missing default protected path (.vscode here) and mounts
// it, so the fallback lists it like the device read would.
func TestBuildGrants_FallbackListsPlaceholders(t *testing.T) {
	ws := t.TempDir()
	m := &grantsMounter{}
	paths, err := SetupSecurityMounts(m, ws, "/workspace", []string{".vscode"}, false, nil)
	if err != nil || len(m.mounted) != 1 {
		t.Fatalf("setup mounted %v, err %v", m.mounted, err)
	}
	st := &setupState{
		opts:        SetupOptions{WorkspacePath: ws, Security: SecurityOptions{ProtectedPaths: paths}},
		result:      &SetupResult{Manager: &fakeGrantsManager{disksErr: errors.New("incus down")}},
		contextInfo: tool.ContextInfo{WorkspacePath: "/workspace"},
	}
	if g := buildGrants(st); strings.Join(g.Protected, ",") != ".vscode" {
		t.Errorf("fallback protected = %v, want the mounted .vscode placeholder", g.Protected)
	}
}

// Copied files list what this launch pushed. A reused container is also
// checked, once, for host files an earlier session copied that this launch
// didn't; the check reports them by kind, still as copied or changed since.
// A new container is not checked.
func TestBuildGrants_CopiedFiles(t *testing.T) {
	claude, err := tool.Get("claude")
	if err != nil {
		t.Fatal(err)
	}
	base := func() *setupState {
		return &setupState{
			opts:              SetupOptions{Tool: claude},
			result:            &SetupResult{Manager: &fakeGrantsManager{disks: map[string]container.DiskDevice{}}, HomeDir: "/home/code"},
			copiedCredentials: []CredentialEntry{{HostPath: "/h/a", ContainerPath: "/home/code/.a"}},
			toolFiles:         []CredentialEntry{{HostPath: "/home/u/.claude.json", ContainerPath: "/home/code/.claude.json"}},
		}
	}

	t.Run("new container", func(t *testing.T) {
		st := base()
		st.opts.ResumeFromID = "abc" // resumed into a new container: still nothing to find
		if op, ok := st.planLeftoverCheck(); ok {
			t.Errorf("a new container should not be checked, got %q", op.cmd)
		}
		g := buildGrants(st)
		if len(g.Credentials) != 1 || g.Credentials[0] != (CredentialGrant{HostPath: "/h/a", ContainerPath: "/home/code/.a"}) {
			t.Errorf("credentials = %+v", g.Credentials)
		}
		if len(g.ToolFiles) != 1 || g.ToolFiles[0].ContainerPath != "/home/code/.claude.json" || g.LeftoversUnchecked {
			t.Errorf("tool files = %+v, unchecked %v", g.ToolFiles, g.LeftoversUnchecked)
		}
	})

	t.Run("reused container", func(t *testing.T) {
		st := base()
		st.skipLaunch = true
		op, ok := st.planLeftoverCheck()
		if !ok {
			t.Fatal("a reused container should be checked")
		}
		if !strings.Contains(op.cmd, "'/home/code/.a'") || !strings.Contains(op.cmd, "'/home/code/.claude.json'") {
			t.Errorf("this launch's copies should be excluded by path: %s", op.cmd)
		}
		st.leftovers.parse("tz set\n" +
			leftoverSameMarker + "c\t/etc/b\t/h/b\n" +
			leftoverChangedMarker + "t\t/home/code/.claude/.credentials.json\t/home/u/.claude/.credentials.json\n" +
			leftoverUnknownMarker + "c\t/home/code/.npmrc\t/home/u/.npmrc\n" +
			"garbage\n" + leftoverCheckedMarker + "\n")
		g := buildGrants(st)

		want := []CredentialGrant{
			{HostPath: "/h/a", ContainerPath: "/home/code/.a"},
			{HostPath: "/h/b", ContainerPath: "/etc/b", Earlier: true},
			{HostPath: "/home/u/.npmrc", ContainerPath: "/home/code/.npmrc", Earlier: true, Unverified: true},
		}
		if len(g.Credentials) != 3 || g.Credentials[0] != want[0] || g.Credentials[1] != want[1] || g.Credentials[2] != want[2] {
			t.Errorf("credentials = %+v, want %+v", g.Credentials, want)
		}
		earlierTool := CredentialGrant{
			HostPath: "/home/u/.claude/.credentials.json", ContainerPath: "/home/code/.claude/.credentials.json",
			Earlier: true, Changed: true,
		}
		if len(g.ToolFiles) != 2 || g.ToolFiles[1] != earlierTool {
			t.Errorf("tool files = %+v, want the copied .claude.json then %+v", g.ToolFiles, earlierTool)
		}
		if g.LeftoversUnchecked {
			t.Error("LeftoversUnchecked set after a completed check")
		}
		out := g.Render()
		for _, w := range []string{
			"/h/b -> /etc/b (already in the container, not copied this launch)",
			"Tool config  /home/u/.claude.json -> /home/code/.claude.json\n",
			"/home/code/.claude/.credentials.json (copied by an earlier session, since changed in the container)\n",
			"/home/code/.npmrc (in the container; it predates coi recording copies, so it may not be from the host)\n",
		} {
			if !strings.Contains(out, w) {
				t.Errorf("missing %q in:\n%s", w, out)
			}
		}
	})

	// A check that never finished (the exec failed) must not read as
	// "nothing left over".
	t.Run("check did not run", func(t *testing.T) {
		st := base()
		st.skipLaunch = true
		if _, ok := st.planLeftoverCheck(); !ok {
			t.Fatal("a reused container should be checked")
		}
		st.leftovers.parse("")
		g := buildGrants(st)
		if !g.LeftoversUnchecked || len(g.Credentials) != 1 {
			t.Errorf("unchecked %v, credentials %+v", g.LeftoversUnchecked, g.Credentials)
		}
		if out := g.Render(); !strings.Contains(out, "(could not check the container for files copied by earlier sessions)") {
			t.Errorf("missing unchecked note in:\n%s", out)
		}
	})

	// Resume into a new container restores the saved config dir: its login
	// file is listed as restored, unless a fresh copy replaced it, and both
	// are recorded in the manifest.
	t.Run("restored on resume", func(t *testing.T) {
		st := base()
		st.restoredFiles = []CredentialEntry{
			{HostPath: "/s/abc/.claude/.credentials.json", ContainerPath: "/home/code/.claude/.credentials.json"},
			{HostPath: "/s/abc/.claude/x.json", ContainerPath: "/home/code/.claude.json"}, // replaced by the copy
		}
		g := buildGrants(st)
		want := CredentialGrant{HostPath: "/s/abc/.claude/.credentials.json", ContainerPath: "/home/code/.claude/.credentials.json", Restored: true}
		if len(g.ToolFiles) != 2 || g.ToolFiles[1] != want {
			t.Errorf("tool files = %+v, want the copy then %+v", g.ToolFiles, want)
		}
		if out := g.Render(); !strings.Contains(out, "/home/code/.claude/.credentials.json (restored from the saved session)\n") {
			t.Errorf("restored label missing:\n%s", out)
		}
		if n := len(st.copiesThisLaunch()); n != 3 {
			t.Errorf("copies to record = %d, want the credential, the copy and the live restore", n)
		}
	})
}

// restoredToolFiles lists only the essential files the saved session has.
func TestRestoredToolFiles(t *testing.T) {
	claude, err := tool.Get("claude")
	if err != nil {
		t.Fatal(err)
	}
	sessions := t.TempDir()
	saved := filepath.Join(sessions, "abc", ".claude")
	if err := os.MkdirAll(saved, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(saved, ".credentials.json"), []byte("{}"), 0o600); err != nil {
		t.Fatal(err)
	}
	got := restoredToolFiles(sessions, "abc", "/home/code", claude)
	want := []CredentialEntry{{HostPath: filepath.Join(saved, ".credentials.json"), ContainerPath: "/home/code/.claude/.credentials.json"}}
	if len(got) != 1 || got[0] != want[0] {
		t.Errorf("restored = %+v, want %+v", got, want)
	}
}

// The record and check ops are real shell: run them (as the batch would)
// against temp files, with paths that need quoting, and feed the output to
// parse. The check finds recorded files from the manifest alone (config need
// not name them), skips this launch's copies, tells unchanged from changed,
// ignores files coi never copied, and without a manifest lists existing
// candidates as origin unknown.
func TestLeftoverCheckOp_RunsInShell(t *testing.T) {
	dir := t.TempDir()
	old := copyManifestPath
	copyManifestPath = filepath.Join(dir, "state", "copied-host-files")
	t.Cleanup(func() { copyManifestPath = old })
	file := func(name, content string) string {
		p := filepath.Join(dir, name)
		if err := os.WriteFile(p, []byte(content), 0o600); err != nil {
			t.Fatal(err)
		}
		return p
	}
	copied := file(`it's \copied`, "token")
	refreshed := file(".credentials.json", "old token")
	thisLaunch := file("fresh", "new")
	fromImage := file("gitconfig", "[user]")
	gone := filepath.Join(dir, "gone")

	run := func(ops ...guestOp) string {
		t.Helper()
		out, err := exec.Command("bash", "-c", renderGuestScript(ops)).Output()
		if err != nil {
			t.Fatalf("ops failed the batch: %v (%s)", err, out)
		}
		return string(out)
	}
	rec := func(kind, p, host string) copyRecord {
		return copyRecord{kind, CredentialEntry{HostPath: host, ContainerPath: p}}
	}
	record, ok := recordCopiesOp([]copyRecord{
		rec(copyKindCredential, copied, "/host/it's copied"),
		rec(copyKindTool, refreshed, "/host/.credentials.json"),
		rec(copyKindTool, thisLaunch, "/host/fresh"),
		rec(copyKindCredential, gone, "/host/gone"), // missing: not recorded
	})
	if !ok {
		t.Fatal("no record op for copied files")
	}
	// A container setup created: marked complete, then recorded.
	run(markManifestCompleteOp(), record, markManifestCompleteOp(), record) // re-runs must not duplicate
	if b, _ := os.ReadFile(copyManifestPath); strings.Count(string(b), "\n") != 4 || !strings.HasPrefix(string(b), copyManifestComplete+"\n") || strings.Contains(string(b), gone) {
		t.Errorf("manifest = %q", b)
	}
	file(".credentials.json", "new token") // the tool refreshed it

	lc := leftoverCheck{planned: true}
	out := run(leftoverCheckOp([]string{thisLaunch}, []copyRecord{rec(copyKindCredential, fromImage, "/host/gitconfig")}))
	lc.parse(out)
	wantCreds := []CredentialGrant{{HostPath: "/host/it's copied", ContainerPath: copied, Earlier: true}}
	wantTools := []CredentialGrant{{HostPath: "/host/.credentials.json", ContainerPath: refreshed, Earlier: true, Changed: true}}
	if !lc.checked || len(lc.creds) != 1 || lc.creds[0] != wantCreds[0] || len(lc.tools) != 1 || lc.tools[0] != wantTools[0] {
		t.Errorf("parsed %+v from %q", lc, out)
	}

	// A manifest started on an older container (no complete mark): recorded
	// copies are vouched for, and unrecorded candidates that exist are still
	// listed as origin unknown, once.
	if err := os.WriteFile(copyManifestPath, []byte(strings.Join(strings.Split(mustRead(t, copyManifestPath), "\n")[1:], "\n")), 0o600); err != nil {
		t.Fatal(err)
	}
	lc = leftoverCheck{planned: true}
	lc.parse(run(leftoverCheckOp([]string{thisLaunch}, []copyRecord{
		rec(copyKindCredential, fromImage, "/host/gitconfig"),
		rec(copyKindCredential, copied, "/host/it's copied"), // recorded: not unknown
	})))
	if !lc.checked || len(lc.creds) != 2 || lc.creds[0].Unverified || lc.creds[0].ContainerPath != copied ||
		!lc.creds[1].Unverified || lc.creds[1].ContainerPath != fromImage {
		t.Errorf("incomplete manifest parsed %+v", lc)
	}

	// No manifest (a container from before coi recorded copies): existing
	// candidates are listed as origin unknown; this launch's copies aren't.
	if err := os.Remove(copyManifestPath); err != nil {
		t.Fatal(err)
	}
	lc = leftoverCheck{planned: true}
	lc.parse(run(leftoverCheckOp([]string{thisLaunch}, []copyRecord{
		rec(copyKindCredential, fromImage, "/host/gitconfig"),
		rec(copyKindTool, thisLaunch, "/host/fresh"),
		rec(copyKindTool, gone, "/host/gone"),
	})))
	if !lc.checked || len(lc.tools) != 0 || len(lc.creds) != 1 || !lc.creds[0].Unverified || lc.creds[0].ContainerPath != fromImage {
		t.Errorf("without a manifest parsed %+v", lc)
	}
}

func mustRead(t *testing.T, path string) string {
	t.Helper()
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}

// The record op is best-effort: an unwritable manifest must not fail the
// batch (and the context files written after it).
func TestRecordCopiesOp_NeverFails(t *testing.T) {
	old := copyManifestPath
	copyManifestPath = "/proc/coi-no-such-dir/copied-host-files"
	t.Cleanup(func() { copyManifestPath = old })
	op, _ := recordCopiesOp([]copyRecord{{copyKindTool, CredentialEntry{ContainerPath: "/etc/hostname"}}})
	if out, err := exec.Command("bash", "-c", renderGuestScript([]guestOp{op, guestCmd("echo after")})).Output(); err != nil || !strings.Contains(string(out), "after") {
		t.Errorf("record op failed the batch: %v (%s)", err, out)
	}
	if _, ok := recordCopiesOp(nil); ok {
		t.Error("nothing copied should need no op")
	}
}

// An unchecked report with no copies still gets a Credentials row for the note.
func TestGrantsRender_LeftoversUnchecked(t *testing.T) {
	g := &Grants{LeftoversUnchecked: true}
	if out := g.Render(); !strings.Contains(out, "Credentials  (could not check the container for files copied by earlier sessions)\n") {
		t.Errorf("unchecked note missing:\n%s", out)
	}
}

// setupCredentials returns only the entries actually pushed: a missing host
// file and a failed push are left out, and on a fatal error the ones copied
// before it are still returned.
func TestSetupCredentials_ReturnsCopied(t *testing.T) {
	dir := t.TempDir()
	write := func(name string) string {
		p := filepath.Join(dir, name)
		if err := os.WriteFile(p, []byte("x"), 0o600); err != nil {
			t.Fatal(err)
		}
		return p
	}
	ok, fails := write("ok"), write("fails")
	entries := []CredentialEntry{
		{HostPath: ok, ContainerPath: ".ok"},
		{HostPath: filepath.Join(dir, "missing"), ContainerPath: ".missing"},
		{HostPath: fails, ContainerPath: "/etc/fails"},
	}
	mgr := &fakeGrantsManager{pushFail: map[string]bool{fails: true}}
	copied, err := setupCredentials(mgr, "/home/code", entries, func(string) {})
	if err != nil {
		t.Fatal(err)
	}
	if len(copied) != 1 || copied[0].HostPath != ok || copied[0].ContainerPath != "/home/code/.ok" {
		t.Errorf("copied = %+v, want only %s at /home/code/.ok", copied, ok)
	}

	copied, err = setupCredentials(&fakeGrantsManager{mkdirFail: true}, "/home/code", entries, func(string) {})
	if err == nil || len(copied) != 0 {
		t.Errorf("mkdir failure: copied = %+v, err = %v", copied, err)
	}
}

// A bare session states every core grant category, with "none" for absent
// ones, and omits the optional rows.
func TestGrantsRender_Minimal(t *testing.T) {
	g := &Grants{
		Workspace: MountGrant{HostPath: "/home/u/proj", ContainerPath: "/workspace"},
	}
	out := g.Render()
	for _, want := range []string{
		"Effective grants:\n",
		"Workspace  /home/u/proj -> /workspace (read-write)",
		"Mounts     none",
		"Protected  none",
		"Network    open (no egress filtering)",
		"Sockets    none",
		"Env        none",
		"Agent      runs as non-root, Docker available",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("missing %q in:\n%s", want, out)
		}
	}
	for _, absent := range []string{"Masked", "Ports", "Credentials", "Limits", "could not read"} {
		if strings.Contains(out, absent) {
			t.Errorf("unexpected %q in:\n%s", absent, out)
		}
	}
}

func TestGrantsRender_Full(t *testing.T) {
	g := &Grants{
		Workspace: MountGrant{HostPath: "/home/u/proj", ContainerPath: "/workspace"},
		Mounts: []MountGrant{
			{HostPath: "/data", ContainerPath: "/mnt/data", Readonly: true},
			{HostPath: "/cache", ContainerPath: "/mnt/cache"},
			{HostPath: "shared", ContainerPath: "/shared", Pool: "default"},
		},
		Protected: []string{".git/hooks", ".husky"},
		Masked:    []string{".env"},
		Sockets: []SocketEntry{
			{HostPath: "/run/user/1000/agent.sock", ContainerPath: "/tmp/ssh-agent.sock", EnvVar: "SSH_AUTH_SOCK"},
			{HostPath: "/run/broker.sock", ContainerPath: "/run/broker.sock"},
		},
		Credentials: []CredentialGrant{{HostPath: "/home/u/.aws/credentials", ContainerPath: "/home/code/.aws/credentials"}},
		ToolFiles:   []CredentialGrant{{HostPath: "/home/u/.claude/.credentials.json", ContainerPath: "/home/code/.claude/.credentials.json"}},
		Env: EnvGrants{
			FromHost:   []string{"GH_TOKEN"},
			Minted:     []string{"AWS_SESSION_TOKEN"},
			Configured: []string{"ANTHROPIC_API_KEY", "FOO"},
		},
		Network: NetworkGrants{
			Mode:           "allowlist",
			AllowedDomains: []string{"github.com", "api.anthropic.com"},
			AllowedPorts:   []int{443},
			Hosts:          []config.HostEntry{{IP: "192.168.1.50", Hostnames: []string{"nas"}, Ports: []int{443}}},
		},
		Ports: []tool.PortInfo{
			{Name: "web", HostPort: 41000, ContainerPort: 3000},
			{HostPort: 42000, ContainerPort: 42000, Pool: true},
		},
		RunAsRoot:         true,
		DockerUnavailable: true,
		Limits:            []string{"cpu 2", "memory 4GiB"},
		MaxDuration:       "2h",
	}
	out := g.Render()
	for _, want := range []string{
		"Mounts       /data -> /mnt/data (read-only)\n",
		"             /cache -> /mnt/cache (read-write)\n",
		"             volume default/shared -> /shared (read-write)\n",
		"Protected    .git/hooks, .husky (read-only)\n",
		"Masked       .env (hidden)\n",
		"Network      allowlist: github.com, api.anthropic.com\n",
		"             LAN and metadata endpoint blocked\n",
		"             ports 443 only\n",
		"             host 192.168.1.50 (nas) on ports 443\n",
		"Ports        web: container 3000 -> host 127.0.0.1:41000\n",
		"             pool: 42000 (same number on host)\n",
		"Sockets      /run/user/1000/agent.sock -> /tmp/ssh-agent.sock (SSH_AUTH_SOCK)\n",
		"             /run/broker.sock -> /run/broker.sock\n",
		"Env          GH_TOKEN (from host)\n",
		"             AWS_SESSION_TOKEN (env_commands)\n",
		"             ANTHROPIC_API_KEY, FOO (set by config)\n",
		"Tool config  /home/u/.claude/.credentials.json -> /home/code/.claude/.credentials.json\n",
		"Credentials  /home/u/.aws/credentials -> /home/code/.aws/credentials\n",
		"Agent        runs as root, Docker unavailable\n",
		"Limits       cpu 2, memory 4GiB, max duration 2h\n",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("missing %q in:\n%s", want, out)
		}
	}
}

func TestGrantsRender_Network(t *testing.T) {
	hosts := []config.HostEntry{{IP: "10.0.0.5", Hostnames: []string{"db"}, Ports: []int{5432}}}
	cases := []struct {
		name    string
		n       NetworkGrants
		want    []string
		notWant []string
	}{
		{
			name: "restricted, LAN and metadata blocked, DNS pinned",
			n:    NetworkGrants{Mode: "restricted", LANBlocked: true, MetadataBlock: true, DNSServers: []string{"10.0.0.53"}},
			want: []string{"restricted: internet (LAN blocked, metadata endpoint blocked)", "DNS pinned to 10.0.0.53"},
		},
		{
			name: "restricted, LAN access wins, metadata open",
			n:    NetworkGrants{Mode: "restricted", LANAccess: true, LANBlocked: true},
			want: []string{"restricted: internet (LAN allowed, metadata endpoint not blocked)"},
		},
		{
			name: "allowlist with LAN access opens metadata",
			n:    NetworkGrants{Mode: "allowlist", LANAccess: true, MetadataBlock: true},
			want: []string{"allowlist: nothing", "LAN allowed (metadata endpoint not blocked)"},
		},
		{
			name:    "allowlist without LAN access blocks LAN and metadata, never shows a DNS pin",
			n:       NetworkGrants{Mode: "allowlist", DNSServers: []string{"1.1.1.1"}},
			want:    []string{"LAN and metadata endpoint blocked"},
			notWant: []string{"DNS pinned"},
		},
		{
			name:    "open lists hosts entries but no unenforced caps",
			n:       NetworkGrants{Mode: "open", Hosts: hosts, AllowedPorts: []int{443}, DNSServers: []string{"1.1.1.1"}},
			want:    []string{"open (no egress filtering)", "host 10.0.0.5 (db)\n"},
			notWant: []string{"ports 443", "DNS pinned", "on ports", "LAN"},
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			out := (&Grants{Network: tc.n}).Render()
			for _, w := range tc.want {
				if !strings.Contains(out, w) {
					t.Errorf("missing %q in:\n%s", w, out)
				}
			}
			for _, w := range tc.notWant {
				if strings.Contains(out, w) {
					t.Errorf("unexpected %q in:\n%s", w, out)
				}
			}
		})
	}
}

func TestGrantsWithEnv_DoesNotMutate(t *testing.T) {
	g := &Grants{Env: EnvGrants{FromHost: []string{"A"}, Tool: []string{"T"}}}
	c := g.WithEnv(EnvGrants{Minted: []string{"B"}}, ToolStarted)
	if len(g.Env.Minted) != 0 || len(g.Env.FromHost) != 1 {
		t.Errorf("original changed: %+v", g.Env)
	}
	if len(c.Env.Minted) != 1 || len(c.Env.FromHost) != 0 {
		t.Errorf("copy = %+v", c.Env)
	}
	if len(c.Env.Tool) != 1 {
		t.Errorf("WithEnv dropped the setup-time env: %+v", c.Env)
	}
}

// Each variable is listed once, under the source the agent's value comes
// from: tool settings beat the config layers, per-exec env beats the
// container's environment.*.
func TestGrantsRender_EnvSources(t *testing.T) {
	g := (&Grants{Env: EnvGrants{
		Tool:      []string{"ANTHROPIC_MODEL", "GH_TOKEN"},
		Container: []string{"GIT_AUTHOR_NAME", "ANTHROPIC_MODEL", "FOO"},
	}}).WithEnv(EnvGrants{FromHost: []string{"GH_TOKEN", "HOME_VAR"}, Configured: []string{"FOO"}}, ToolStarted)
	out := g.Render()
	for _, w := range []string{
		"Env        ANTHROPIC_MODEL, GH_TOKEN (tool settings)\n",
		"           HOME_VAR (from host)\n",
		"           FOO (set by config)\n",
		"           GIT_AUTHOR_NAME (container environment)\n",
	} {
		if !strings.Contains(out, w) {
			t.Errorf("missing %q in:\n%s", w, out)
		}
	}
}

// A launch into a running tmux session: the tool keeps its env (attached, or
// typed into the existing pane by a background launch), but the session env
// is updated, so the names are listed as reaching new panes.
func TestGrantsRender_EnvRunningTool(t *testing.T) {
	g := (&Grants{Env: EnvGrants{Tool: []string{"T"}}}).WithEnv(EnvGrants{Minted: []string{"TOKEN"}}, ToolAttached)
	out := g.Render()
	for _, w := range []string{
		"Env        the running tool keeps the env it started with; new panes get:\n",
		"           T (tool settings)\n",
		"           TOKEN (env_commands)\n",
	} {
		if !strings.Contains(out, w) {
			t.Errorf("missing %q in:\n%s", w, out)
		}
	}
	sent := g.WithEnv(EnvGrants{Minted: []string{"TOKEN"}}, ToolSentToPane).Render()
	if !strings.Contains(sent, "Env        the tool starts in the existing pane, which keeps its env; new panes get:\n") {
		t.Errorf("send-to-pane note missing:\n%s", sent)
	}
	empty := (&Grants{}).WithEnv(EnvGrants{}, ToolAttached).Render()
	if !strings.Contains(empty, "new panes get:\n             none\n") {
		t.Errorf("attach with no env should say none:\n%s", empty)
	}
}

// A device with coi's protect-/gitc-/mask- prefix that is writable is not a
// coi protection (coi's are always read-only), so it is listed as a mount.
func TestClassifyDisks_WritablePrefixIsAMount(t *testing.T) {
	_, mounts, protected, masked := classifyDisks(map[string]container.DiskDevice{
		"mask-data":     {Source: "/home/u/secrets", Path: "/data"},
		"protect-thing": {Source: "/srv/thing", Path: "/thing"},
		"mask-real":     {Source: "/tmp/empty", Path: "/workspace/.env", Readonly: true},
		"protect-hooks": {Source: "/p/.git/hooks", Path: "/workspace/.git/hooks", Readonly: true},
	}, "/workspace")
	if len(mounts) != 2 || mounts[0].ContainerPath != "/data" || mounts[1].ContainerPath != "/thing" {
		t.Errorf("mounts = %+v, want the two writable look-alikes", mounts)
	}
	if strings.Join(protected, ",") != ".git/hooks" || strings.Join(masked, ",") != ".env" {
		t.Errorf("protected = %v, masked = %v", protected, masked)
	}
}

// Limits and Docker follow the container, which keeps what it was created
// with. A Docker setting config would change on restart is flagged as such;
// one an Incus profile pins is flagged as the profile's, since a restart
// wouldn't change it; one whose source can't be told gets no advice.
func TestBuildGrants_AppliedLimitsAndDocker(t *testing.T) {
	mgr := &fakeGrantsManager{
		disks:   map[string]container.DiskDevice{"workspace": {Source: "/p", Path: "/workspace"}},
		nesting: true,
		limits: map[string]string{
			"limits.cpu.allowance": "50%", "limits.cpu": "2", "root.limits.read": "10MB", "limits.processes": "500",
			// Config's defaults, written with any limit: they cap nothing.
			"limits.memory.enforce": "soft", "limits.memory.swap": "true",
		},
	}
	st := &setupState{
		opts:        SetupOptions{}, // Docker off in config
		result:      &SetupResult{Manager: mgr},
		contextInfo: tool.ContextInfo{WorkspacePath: "/workspace", CPULimit: "8", MemoryLimit: "4GiB", MaxDuration: "1h"},
	}
	g := buildGrants(st)
	if strings.Join(g.Limits, ", ") != "cpu 2, cpu allowance 50%, processes 500, disk read 10MB" || g.MaxDuration != "1h" {
		t.Errorf("limits = %v, duration %q; want the container's, in order, and config's duration", g.Limits, g.MaxDuration)
	}
	out := g.Render()
	for _, w := range []string{
		"Agent      runs as non-root, Docker available (config disables it; restart the container to apply)\n",
		"Limits     cpu 2, cpu allowance 50%, processes 500, disk read 10MB, max duration 1h\n",
	} {
		if !strings.Contains(out, w) {
			t.Errorf("missing %q in:\n%s", w, out)
		}
	}

	// contextInfo's DockerUnavailable is what contextInfoFor derives from the
	// container's nesting; the report keeps it and compares it with config.
	fresh := func(m *fakeGrantsManager, o SetupOptions) string {
		info := st.contextInfo
		info.DockerUnavailable = !m.nesting
		return buildGrants(&setupState{opts: o, result: &SetupResult{Manager: m}, contextInfo: info}).Render()
	}
	mgr.fromProfile = true
	if out := fresh(mgr, SetupOptions{}); !strings.Contains(out, "Docker available (an Incus profile enables nesting; config disables Docker)\n") {
		t.Errorf("profile nesting not attributed:\n%s", out)
	}
	mgr.fromProfile, mgr.sourceUnknown = false, true
	if out := fresh(mgr, SetupOptions{}); !strings.Contains(out, "Docker available (config disables it)\n") {
		t.Errorf("unknown source should carry no restart advice:\n%s", out)
	}
	mgr.nesting, mgr.sourceUnknown = false, false
	if out := fresh(mgr, SetupOptions{Security: SecurityOptions{Docker: true}}); !strings.Contains(out, "Docker unavailable (config enables it; restart the container to apply)\n") {
		t.Errorf("enable mismatch not flagged:\n%s", out)
	}
	if out := fresh(mgr, SetupOptions{}); !strings.Contains(out, "Docker unavailable\n") {
		t.Errorf("matching setting should carry no note:\n%s", out)
	}
}

// The context files tell the agent the same Docker state as the report: the
// container's, once setup read it.
// Memory enforcement and swap are listed only when they tighten the defaults.
func TestLimitLines_TighterThanDefaults(t *testing.T) {
	got := strings.Join(limitLines(map[string]string{
		"limits.memory": "2GiB", "limits.memory.enforce": "hard", "limits.memory.swap": "false",
	}), ", ")
	if got != "memory 2GiB, memory enforce hard, swap false" {
		t.Errorf("limits = %q", got)
	}
}

func TestContextInfo_DockerFollowsContainer(t *testing.T) {
	opts := SetupOptions{Security: SecurityOptions{Docker: true}}
	if contextInfoFor(&SetupResult{}, opts).DockerUnavailable {
		t.Error("without a read, config decides")
	}
	r := &SetupResult{applied: &container.AppliedState{Nesting: false}}
	if !contextInfoFor(r, opts).DockerUnavailable {
		t.Error("the container's nesting should decide once read")
	}
}

// When the devices can't be read and setup left the workspace path empty,
// the fallback uses /workspace like the rest of coi, not an empty path.
func TestBuildGrants_FallbackDefaultWorkspace(t *testing.T) {
	st := &setupState{
		opts:   SetupOptions{WorkspacePath: "/home/u/p"},
		result: &SetupResult{Manager: &fakeGrantsManager{disksErr: errors.New("incus down")}},
	}
	if out := buildGrants(st).Render(); !strings.Contains(out, "Workspace  /home/u/p -> /workspace (read-write)\n") {
		t.Errorf("fallback workspace:\n%s", out)
	}
}

// Without a "workspace" device the row says none instead of a blank path.
func TestGrantsRender_NoWorkspaceDevice(t *testing.T) {
	if out := (&Grants{}).Render(); !strings.Contains(out, "Workspace  none\n") {
		t.Errorf("missing workspace should say none:\n%s", out)
	}
}
