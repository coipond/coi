package session

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/coipond/coi/internal/config"
	"github.com/coipond/coi/internal/container"
	"github.com/coipond/coi/internal/tool"
)

// fakeGrantsManager is a container with disk devices in a map, an exec that
// answers the credential probe, and a file push that can fail per path.
type fakeGrantsManager struct {
	container.ContainerManager
	disks     map[string]container.DiskDevice
	disksErr  error
	probeOut  string
	probeArgs []string
	pushFail  map[string]bool // host paths whose push fails
	mkdirFail bool
}

func (f *fakeGrantsManager) DiskDevices() (map[string]container.DiskDevice, error) {
	return f.disks, f.disksErr
}

func (f *fakeGrantsManager) ExecArgsCapture(args []string, _ container.ExecCommandOptions) (string, error) {
	f.probeArgs = args
	return f.probeOut, nil
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
		"protect-git-hooks":   {Source: "/home/u/proj/.git/hooks", Path: "/workspace/.git/hooks", Readonly: true},
		"gitc-hooks":          {Source: "/home/u/repo/.git/hooks", Path: "/home/u/repo/.git/hooks", Readonly: true},
		"mask-env":            {Source: "/tmp/empty", Path: "/workspace/.env", Readonly: true},
		gitReadonlyDeviceName: {Source: "/home/u/.coi/gitconfig", Path: "/home/code/.gitconfig", Readonly: true},
	}
	ws, mounts, protected, masked := classifyDisks(disks, "/workspace")

	if ws != (MountGrant{"/home/u/proj", "/workspace", false}) {
		t.Errorf("workspace = %+v", ws)
	}
	want := []MountGrant{
		{"/home/u/repo/.git", "/home/u/repo/.git", false},
		{"/data", "/mnt/data", true},
		{"/srv", "/srv", false},
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
	mgr := &fakeGrantsManager{disks: map[string]container.DiskDevice{
		"workspace":         {Source: "/home/u/proj", Path: "/workspace"},
		"mount-0":           {Source: "/home/u/.aws", Path: "/home/code/.aws"}, // dropped by trust, still attached
		"protect-git-hooks": {Source: "/home/u/proj/.git/hooks", Path: "/workspace/.git/hooks", Readonly: true},
	}}
	st := &setupState{
		opts: SetupOptions{
			WorkspacePath: "/home/u/proj",
			MountConfig:   &MountConfig{Mounts: []MountEntry{{HostPath: "/new", ContainerPath: "/new"}}},
			Security:      SecurityOptions{ProtectedPaths: []string{".git/hooks", ".git/config"}},
			Network: NetworkOptions{Config: &config.NetworkConfig{
				Mode:                    config.NetworkModeRestricted,
				AllowLocalNetworkAccess: boolPtr(true),
				BlockMetadataEndpoint:   boolPtr(true),
			}},
		},
		result:           &SetupResult{Manager: mgr},
		forwardedSockets: []SocketEntry{{HostPath: "/run/a.sock", ContainerPath: "/run/a.sock"}},
		contextInfo: tool.ContextInfo{
			WorkspacePath:    "/workspace",
			ForwardedEnvVars: []string{"GH_TOKEN"},
			ProfileContext:   "long profile text",
		},
	}
	g := buildGrants(st)

	if g.DevicesUnread {
		t.Fatal("devices were readable")
	}
	if len(g.Mounts) != 1 || g.Mounts[0].HostPath != "/home/u/.aws" {
		t.Errorf("mounts = %+v, want only the attached ~/.aws", g.Mounts)
	}
	if strings.Join(g.Protected, ",") != ".git/hooks" {
		t.Errorf("protected = %v, want only the mounted .git/hooks", g.Protected)
	}
	if len(g.Sockets) != 1 || strings.Join(g.Env.FromHost, ",") != "GH_TOKEN" {
		t.Errorf("sockets/env = %+v / %+v", g.Sockets, g.Env)
	}
	if g.Context.ProfileContext != "" {
		t.Error("the profile context text should not be carried in Grants")
	}
	if !g.LANAccess || g.LANBlocked || !g.MetadataBlock {
		t.Errorf("network flags = lan %v, blocked %v, metadata %v", g.LANAccess, g.LANBlocked, g.MetadataBlock)
	}
}

func TestBuildGrants_DevicesUnreadable(t *testing.T) {
	ws := t.TempDir()
	if err := os.MkdirAll(filepath.Join(ws, ".git", "hooks"), 0o755); err != nil {
		t.Fatal(err)
	}
	mgr := &fakeGrantsManager{disksErr: errors.New("incus down")}
	st := &setupState{
		opts: SetupOptions{
			WorkspacePath: ws,
			MountConfig:   &MountConfig{Mounts: []MountEntry{{HostPath: "/data", ContainerPath: "/data", Readonly: true}}},
			Security:      SecurityOptions{ProtectedPaths: []string{".git/hooks", ".husky"}},
		},
		result:      &SetupResult{Manager: mgr},
		contextInfo: tool.ContextInfo{WorkspacePath: "/workspace"},
	}
	g := buildGrants(st)

	if !g.DevicesUnread || len(g.Mounts) != 1 || strings.Join(g.Protected, ",") != ".git/hooks" {
		t.Fatalf("fallback grants = %+v", g)
	}
	out := g.Render()
	if !strings.Contains(out, "(could not read the container's devices; showing configured mounts)") {
		t.Errorf("fallback should be flagged:\n%s", out)
	}
}

// Credentials list what was copied this launch; when this launch copied none
// (a reused container), the destinations still in the container are listed as
// left from an earlier session.
func TestBuildGrants_Credentials(t *testing.T) {
	entries := []CredentialEntry{
		{HostPath: "/h/a", ContainerPath: ".a"},
		{HostPath: "/h/b", ContainerPath: "/etc/b"},
	}
	base := func(mgr *fakeGrantsManager) *setupState {
		return &setupState{
			opts:   SetupOptions{CredentialConfig: &CredentialConfig{Entries: entries}},
			result: &SetupResult{Manager: mgr, HomeDir: "/home/code"},
		}
	}

	t.Run("copied this launch", func(t *testing.T) {
		st := base(&fakeGrantsManager{disks: map[string]container.DiskDevice{}})
		st.credentialsSeeded = true
		st.copiedCredentials = []CredentialEntry{{HostPath: "/h/a", ContainerPath: "/home/code/.a"}}
		g := buildGrants(st)
		if len(g.Credentials) != 1 || g.Credentials[0] != (CredentialGrant{"/h/a", "/home/code/.a", false}) {
			t.Errorf("credentials = %+v", g.Credentials)
		}
	})

	t.Run("reused container", func(t *testing.T) {
		mgr := &fakeGrantsManager{disks: map[string]container.DiskDevice{}, probeOut: "/etc/b\n"}
		g := buildGrants(base(mgr))
		if len(g.Credentials) != 1 || g.Credentials[0] != (CredentialGrant{"/h/b", "/etc/b", true}) {
			t.Errorf("credentials = %+v", g.Credentials)
		}
		if got := mgr.probeArgs[len(mgr.probeArgs)-2:]; got[0] != "/home/code/.a" || got[1] != "/etc/b" {
			t.Errorf("probe paths = %v", got)
		}
		if out := g.Render(); !strings.Contains(out, "/h/b -> /etc/b (from an earlier session, not refreshed)") {
			t.Errorf("earlier credential not annotated:\n%s", out)
		}
	})
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
		},
		Protected: []string{".git/hooks", ".husky"},
		Masked:    []string{".env"},
		Sockets: []SocketEntry{
			{HostPath: "/run/user/1000/agent.sock", ContainerPath: "/tmp/ssh-agent.sock", EnvVar: "SSH_AUTH_SOCK"},
			{HostPath: "/run/broker.sock", ContainerPath: "/run/broker.sock"},
		},
		Credentials: []CredentialGrant{{HostPath: "/home/u/.aws/credentials", ContainerPath: "/home/code/.aws/credentials"}},
		Hosts:       []config.HostEntry{{IP: "192.168.1.50", Hostnames: []string{"nas"}, Ports: []int{443}}},
		Env: EnvGrants{
			FromHost:   []string{"GH_TOKEN"},
			Minted:     []string{"AWS_SESSION_TOKEN"},
			Configured: []string{"ANTHROPIC_API_KEY", "FOO"},
		},
		Context: tool.ContextInfo{
			NetworkMode:    "allowlist",
			AllowedDomains: []string{"github.com", "api.anthropic.com"},
			AllowedPorts:   []int{443},
			PublishedPorts: []tool.PortInfo{
				{Name: "web", HostPort: 41000, ContainerPort: 3000},
				{HostPort: 42000, ContainerPort: 42000, Pool: true},
			},
			RunAsRoot:         true,
			DockerUnavailable: true,
			CPULimit:          "2",
			MemoryLimit:       "4GiB",
			MaxDuration:       "2h",
		},
	}
	out := g.Render()
	for _, want := range []string{
		"Mounts       /data -> /mnt/data (read-only)\n",
		"             /cache -> /mnt/cache (read-write)\n",
		"Protected    .git/hooks, .husky (read-only)\n",
		"Masked       .env (hidden)\n",
		"Network      allowlist: github.com, api.anthropic.com\n",
		"             ports 443 only\n",
		"             host 192.168.1.50 (nas) on ports 443\n",
		"Ports        web: container 3000 -> host 127.0.0.1:41000\n",
		"             pool: 42000 (same number on host)\n",
		"Sockets      /run/user/1000/agent.sock -> /tmp/ssh-agent.sock (SSH_AUTH_SOCK)\n",
		"             /run/broker.sock -> /run/broker.sock\n",
		"Env          GH_TOKEN (from host)\n",
		"             AWS_SESSION_TOKEN (env_commands)\n",
		"             ANTHROPIC_API_KEY, FOO (set by config)\n",
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
		g       Grants
		want    []string
		notWant []string
	}{
		{
			name: "restricted, LAN and metadata blocked, DNS pinned",
			g: Grants{LANBlocked: true, MetadataBlock: true, Context: tool.ContextInfo{
				NetworkMode: "restricted", DNSServers: []string{"10.0.0.53"},
			}},
			want: []string{"restricted: internet (LAN blocked, metadata endpoint blocked)", "DNS pinned to 10.0.0.53"},
		},
		{
			name: "restricted, LAN access wins, metadata open",
			g:    Grants{LANAccess: true, LANBlocked: true, Context: tool.ContextInfo{NetworkMode: "restricted"}},
			want: []string{"restricted: internet (LAN allowed, metadata endpoint not blocked)"},
		},
		{
			name: "allowlist with LAN access opens metadata",
			g:    Grants{LANAccess: true, MetadataBlock: true, Context: tool.ContextInfo{NetworkMode: "allowlist"}},
			want: []string{"allowlist: nothing", "LAN allowed (metadata endpoint not blocked)"},
		},
		{
			name:    "allowlist never shows a DNS pin",
			g:       Grants{Context: tool.ContextInfo{NetworkMode: "allowlist", DNSServers: []string{"1.1.1.1"}}},
			notWant: []string{"DNS pinned"},
		},
		{
			name: "open lists hosts entries but no unenforced caps",
			g: Grants{Hosts: hosts, Context: tool.ContextInfo{
				NetworkMode: "open", AllowedPorts: []int{443}, DNSServers: []string{"1.1.1.1"},
			}},
			want:    []string{"open (no egress filtering)", "host 10.0.0.5 (db)\n"},
			notWant: []string{"ports 443", "DNS pinned", "on ports"},
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			out := tc.g.Render()
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
	g := &Grants{Env: EnvGrants{FromHost: []string{"A"}}}
	c := g.WithEnv(EnvGrants{Minted: []string{"B"}})
	if len(g.Env.Minted) != 0 || len(g.Env.FromHost) != 1 {
		t.Errorf("original changed: %+v", g.Env)
	}
	if len(c.Env.Minted) != 1 || len(c.Env.FromHost) != 0 {
		t.Errorf("copy = %+v", c.Env)
	}
}
