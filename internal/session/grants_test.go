package session

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/coipond/coi/internal/config"
	"github.com/coipond/coi/internal/tool"
)

// A bare session states every core grant category, with "none" for absent
// ones, and omits the optional rows (ports, credentials, limits).
func TestGrantsRender_Minimal(t *testing.T) {
	g := &Grants{
		WorkspaceHost: "/home/u/proj",
		Context:       tool.ContextInfo{WorkspacePath: "/workspace"},
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
	for _, absent := range []string{"Ports", "Credentials", "Limits"} {
		if strings.Contains(out, absent) {
			t.Errorf("unexpected %q row in:\n%s", absent, out)
		}
	}
}

func TestGrantsRender_Full(t *testing.T) {
	ws := t.TempDir()
	if err := os.MkdirAll(filepath.Join(ws, ".git", "hooks"), 0o755); err != nil {
		t.Fatal(err)
	}
	g := &Grants{
		WorkspaceHost: ws,
		Mounts: []MountEntry{
			{HostPath: "/data", ContainerPath: "/mnt/data", Readonly: true},
			{HostPath: "/cache", ContainerPath: "/mnt/cache"},
		},
		Sockets: []SocketEntry{
			{HostPath: "/run/user/1000/agent.sock", ContainerPath: "/tmp/ssh-agent.sock", EnvVar: "SSH_AUTH_SOCK"},
			{HostPath: "/run/broker.sock", ContainerPath: "/run/broker.sock"},
		},
		Credentials: []CredentialEntry{
			{HostPath: "/home/u/.aws/credentials", ContainerPath: ".aws/credentials"},
		},
		Hosts:       []config.HostEntry{{IP: "192.168.1.50", Hostnames: []string{"nas"}, Ports: []int{443}}},
		EnvCommands: []string{"AWS_SESSION_TOKEN"},
		Context: tool.ContextInfo{
			WorkspacePath:    "/workspace",
			HomeDir:          "/home/code",
			NetworkMode:      "allowlist",
			AllowedDomains:   []string{"github.com", "api.anthropic.com"},
			AllowedPorts:     []int{443},
			ProtectedPaths:   []string{".git/hooks", ".husky"}, // .husky absent -> not listed
			ForwardedEnvVars: []string{"GH_TOKEN"},
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
		"Protected    .git/hooks (read-only)\n",
		"Network      allowlist: github.com, api.anthropic.com\n",
		"             ports 443 only\n",
		"             host 192.168.1.50 (nas) on ports 443\n",
		"Ports        web: container 3000 -> host 127.0.0.1:41000\n",
		"             pool: 42000 (same number on host)\n",
		"Sockets      /run/user/1000/agent.sock -> /tmp/ssh-agent.sock (SSH_AUTH_SOCK)\n",
		"             /run/broker.sock -> /run/broker.sock\n",
		"Env          GH_TOKEN (from host)\n",
		"             AWS_SESSION_TOKEN (env_commands)\n",
		"Credentials  /home/u/.aws/credentials -> /home/code/.aws/credentials\n",
		"Agent        runs as root, Docker unavailable\n",
		"Limits       cpu 2, memory 4GiB, max duration 2h\n",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("missing %q in:\n%s", want, out)
		}
	}
	if strings.Contains(out, ".husky") {
		t.Errorf("protected path absent from the workspace should not be listed:\n%s", out)
	}
}

func TestGrantsRender_RestrictedNetwork(t *testing.T) {
	cases := []struct {
		name string
		g    Grants
		want string
	}{
		{
			"lan blocked",
			Grants{LANBlocked: true, MetadataBlock: true},
			"restricted: internet (LAN blocked, metadata endpoint blocked)",
		},
		{
			"lan allowed wins",
			Grants{LANAccess: true, LANBlocked: true},
			"restricted: internet (LAN allowed)",
		},
		{"neither", Grants{}, "restricted: internet (LAN not blocked)"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			tc.g.Context = tool.ContextInfo{NetworkMode: "restricted", DNSServers: []string{"10.0.0.53"}}
			out := tc.g.Render()
			if !strings.Contains(out, tc.want) {
				t.Errorf("missing %q in:\n%s", tc.want, out)
			}
			if !strings.Contains(out, "DNS pinned to 10.0.0.53") {
				t.Errorf("missing DNS pin in:\n%s", out)
			}
		})
	}
}

func TestGrantsRender_EmptyAllowlist(t *testing.T) {
	g := &Grants{Context: tool.ContextInfo{NetworkMode: "allowlist"}}
	if out := g.Render(); !strings.Contains(out, "allowlist: nothing") {
		t.Errorf("empty allowlist should say so:\n%s", out)
	}
}

// buildGrants reports what was granted: trust-gated mounts from opts, the
// forwarded sockets it is handed, and only credentials whose host file exists.
func TestBuildGrants(t *testing.T) {
	dir := t.TempDir()
	present := filepath.Join(dir, "present")
	if err := os.WriteFile(present, []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	opts := SetupOptions{
		WorkspacePath: "/home/u/proj",
		MountConfig:   &MountConfig{Mounts: []MountEntry{{HostPath: "/data", ContainerPath: "/data"}}},
		CredentialConfig: &CredentialConfig{Entries: []CredentialEntry{
			{HostPath: present, ContainerPath: ".present"},
			{HostPath: filepath.Join(dir, "missing"), ContainerPath: ".missing"},
		}},
		Network: NetworkOptions{Config: &config.NetworkConfig{
			Mode:                    config.NetworkModeRestricted,
			AllowLocalNetworkAccess: boolPtr(true),
			BlockMetadataEndpoint:   boolPtr(true),
		}},
		Context: ContextOptions{ForwardedEnvVars: []string{"GH_TOKEN"}},
	}
	sockets := []SocketEntry{{HostPath: "/run/a.sock", ContainerPath: "/run/a.sock"}}
	g := buildGrants(&SetupResult{ContainerWorkspacePath: "/workspace"}, opts, sockets)

	if g.WorkspaceHost != "/home/u/proj" || g.Context.WorkspacePath != "/workspace" {
		t.Errorf("workspace = %q -> %q", g.WorkspaceHost, g.Context.WorkspacePath)
	}
	if len(g.Mounts) != 1 || len(g.Sockets) != 1 {
		t.Errorf("mounts/sockets = %d/%d, want 1/1", len(g.Mounts), len(g.Sockets))
	}
	if len(g.Credentials) != 1 || g.Credentials[0].HostPath != present {
		t.Errorf("credentials = %+v, want only the present file", g.Credentials)
	}
	if !g.LANAccess || g.LANBlocked || !g.MetadataBlock {
		t.Errorf("network flags = lan %v, blocked %v, metadata %v", g.LANAccess, g.LANBlocked, g.MetadataBlock)
	}
	if g.Context.NetworkMode != "restricted" || len(g.Context.ForwardedEnvVars) != 1 {
		t.Errorf("context = %+v", g.Context)
	}
}

func TestSortedKeys(t *testing.T) {
	got := SortedKeys(map[string]string{"B": "1", "A": "2"})
	if strings.Join(got, ",") != "A,B" {
		t.Errorf("SortedKeys = %v", got)
	}
}
