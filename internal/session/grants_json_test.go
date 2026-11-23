package session

import (
	"encoding/json"
	"reflect"
	"strings"
	"testing"

	"github.com/coipond/coi/internal/config"
	"github.com/coipond/coi/internal/container"
	"github.com/coipond/coi/internal/tool"
)

// fullGrants fills every report section, with each copy state, a deduped env
// name and a Docker config mismatch.
func fullGrants() *Grants {
	return (&Grants{
		Workspace: MountGrant{HostPath: "/home/u/proj", ContainerPath: "/workspace"},
		Mounts: []MountGrant{
			{HostPath: "/data", ContainerPath: "/mnt/data", Readonly: true},
			{HostPath: "shared", ContainerPath: "/shared", Pool: "default"},
		},
		Protected: []string{".git/hooks", ".husky"},
		Masked:    []string{".env"},
		Sockets: []SocketEntry{
			{HostPath: "/run/user/1000/agent.sock", ContainerPath: "/tmp/ssh-agent.sock", EnvVar: "SSH_AUTH_SOCK", DeviceName: "ssh-agent"},
			{HostPath: "/run/broker.sock", ContainerPath: "/run/broker.sock"},
		},
		Credentials: []CredentialGrant{
			{HostPath: "/home/u/.aws/credentials", ContainerPath: "/home/code/.aws/credentials"},
			{HostPath: "/home/u/.npmrc", ContainerPath: "/home/code/.npmrc", Earlier: true},
			{HostPath: "/home/u/.netrc", ContainerPath: "/home/code/.netrc", Earlier: true, Changed: true},
			{HostPath: "/home/u/.pypirc", ContainerPath: "/home/code/.pypirc", Earlier: true, Unverified: true},
		},
		ToolFiles: []CredentialGrant{
			{HostPath: "/home/u/.claude/.credentials.json", ContainerPath: "/home/code/.claude/.credentials.json", Restored: true},
		},
		LeftoversUnchecked: true,
		Env: EnvGrants{
			Tool:      []string{"ANTHROPIC_MODEL"},
			Container: []string{"GIT_AUTHOR_NAME", "GH_TOKEN"},
		},
		Network: NetworkGrants{
			Mode:           "allowlist",
			AllowedDomains: []string{"github.com", "api.anthropic.com"},
			AllowedPorts:   []int{443},
			DNSServers:     []string{"1.1.1.1"},
			Hosts:          []config.HostEntry{{IP: "192.168.1.50", Hostnames: []string{"nas"}, Ports: []int{443}}},
			HostAccess:     true,
		},
		Ports: []tool.PortInfo{
			{Name: "web", HostPort: 41000, ContainerPort: 3000, EnvVar: "COI_PORT_WEB"},
			{Name: "api", HostPort: 41001, ContainerPort: 8080, Listen: "0.0.0.0"},
			{Name: "pool-1", HostPort: 42000, ContainerPort: 42000, Pool: true}, // as ResolvePorts names it
		},
		RunAsRoot:           true,
		DockerUnavailable:   true,
		DockerConfigDiffers: true,
		DockerSource:        dockerSourceInstance,
		Limits:              []string{"cpu 2", "memory 4GiB"},
		MaxDuration:         "2h",
	}).WithEnv(EnvGrants{FromHost: []string{"GH_TOKEN"}, Minted: []string{"AWS_SESSION_TOKEN"}, Configured: []string{"ANTHROPIC_MODEL", "FOO"}}, ToolAttached)
}

// Render gives exactly this text, byte for byte.
func TestGrantsRender_Golden(t *testing.T) {
	cases := []struct {
		name string
		g    *Grants
		want string
	}{
		{
			name: "every section",
			g:    fullGrants(),
			want: `Effective grants:
  Workspace    /home/u/proj -> /workspace (read-write)
  Mounts       /data -> /mnt/data (read-only)
               volume default/shared -> /shared (read-write)
  Protected    .git/hooks, .husky (read-only)
  Masked       .env (hidden)
  Network      allowlist: github.com, api.anthropic.com
               LAN and metadata endpoint blocked
               host services allowed (allow_host_access)
               ports 443 only
               host 192.168.1.50 (nas) on ports 443
  Ports        web: container 3000 -> host 127.0.0.1:41000
               api: container 8080 -> host 0.0.0.0:41001
               pool: 42000 (same number on host)
  Sockets      /run/user/1000/agent.sock -> /tmp/ssh-agent.sock (SSH_AUTH_SOCK)
               /run/broker.sock -> /run/broker.sock
  Env          the running tool keeps the env it started with; new panes get:
               ANTHROPIC_MODEL (tool settings)
               GH_TOKEN (from host)
               AWS_SESSION_TOKEN (env_commands)
               FOO (set by config)
               GIT_AUTHOR_NAME (container environment)
  Tool config  /home/u/.claude/.credentials.json -> /home/code/.claude/.credentials.json (restored from the saved session)
  Credentials  /home/u/.aws/credentials -> /home/code/.aws/credentials
               /home/u/.npmrc -> /home/code/.npmrc (already in the container, not copied this launch)
               /home/u/.netrc -> /home/code/.netrc (copied by an earlier session, since changed in the container)
               /home/u/.pypirc -> /home/code/.pypirc (in the container; it predates coi recording copies, so it may not be from the host)
               (could not check the container for files copied by earlier sessions)
  Agent        runs as root, Docker unavailable (config enables it; restart the container to apply)
  Limits       cpu 2, memory 4GiB, max duration 2h
`,
		},
		{
			name: "bare session",
			g:    &Grants{DevicesUnread: true},
			want: `Effective grants:
  Workspace  none
  Mounts     none
             (could not read the container's devices; showing what config asks for)
  Protected  none
  Network    open (no egress filtering)
  Sockets    none
  Env        none
  Agent      runs as non-root, Docker available
`,
		},
		{
			name: "restricted network",
			g: &Grants{
				Workspace: MountGrant{HostPath: "/p", ContainerPath: "/workspace", Readonly: true},
				Network: NetworkGrants{
					Mode: "restricted", LANBlocked: true, MetadataBlock: true, AllowedPorts: []int{80, 443},
					DNSServers: []string{"10.0.0.53"}, Hosts: []config.HostEntry{{IP: "10.0.0.5", Ports: []int{5432}}},
				},
				DockerConfigDiffers: true,
				DockerSource:        dockerSourceProfile,
			},
			want: `Effective grants:
  Workspace  /p -> /workspace (read-only)
  Mounts     none
  Protected  none
  Network    restricted: internet (LAN blocked, metadata endpoint blocked)
             ports 80, 443 only
             DNS pinned to 10.0.0.53
             host 10.0.0.5 on ports 5432
  Sockets    none
  Env        none
  Agent      runs as non-root, Docker available (an Incus profile enables nesting; config disables Docker)
`,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := tc.g.Render(); got != tc.want {
				t.Errorf("Render() =\n%s\nwant:\n%s", got, tc.want)
			}
		})
	}
}

// sameJSON reports whether got and want hold the same JSON value.
func sameJSON(t *testing.T, got []byte, want string) {
	t.Helper()
	var g, w any
	if err := json.Unmarshal(got, &g); err != nil {
		t.Fatalf("invalid JSON %s: %v", got, err)
	}
	if err := json.Unmarshal([]byte(want), &w); err != nil {
		t.Fatalf("invalid want: %v", err)
	}
	if !reflect.DeepEqual(g, w) {
		t.Errorf("JSON =\n%s\nwant:\n%s", got, want)
	}
}

func TestGrantsJSON_EverySection(t *testing.T) {
	got, err := fullGrants().JSON()
	if err != nil {
		t.Fatal(err)
	}
	sameJSON(t, got, `{
		"workspace": {"host_path": "/home/u/proj", "container_path": "/workspace", "readonly": false},
		"mounts": [
			{"host_path": "/data", "container_path": "/mnt/data", "readonly": true},
			{"pool": "default", "volume": "shared", "container_path": "/shared", "readonly": false}
		],
		"devices_unread": false,
		"protected": [".git/hooks", ".husky"],
		"masked": [".env"],
		"network": {
			"mode": "allowlist",
			"allowed_domains": ["github.com", "api.anthropic.com"],
			"lan": "blocked",
			"metadata_endpoint": "blocked",
			"host_access": true,
			"allowed_ports": [443],
			"dns_servers": null,
			"hosts": [{"ip": "192.168.1.50", "hostnames": ["nas"], "ports": [443]}]
		},
		"ports": [
			{"name": "web", "container_port": 3000, "host_port": 41000, "listen": "127.0.0.1", "pool": false},
			{"name": "api", "container_port": 8080, "host_port": 41001, "listen": "0.0.0.0", "pool": false},
			{"container_port": 42000, "host_port": 42000, "listen": "127.0.0.1", "pool": true}
		],
		"sockets": [
			{"host_path": "/run/user/1000/agent.sock", "container_path": "/tmp/ssh-agent.sock", "env_var": "SSH_AUTH_SOCK"},
			{"host_path": "/run/broker.sock", "container_path": "/run/broker.sock"}
		],
		"env": {
			"launch": "attached",
			"tool": ["ANTHROPIC_MODEL"],
			"from_host": ["GH_TOKEN"],
			"env_commands": ["AWS_SESSION_TOKEN"],
			"configured": ["FOO"],
			"container": ["GIT_AUTHOR_NAME"]
		},
		"tool_files": [
			{"host_path": "/home/u/.claude/.credentials.json", "container_path": "/home/code/.claude/.credentials.json", "state": "restored"}
		],
		"credentials": [
			{"host_path": "/home/u/.aws/credentials", "container_path": "/home/code/.aws/credentials", "state": "copied"},
			{"host_path": "/home/u/.npmrc", "container_path": "/home/code/.npmrc", "state": "earlier"},
			{"host_path": "/home/u/.netrc", "container_path": "/home/code/.netrc", "state": "changed"},
			{"host_path": "/home/u/.pypirc", "container_path": "/home/code/.pypirc", "state": "unverified"}
		],
		"leftovers_unchecked": true,
		"agent": {"run_as_root": true, "docker_available": false, "docker_note": "config enables it; restart the container to apply"},
		"limits": ["cpu 2", "memory 4GiB"],
		"max_duration": "2h"
	}`)
}

// The JSON twin of the golden bare session: no workspace device is null,
// empty sections are [].
func TestGrantsJSON_BareSession(t *testing.T) {
	got, err := (&Grants{DevicesUnread: true}).JSON()
	if err != nil {
		t.Fatal(err)
	}
	sameJSON(t, got, `{
		"workspace": null,
		"mounts": [],
		"devices_unread": true,
		"protected": [],
		"masked": [],
		"network": {"mode": "open", "allowed_domains": null, "lan": null, "metadata_endpoint": null,
			"host_access": null, "allowed_ports": null, "dns_servers": null, "hosts": []},
		"ports": [],
		"sockets": [],
		"env": {"launch": "started", "tool": [], "from_host": [], "env_commands": [], "configured": [], "container": []},
		"tool_files": [],
		"credentials": [],
		"leftovers_unchecked": false,
		"agent": {"run_as_root": false, "docker_available": true},
		"limits": []
	}`)
}

// Empty sections are [], and network settings the mode doesn't enforce are
// null, as the text report leaves them out.
func TestGrantsJSON_Network(t *testing.T) {
	hosts := []config.HostEntry{{IP: "10.0.0.5", Ports: []int{5432}}}
	cases := []struct {
		name string
		n    NetworkGrants
		want string
	}{
		{
			name: "open enforces no caps",
			n:    NetworkGrants{Hosts: hosts, AllowedPorts: []int{443}, DNSServers: []string{"1.1.1.1"}, HostAccess: true, LANBlocked: true},
			want: `{"mode": "open", "allowed_domains": null, "lan": null, "metadata_endpoint": null, "host_access": null, "allowed_ports": null, "dns_servers": null,
				"hosts": [{"ip": "10.0.0.5", "hostnames": [], "ports": null}]}`,
		},
		{
			name: "open with metadata block",
			n:    NetworkGrants{Mode: "open", MetadataBlock: true},
			want: `{"mode": "open", "allowed_domains": null, "lan": null, "metadata_endpoint": "blocked", "host_access": null, "allowed_ports": null, "dns_servers": null,
				"hosts": []}`,
		},
		{
			name: "explicit open without metadata block",
			n:    NetworkGrants{Mode: "open"},
			want: `{"mode": "open", "allowed_domains": null, "lan": null, "metadata_endpoint": "not_blocked", "host_access": null, "allowed_ports": null, "dns_servers": null,
				"hosts": []}`,
		},
		{
			name: "restricted pins DNS",
			n:    NetworkGrants{Mode: "restricted", LANAccess: true, MetadataBlock: true, DNSServers: []string{"10.0.0.53"}},
			want: `{"mode": "restricted", "allowed_domains": null, "lan": "allowed", "metadata_endpoint": "blocked",
				"host_access": false, "allowed_ports": null, "dns_servers": ["10.0.0.53"], "hosts": []}`,
		},
		{
			name: "restricted with no blocks",
			n:    NetworkGrants{Mode: "restricted"},
			want: `{"mode": "restricted", "allowed_domains": null, "lan": "not_blocked", "metadata_endpoint": "not_blocked",
				"host_access": false, "allowed_ports": null, "dns_servers": null, "hosts": []}`,
		},
		{
			name: "allowlist of nothing with LAN access",
			n:    NetworkGrants{Mode: "allowlist", LANAccess: true, DNSServers: []string{"1.1.1.1"}},
			want: `{"mode": "allowlist", "allowed_domains": [], "lan": "allowed", "metadata_endpoint": "not_blocked",
				"host_access": false, "allowed_ports": null, "dns_servers": null, "hosts": []}`,
		},
		{
			name: "allowlist with LAN access and metadata block",
			n:    NetworkGrants{Mode: "allowlist", LANAccess: true, MetadataBlock: true},
			want: `{"mode": "allowlist", "allowed_domains": [], "lan": "allowed", "metadata_endpoint": "blocked",
				"host_access": false, "allowed_ports": null, "dns_servers": null, "hosts": []}`,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, err := (&Grants{Network: tc.n}).JSON()
			if err != nil {
				t.Fatal(err)
			}
			var out struct{ Network json.RawMessage }
			if err := json.Unmarshal(got, &out); err != nil {
				t.Fatal(err)
			}
			sameJSON(t, out.Network, tc.want)
		})
	}
}

// secretEnvTool sets a variable whose value is a secret.
type secretEnvTool struct{ tool.Tool }

func (secretEnvTool) GetContainerEnv(string) map[string]string {
	return map[string]string{"API_KEY": "s3cr3t-value"}
}

// Both forms name a variable without its value.
func TestGrants_NamesNotValues(t *testing.T) {
	st := &setupState{
		opts:        SetupOptions{Tool: secretEnvTool{}},
		result:      &SetupResult{Manager: &fakeGrantsManager{disks: map[string]container.DiskDevice{}, envNames: []string{"GIT_TOKEN"}}},
		contextInfo: tool.ContextInfo{WorkspacePath: "/workspace"},
	}
	g := buildGrants(st)
	j, err := g.JSON()
	if err != nil {
		t.Fatal(err)
	}
	for name, out := range map[string]string{"text": g.Render(), "json": string(j)} {
		if !strings.Contains(out, "API_KEY") || !strings.Contains(out, "GIT_TOKEN") {
			t.Errorf("%s misses a variable name:\n%s", name, out)
		}
		if strings.Contains(out, "s3cr3t-value") {
			t.Errorf("%s shows a value:\n%s", name, out)
		}
	}
}
