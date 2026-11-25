package session

import (
	"encoding/json"

	"github.com/coipond/coi/internal/config"
)

// netAccess is whether the firewall lets traffic to a destination class
// through.
type netAccess string

const (
	netAllowed    netAccess = "allowed"     // allow_local_network_access
	netBlocked    netAccess = "blocked"     // rejected by the firewall
	netNotBlocked netAccess = "not_blocked" // reachable by default
)

func accessOf(a netAccess) *netAccess { return &a }

// effectiveNetwork is the egress the firewall enforces: fields a mode doesn't
// enforce are empty (null in JSON), so the text and JSON report show the same.
type effectiveNetwork struct {
	Mode             string        `json:"mode"`
	AllowedDomains   []string      `json:"allowed_domains"` // allowlist mode only
	LAN              *netAccess    `json:"lan"`
	MetadataEndpoint *netAccess    `json:"metadata_endpoint"`
	HostAccess       *bool         `json:"host_access"`
	AllowedPorts     []int         `json:"allowed_ports"`
	DNSServers       []string      `json:"dns_servers"` // restricted mode only
	Hosts            []grantedHost `json:"hosts"`
}

type grantedHost struct {
	IP        string   `json:"ip"`
	Hostnames []string `json:"hostnames"`
	Ports     []int    `json:"ports"` // nil when the mode doesn't enforce ports
}

// effective resolves what n's mode enforces. Allowlist mode keys its
// private handling off allow_local_network_access alone: with it off, LAN
// and metadata are rejected; with it on, the LAN is allowed and metadata is
// rejected only under block_metadata_endpoint. Open mode filters nothing but
// metadata, under block_metadata_endpoint. Port caps and DNS pins apply only
// in the modes whose firewall enforces them, as the sandbox context says.
func (n NetworkGrants) effective() effectiveNetwork {
	mode := config.NetworkMode(n.Mode)
	if mode == "" {
		mode = config.NetworkModeOpen
	}
	e := effectiveNetwork{Mode: string(mode), Hosts: []grantedHost{}}
	switch mode {
	case config.NetworkModeOpen:
		if n.Mode == "" {
			break // no network config: nothing known
		}
		e.MetadataEndpoint = accessOf(netNotBlocked)
		if n.MetadataBlock {
			e.MetadataEndpoint = accessOf(netBlocked)
		}
	case config.NetworkModeAllowlist:
		e.AllowedDomains = append([]string{}, n.AllowedDomains...)
		e.LAN, e.MetadataEndpoint = accessOf(netBlocked), accessOf(netBlocked)
		if n.LANAccess {
			e.LAN = accessOf(netAllowed)
			if !n.MetadataBlock {
				e.MetadataEndpoint = accessOf(netNotBlocked)
			}
		}
	case config.NetworkModeRestricted:
		switch {
		case n.LANAccess:
			e.LAN = accessOf(netAllowed)
		case n.LANBlocked:
			e.LAN = accessOf(netBlocked)
		default:
			e.LAN = accessOf(netNotBlocked)
		}
		e.MetadataEndpoint = accessOf(netNotBlocked)
		if n.MetadataBlock {
			e.MetadataEndpoint = accessOf(netBlocked)
		}
		if len(n.DNSServers) > 0 {
			e.DNSServers = n.DNSServers
		}
	}
	enforcing := mode == config.NetworkModeRestricted || mode == config.NetworkModeAllowlist
	if enforcing {
		e.HostAccess = &n.HostAccess
		if len(n.AllowedPorts) > 0 {
			e.AllowedPorts = n.AllowedPorts
		}
	}
	for _, h := range n.Hosts {
		gh := grantedHost{IP: h.IP, Hostnames: nonNil(h.Hostnames)}
		if enforcing && len(h.Ports) > 0 {
			gh.Ports = h.Ports
		}
		e.Hosts = append(e.Hosts, gh)
	}
	return e
}

// grantsJSON is the report as data, with the same content as Render: paths
// and names, never a value. Lists are [] when empty; null marks a setting the
// network mode does not enforce.
type grantsJSON struct {
	Workspace          *mountJSON       `json:"workspace"` // null: no workspace device
	Mounts             []mountJSON      `json:"mounts"`
	DevicesUnread      bool             `json:"devices_unread"`
	Protected          []string         `json:"protected"`
	Masked             []string         `json:"masked"`
	Network            effectiveNetwork `json:"network"`
	Ports              []portJSON       `json:"ports"`
	Sockets            []socketJSON     `json:"sockets"`
	Env                envJSON          `json:"env"`
	ToolFiles          []copiedJSON     `json:"tool_files"`
	Credentials        []copiedJSON     `json:"credentials"`
	LeftoversUnchecked bool             `json:"leftovers_unchecked"`
	Agent              agentJSON        `json:"agent"`
	Limits             []string         `json:"limits"`
	MaxDuration        string           `json:"max_duration,omitempty"`
}

type mountJSON struct {
	HostPath      string `json:"host_path,omitempty"`
	Pool          string `json:"pool,omitempty"`   // a storage-pool volume, instead of a host path
	Volume        string `json:"volume,omitempty"` // the volume's name in Pool
	ContainerPath string `json:"container_path"`
	Readonly      bool   `json:"readonly"`
}

type portJSON struct {
	Name          string `json:"name,omitempty"` // left out for a pool port, as the text does
	ContainerPort int    `json:"container_port"`
	HostPort      int    `json:"host_port"`
	Listen        string `json:"listen"`
	Pool          bool   `json:"pool"`
}

type socketJSON struct {
	HostPath      string `json:"host_path"`
	ContainerPath string `json:"container_path"`
	EnvVar        string `json:"env_var,omitempty"`
}

// envJSON names the variables by source, each once, as envSources does.
type envJSON struct {
	// Launch is "started", or "attached"/"sent_to_pane" when the running tool
	// keeps its env and only new panes get these names.
	Launch      string   `json:"launch"`
	Tool        []string `json:"tool"`
	FromHost    []string `json:"from_host"`
	EnvCommands []string `json:"env_commands"`
	Configured  []string `json:"configured"`
	Container   []string `json:"container"`
}

type copiedJSON struct {
	HostPath      string    `json:"host_path"`
	ContainerPath string    `json:"container_path"`
	State         copyState `json:"state"`
}

type agentJSON struct {
	RunAsRoot       bool   `json:"run_as_root"`
	DockerAvailable bool   `json:"docker_available"`
	DockerNote      string `json:"docker_note,omitempty"` // why it differs from config
}

var toolLaunchNames = map[ToolLaunch]string{
	ToolStarted:    "started",
	ToolAttached:   "attached",
	ToolSentToPane: "sent_to_pane",
}

// JSON is the report as one JSON object, for an orchestrator to record.
func (g *Grants) JSON() ([]byte, error) {
	out := grantsJSON{
		Mounts:             []mountJSON{},
		DevicesUnread:      g.DevicesUnread,
		Protected:          nonNil(g.Protected),
		Masked:             nonNil(g.Masked),
		Network:            g.Network.effective(),
		Ports:              []portJSON{},
		Sockets:            []socketJSON{},
		ToolFiles:          copiedOf(g.ToolFiles),
		Credentials:        copiedOf(g.Credentials),
		LeftoversUnchecked: g.LeftoversUnchecked,
		Agent: agentJSON{
			RunAsRoot:       g.RunAsRoot,
			DockerAvailable: !g.DockerUnavailable,
			DockerNote:      g.dockerNote(),
		},
		Limits:      nonNil(g.Limits),
		MaxDuration: g.MaxDuration,
	}
	if g.Workspace.HostPath != "" {
		ws := mountOf(g.Workspace)
		out.Workspace = &ws
	}
	for _, m := range g.Mounts {
		out.Mounts = append(out.Mounts, mountOf(m))
	}
	for _, p := range g.Ports {
		listen := p.Listen
		if listen == "" {
			listen = "127.0.0.1"
		}
		name := p.Name
		if p.Pool {
			name = ""
		}
		out.Ports = append(out.Ports, portJSON{Name: name, ContainerPort: p.ContainerPort, HostPort: p.HostPort, Listen: listen, Pool: p.Pool})
	}
	for _, s := range g.Sockets {
		out.Sockets = append(out.Sockets, socketJSON{HostPath: s.HostPath, ContainerPath: s.ContainerPath, EnvVar: s.EnvVar})
	}
	out.Env.Launch = toolLaunchNames[g.Env.Launch]
	for _, src := range g.envSources() {
		names := nonNil(src.names)
		switch src.kind {
		case envTool:
			out.Env.Tool = names
		case envFromHost:
			out.Env.FromHost = names
		case envMinted:
			out.Env.EnvCommands = names
		case envConfigured:
			out.Env.Configured = names
		case envContainer:
			out.Env.Container = names
		}
	}
	return json.Marshal(out)
}

func mountOf(m MountGrant) mountJSON {
	j := mountJSON{HostPath: m.HostPath, ContainerPath: m.ContainerPath, Readonly: m.Readonly}
	if m.Pool != "" {
		j.HostPath, j.Pool, j.Volume = "", m.Pool, m.HostPath
	}
	return j
}

func copiedOf(files []CredentialGrant) []copiedJSON {
	out := []copiedJSON{}
	for _, c := range files {
		out = append(out, copiedJSON{HostPath: c.HostPath, ContainerPath: c.ContainerPath, State: c.state()})
	}
	return out
}

func nonNil[T any](s []T) []T {
	if s == nil {
		return []T{}
	}
	return s
}
