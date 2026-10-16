package container

import (
	"encoding/csv"
	"fmt"
	"regexp"
	"strings"
)

// InstanceState is a container's existence, run state and eth0 IPv4 address,
// as reported by one `incus list`.
type InstanceState struct {
	Exists  bool
	Running bool
	// IPv4 is eth0's address; empty when the container is stopped or has no
	// DHCP lease yet.
	IPv4 string
}

// State answers Exists, Running and the eth0 IPv4 address with a single CSV
// `incus list`.
func (m *Manager) State() (InstanceState, error) {
	output, err := IncusOutput("list", "^"+regexp.QuoteMeta(m.ContainerName)+"$", "--format=csv", "--columns=ns4")
	if err != nil {
		return InstanceState{}, err
	}
	return parseInstanceStateCSV(output, m.ContainerName)
}

// parseInstanceStateCSV parses `incus list --format=csv --columns=ns4` output.
// The IPv4 column holds one "<address> (<interface>)" entry per line, inside a
// quoted field when there are several.
func parseInstanceStateCSV(output, containerName string) (InstanceState, error) {
	r := csv.NewReader(strings.NewReader(output))
	r.FieldsPerRecord = -1
	records, err := r.ReadAll()
	if err != nil {
		return InstanceState{}, fmt.Errorf("failed to parse instance list: %w", err)
	}
	for _, rec := range records {
		if len(rec) < 2 || rec[0] != containerName {
			continue
		}
		state := InstanceState{Exists: true, Running: StatusIsRunning(rec[1])}
		if len(rec) > 2 {
			state.IPv4 = eth0Address(rec[2])
		}
		return state, nil
	}
	return InstanceState{}, nil
}

func eth0Address(field string) string {
	for _, line := range strings.Split(field, "\n") {
		addr, iface, ok := strings.Cut(strings.TrimSpace(line), " ")
		if ok && strings.TrimSpace(iface) == "(eth0)" {
			return addr
		}
	}
	return ""
}
