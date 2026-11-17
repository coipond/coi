package network

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
)

// Host veth records.
//
// A host veth that lost its bridge (Incus or the host died mid-teardown) looks
// the same whether coi's container or another tool (CNI, a manual netns pair)
// made it: the name is random hex either way. So coi records every host veth
// it sees for its own containers, one empty file per interface name, and
// `coi clean --orphans` only ever deletes recorded ones.

// hostVethRecordsDir is where the records live.
func hostVethRecordsDir() (string, error) {
	home, err := os.UserHomeDir()
	if err != nil {
		return "", err
	}
	return filepath.Join(home, ".coi", "veths"), nil
}

// validVethRecordName rejects names that are not a single path element.
func validVethRecordName(name string) bool {
	return name != "" && !strings.ContainsAny(name, "/.")
}

// recordHostVeth records veth as a coi container's host veth. Best-effort: a
// failed write only means `coi clean --orphans` will leave it alone. A new
// record also drops the records of interfaces that are gone, so the directory
// holds about one file per live veth.
func recordHostVeth(veth string) {
	if !validVethRecordName(veth) {
		return
	}
	dir, err := hostVethRecordsDir()
	if err != nil {
		return
	}
	path := filepath.Join(dir, veth)
	if _, err := os.Stat(path); err == nil {
		return
	}
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return
	}
	if err := os.WriteFile(path, nil, 0o600); err != nil {
		return
	}
	entries, err := os.ReadDir(dir)
	if err != nil {
		return
	}
	for _, e := range entries {
		if name := e.Name(); name != veth && !hostInterfaceExists(name) {
			_ = os.Remove(filepath.Join(dir, name))
		}
	}
}

// RecordedHostVeths returns the host veth names coi recorded for its
// containers, sorted. No records is not an error.
func RecordedHostVeths() ([]string, error) {
	dir, err := hostVethRecordsDir()
	if err != nil {
		return nil, err
	}
	entries, err := os.ReadDir(dir)
	if errors.Is(err, os.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	names := make([]string, 0, len(entries))
	for _, e := range entries {
		if validVethRecordName(e.Name()) {
			names = append(names, e.Name())
		}
	}
	return names, nil
}

// ForgetHostVeth drops the record of veth, if any.
func ForgetHostVeth(veth string) error {
	if !validVethRecordName(veth) {
		return nil
	}
	dir, err := hostVethRecordsDir()
	if err != nil {
		return err
	}
	if err := os.Remove(filepath.Join(dir, veth)); err != nil && !errors.Is(err, os.ErrNotExist) {
		return err
	}
	return nil
}
