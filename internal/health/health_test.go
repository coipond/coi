package health

import (
	"reflect"
	"sort"
	"testing"

	"github.com/mensfeld/coi/internal/config"
)

// TestCollectReferencedPools walks through the scenarios that the storage
// pool health check must cover. It uses already-resolved in-memory Config
// values (i.e. what collectReferencedPools actually sees after
// ResolveProfileInheritance has run) so it exercises the enumeration logic
// directly without dragging in TOML loading.
func TestCollectReferencedPools(t *testing.T) {
	tests := []struct {
		name     string
		cfg      *config.Config
		expected []string
	}{
		{
			name: "global only, empty",
			cfg: &config.Config{
				Container: config.ContainerConfig{StoragePool: ""},
				Profiles:  map[string]config.ProfileConfig{},
			},
			expected: []string{""},
		},
		{
			name: "global set, no profiles",
			cfg: &config.Config{
				Container: config.ContainerConfig{StoragePool: "nvme"},
				Profiles:  map[string]config.ProfileConfig{},
			},
			expected: []string{"nvme"},
		},
		{
			name: "global empty + one profile with explicit pool",
			cfg: &config.Config{
				Container: config.ContainerConfig{StoragePool: ""},
				Profiles: map[string]config.ProfileConfig{
					"rust": {Container: config.ContainerConfig{StoragePool: "fast"}},
				},
			},
			expected: []string{"", "fast"},
		},
		{
			name: "two profiles with distinct pools",
			cfg: &config.Config{
				Container: config.ContainerConfig{StoragePool: "nvme"},
				Profiles: map[string]config.ProfileConfig{
					"a": {Container: config.ContainerConfig{StoragePool: "fast"}},
					"b": {Container: config.ContainerConfig{StoragePool: "slow"}},
				},
			},
			expected: []string{"nvme", "fast", "slow"},
		},
		{
			name: "child profile inheriting parent's pool (post-resolution state)",
			cfg: &config.Config{
				Container: config.ContainerConfig{StoragePool: ""},
				Profiles: map[string]config.ProfileConfig{
					"parent": {Container: config.ContainerConfig{StoragePool: "fast"}},
					"child":  {Inherits: "parent", Container: config.ContainerConfig{StoragePool: "fast"}},
				},
			},
			expected: []string{"", "fast"}, // deduped
		},
		{
			name: "child overriding parent's pool",
			cfg: &config.Config{
				Container: config.ContainerConfig{StoragePool: ""},
				Profiles: map[string]config.ProfileConfig{
					"parent": {Container: config.ContainerConfig{StoragePool: "fast"}},
					"child":  {Inherits: "parent", Container: config.ContainerConfig{StoragePool: "slow"}},
				},
			},
			expected: []string{"", "fast", "slow"},
		},
		{
			name: "profile with no container section — falls back to global at runtime",
			cfg: &config.Config{
				Container: config.ContainerConfig{StoragePool: "nvme"},
				Profiles: map[string]config.ProfileConfig{
					"bare": {},
				},
			},
			expected: []string{"nvme"},
		},
		{
			name: "dedup across profile and global",
			cfg: &config.Config{
				Container: config.ContainerConfig{StoragePool: "fast"},
				Profiles: map[string]config.ProfileConfig{
					"a": {Container: config.ContainerConfig{StoragePool: "fast"}},
				},
			},
			expected: []string{"fast"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := collectReferencedPools(tt.cfg)
			// cfg.Profiles is a Go map, so iteration order is random.
			// Compare as sorted sets.
			sort.Strings(got)
			want := append([]string(nil), tt.expected...)
			sort.Strings(want)
			if !reflect.DeepEqual(got, want) {
				t.Errorf("collectReferencedPools:\n got  %v\n want %v", got, want)
			}
		})
	}
}

// TestCollectReferencedPools_WithInheritance exercises the full
// load-time inheritance resolution path. This is the key regression test:
// if a future change to mergeProfiles or ResolveProfileInheritance breaks
// the "child inherits parent's pool" guarantee, the enumeration would
// silently miss the parent's pool and this test would catch it.
func TestCollectReferencedPools_WithInheritance(t *testing.T) {
	cfg := &config.Config{
		Container: config.ContainerConfig{StoragePool: ""},
		Profiles: map[string]config.ProfileConfig{
			"parent": {Container: config.ContainerConfig{StoragePool: "fast"}},
			// Child has NO container section at all — must inherit from parent.
			"child": {Inherits: "parent"},
		},
	}

	if err := cfg.ResolveProfileInheritance(); err != nil {
		t.Fatalf("ResolveProfileInheritance: %v", err)
	}

	pools := collectReferencedPools(cfg)
	sort.Strings(pools)

	want := []string{"", "fast"}
	sort.Strings(want)

	if !reflect.DeepEqual(pools, want) {
		t.Errorf("expected %v, got %v", want, pools)
	}
}
