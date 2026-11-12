package config

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestPortsValidation(t *testing.T) {
	valid := func(p *PortsConfig) error {
		prof := ProfileConfig{Ports: p}
		return prof.Validate("test")
	}

	if err := valid(&PortsConfig{Pool: 5, Map: []PortEntry{{Name: "web", Container: 3000}}}); err != nil {
		t.Errorf("valid ports config rejected: %v", err)
	}
	if err := valid(&PortsConfig{Pool: 11}); err == nil || !strings.Contains(err.Error(), "pool must be 0-10") {
		t.Errorf("pool > 10 should be rejected, got: %v", err)
	}
	if err := valid(&PortsConfig{Map: []PortEntry{{Container: 3000}}}); err == nil || !strings.Contains(err.Error(), "missing 'name'") {
		t.Errorf("missing name should be rejected, got: %v", err)
	}
	if err := valid(&PortsConfig{Map: []PortEntry{
		{Name: "web", Container: 3000},
		{Name: "web", Container: 4000},
	}}); err == nil || !strings.Contains(err.Error(), "duplicates name") {
		t.Errorf("duplicate names should be rejected, got: %v", err)
	}
	if err := valid(&PortsConfig{Map: []PortEntry{{Name: "web", Container: 0}}}); err == nil {
		t.Error("container port 0 should be rejected")
	}
	if err := valid(&PortsConfig{Map: []PortEntry{{Name: "web", Container: 3000, Host: 70000}}}); err == nil {
		t.Error("out-of-range host pin should be rejected")
	}
	if err := valid(&PortsConfig{Map: []PortEntry{{Name: "web", Container: 3000, Listen: "not-an-ip"}}}); err == nil {
		t.Error("non-IP listen address should be rejected")
	}
}

func TestMergePortsInto(t *testing.T) {
	dst := PortsConfig{Pool: 2, Map: []PortEntry{{Name: "a", Container: 1000}}}
	src := PortsConfig{Pool: 5, Map: []PortEntry{{Name: "b", Container: 2000}}}
	mergePortsInto(&dst, &src)
	if dst.Pool != 5 {
		t.Errorf("non-zero src pool should win, got %d", dst.Pool)
	}
	if len(dst.Map) != 2 {
		t.Errorf("new-name map entries should append, got %d", len(dst.Map))
	}

	// Zero src pool leaves dst pool alone
	dst2 := PortsConfig{Pool: 3}
	mergePortsInto(&dst2, &PortsConfig{Map: []PortEntry{{Name: "c", Container: 3000}}})
	if dst2.Pool != 3 {
		t.Errorf("zero src pool must not clobber, got %d", dst2.Pool)
	}

	// Untrusted pool provenance follows the overlaying source
	dst3 := PortsConfig{}
	mergePortsInto(&dst3, &PortsConfig{Pool: 4, PoolUntrusted: true, PoolSourcePath: "/repo/.coi/config.toml"})
	if !dst3.PoolUntrusted || dst3.PoolSourcePath != "/repo/.coi/config.toml" {
		t.Error("pool untrusted provenance must carry through merge")
	}
}

func TestMergePortsIntoReplacesByName(t *testing.T) {
	// A later scope overriding an existing name must replace, not duplicate —
	// otherwise re-applying the synthesized default profile doubles every
	// entry and the duplicate device name clobbers the first at publish.
	dst := PortsConfig{Map: []PortEntry{{Name: "web", Container: 3000}, {Name: "db", Container: 5432}}}
	mergePortsInto(&dst, &PortsConfig{Map: []PortEntry{{Name: "web", Container: 4000}}})
	if len(dst.Map) != 2 {
		t.Fatalf("same-name entry must replace, got %d entries", len(dst.Map))
	}
	if dst.Map[0].Container != 4000 {
		t.Errorf("replacement must take the overlaying values, got container %d", dst.Map[0].Container)
	}

	// Re-applying a clone of the merged section (the default-profile case)
	// must be a no-op.
	clone := clonePortsConfig(&dst)
	mergePortsInto(&dst, clone)
	if len(dst.Map) != 2 {
		t.Errorf("re-applying a clone must not duplicate entries, got %d", len(dst.Map))
	}
}

func TestMergePortsIntoPoolProvenance(t *testing.T) {
	// Untrusted overlay over a trusted pool: remember the trusted value so
	// the trust gate can restore it instead of dropping the pool to zero.
	dst := PortsConfig{Pool: 3}
	mergePortsInto(&dst, &PortsConfig{Pool: 5, PoolUntrusted: true, PoolSourcePath: "/repo/.coi/config.toml"})
	if dst.Pool != 5 || !dst.PoolUntrusted {
		t.Errorf("untrusted overlay should win pending the gate, got pool=%d untrusted=%v", dst.Pool, dst.PoolUntrusted)
	}
	if dst.PoolTrustedFallback != 3 {
		t.Errorf("trusted value must be remembered as fallback, got %d", dst.PoolTrustedFallback)
	}

	// A TRUSTED source winning afterwards (profile applied after the project
	// overlay) must clear the untrusted flags — the user's own explicit pool
	// must not stay gated under the repo's source path.
	mergePortsInto(&dst, &PortsConfig{Pool: 4})
	if dst.Pool != 4 || dst.PoolUntrusted || dst.PoolSourcePath != "" || dst.PoolTrustedFallback != 0 {
		t.Errorf("trusted winner must reset provenance, got %+v", dst)
	}
}

func TestMarkUntrustedPorts(t *testing.T) {
	pc := &PortsConfig{Pool: 3, Map: []PortEntry{{Name: "web", Container: 3000}}}
	markUntrustedPorts(pc, "/repo/.coi/config.toml")
	if !pc.PoolUntrusted || pc.PoolSourcePath == "" {
		t.Error("pool must be marked untrusted")
	}
	if !pc.Map[0].Untrusted || pc.Map[0].SourcePath == "" {
		t.Error("map entries must be marked untrusted")
	}

	// Empty section: no marking (nothing gated)
	empty := &PortsConfig{}
	markUntrustedPorts(empty, "/repo/.coi/config.toml")
	if empty.PoolUntrusted {
		t.Error("empty section must not be marked")
	}
}

func TestConfigFilePortListenValidation(t *testing.T) {
	path := filepath.Join(t.TempDir(), "config.toml")
	write := func(listen string) {
		t.Helper()
		body := "[[ports.map]]\nname = \"web\"\ncontainer = 8000\nlisten = \"" + listen + "\"\n"
		if err := os.WriteFile(path, []byte(body), 0o644); err != nil {
			t.Fatal(err)
		}
	}

	for _, trusted := range []bool{true, false} {
		write("localhost")
		err := loadConfigFileScoped(GetDefaultConfig(), path, trusted)
		if err == nil || !strings.Contains(err.Error(), "'listen' must be an IP address") {
			t.Errorf("trusted=%v: non-IP listen should be rejected, got: %v", trusted, err)
		}

		write("0.0.0.0")
		cfg := GetDefaultConfig()
		if err := loadConfigFileScoped(cfg, path, trusted); err != nil {
			t.Errorf("trusted=%v: IP listen rejected: %v", trusted, err)
		}
		if len(cfg.Ports.Map) != 1 || cfg.Ports.Map[0].Listen != "0.0.0.0" {
			t.Errorf("trusted=%v: entry not merged: %+v", trusted, cfg.Ports.Map)
		}
	}
}
