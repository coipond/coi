package session

import (
	"context"
	"os"
	"strings"
	"testing"

	"github.com/coipond/coi/internal/container"
)

// imageListCase is a fakeLimitsIncusCases case answering `incus image list`
// with one image of fingerprint under alias.
func imageListCase(alias, fingerprint string) string {
	return `  *"image list"*) echo '[{"fingerprint":"` + fingerprint + `","aliases":[{"name":"` + alias + `"}]}]' ;;
`
}

func TestPhaseReconcileExisting_WarnsOnOutdatedImage(t *testing.T) {
	for _, tc := range []struct {
		name, status, base string
		persistent         bool
		explicit, resume   bool
		wantWarn           bool
	}{
		{"stopped persistent, image rebuilt", "STOPPED", "oldfp", true, false, false, true},
		{"running persistent, image rebuilt", "RUNNING", "oldfp", true, false, false, true},
		{"stopped persistent, same image", "STOPPED", "newfp", true, false, false, false},
		{"running persistent, same image", "RUNNING", "newfp", true, false, false, false},
		{"no base image recorded", "STOPPED", "", true, false, false, false},
		{"stopped explicit --container", "STOPPED", "oldfp", true, true, false, false},
		{"running explicit --container", "RUNNING", "oldfp", true, true, false, false},
		{"running non-persistent --resume", "RUNNING", "oldfp", false, false, true, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			ws := t.TempDir()
			name := "io-" + strings.NewReplacer(" ", "-", ",", "").Replace(tc.name)
			alias := name + "-img"
			cfgLines := "  " + container.ImageAliasConfigKey + ": " + alias + "\n"
			if tc.base != "" {
				cfgLines += "  " + container.BaseImageConfigKey + ": " + tc.base + "\n"
			}
			logPath := fakeLimitsIncusCases(t, name, limitsWorkspaceYAML(ws, cfgLines), tc.status, imageListCase(alias, "newfp"))
			// phaseResolveImage looked the alias up before this phase.
			if _, err := container.ImageExists(alias); err != nil {
				t.Fatal(err)
			}
			var logged []string
			opts := SetupOptions{Persistent: tc.persistent, WorkspacePath: ws, Logger: func(s string) { logged = append(logged, s) }}
			if tc.explicit {
				opts.ContainerName = name
			}
			if tc.resume {
				opts.ResumeFromID = "sess-1"
			}
			st := &setupState{
				opts:   opts,
				result: &SetupResult{Manager: container.NewManager(name), ContainerName: name},
				image:  alias,
			}
			if _, err := st.phaseReconcileExisting(context.Background()); err != nil {
				t.Fatal(err)
			}
			warnings := 0
			for _, l := range logged {
				if strings.Contains(l, "runs an older build of image "+alias) {
					warnings++
					if !strings.Contains(l, "coi shutdown "+name) {
						t.Errorf("warning names no fix: %s", l)
					}
				}
			}
			if want := map[bool]int{true: 1, false: 0}[tc.wantWarn]; warnings != want {
				t.Errorf("%d outdated-image warnings, want %d; log:\n%s", warnings, want, strings.Join(logged, "\n"))
			}
			b, _ := os.ReadFile(logPath)
			calls := string(b)
			if n := strings.Count(calls, "image list"); n != 1 {
				t.Errorf("%d image lists, want only the alias lookup before the phase; calls:\n%s", n, calls)
			}
			if strings.Contains(calls, container.BaseImageConfigKey) || strings.Contains(calls, container.ImageAliasConfigKey) {
				t.Errorf("image keys read with their own incus call, want them from the config cache; calls:\n%s", calls)
			}
		})
	}
}

func TestPhaseReconcileExisting_OtherImageIsNotOutdated(t *testing.T) {
	// `coi shell --profile X` reuses the workspace's container created from
	// another, current image: it was not rebuilt, so no warning.
	ws := t.TempDir()
	name := "io-other-image"
	cfgLines := "  " + container.ImageAliasConfigKey + ": " + name + "-default\n  " + container.BaseImageConfigKey + ": defaultfp\n"
	fakeLimitsIncusCases(t, name, limitsWorkspaceYAML(ws, cfgLines), "STOPPED",
		`  *"image list"*) echo '[{"fingerprint":"defaultfp","aliases":[{"name":"`+name+`-default"}]},{"fingerprint":"rustfp","aliases":[{"name":"`+name+`-rust"}]}]' ;;
`)
	var logged []string
	st := &setupState{
		opts:   SetupOptions{Persistent: true, WorkspacePath: ws, Logger: func(s string) { logged = append(logged, s) }},
		result: &SetupResult{Manager: container.NewManager(name), ContainerName: name},
		image:  name + "-rust",
	}
	if _, err := st.phaseReconcileExisting(context.Background()); err != nil {
		t.Fatal(err)
	}
	if log := strings.Join(logged, "\n"); strings.Contains(log, "older build") {
		t.Errorf("warning for a container on another, current image:\n%s", log)
	}
}
