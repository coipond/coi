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
		name, status, base, imageAlias, explicit string
		wantWarn                                 bool
	}{
		{"stopped persistent, image rebuilt", "STOPPED", "oldfp", "img", "", true},
		{"running persistent, image rebuilt", "RUNNING", "oldfp", "img", "", true},
		{"stopped persistent, same image", "STOPPED", "newfp", "img", "", false},
		{"running persistent, same image", "RUNNING", "newfp", "img", "", false},
		{"no base image recorded", "STOPPED", "", "img", "", false},
		{"explicit --container", "STOPPED", "oldfp", "img", "set", false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			ws := t.TempDir()
			name := "io-" + strings.NewReplacer(" ", "-", ",", "").Replace(tc.name)
			alias := name + "-" + tc.imageAlias
			cfgLines := ""
			if tc.base != "" {
				cfgLines = "  volatile.base_image: " + tc.base + "\n"
			}
			logPath := fakeLimitsIncusCases(t, name, limitsWorkspaceYAML(ws, cfgLines), tc.status, imageListCase(name+"-img", "newfp"))
			// phaseResolveImage looked the alias up before this phase.
			if _, err := container.ImageExists(alias); err != nil {
				t.Fatal(err)
			}
			var logged []string
			opts := SetupOptions{Persistent: true, WorkspacePath: ws, Logger: func(s string) { logged = append(logged, s) }}
			if tc.explicit != "" {
				opts.ContainerName = name
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
			if strings.Contains(calls, container.BaseImageConfigKey) {
				t.Errorf("base image read with its own incus call, want it from the config cache; calls:\n%s", calls)
			}
		})
	}
}
