package cli

import (
	"context"
	"encoding/json"
	"os"
	"strings"
	"testing"

	"github.com/coipond/coi/internal/config"
)

// imageListCase is a fakeIncusCases case answering `incus image list` with
// one image of fingerprint under alias.
func imageListCase(alias, fingerprint string) string {
	return `  *"image list"*) echo '[{"fingerprint":"` + fingerprint + `","aliases":[{"name":"` + alias + `"}]}]' ;;
`
}

func TestLaunchContainerRunPhase_RestartWarnsOnOutdatedImage(t *testing.T) {
	for _, tc := range []struct {
		name, base string
		wantWarn   bool
	}{
		{"image rebuilt", "oldfp", true},
		{"same image", "newfp", false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Setenv("HOME", t.TempDir())
			ws := t.TempDir()
			name := "run-img-" + strings.ReplaceAll(tc.name, " ", "-")
			alias := name + "-alias"
			fakeIncusCases(t, name,
				"config:\n  volatile.base_image: "+tc.base+"\ndevices:\n  workspace:\n    path: /workspace\n    source: "+ws+"\n    type: disk\n",
				"STOPPED", imageListCase(alias, "newfp"))
			cfg := config.GetDefaultConfig()
			cfg.Network.Mode = config.NetworkModeOpen
			cfg.Security.DisableProtection = true
			a := &App{cfg: cfg, persistent: true}
			s := &runState{absWorkspace: ws, containerName: name, img: alias, slot: 1}

			stderr := captureOutput(t, &os.Stderr, func() {
				if _, err := a.launchContainerRunPhase(s).Run(context.Background()); err != nil {
					t.Error(err)
				}
			})
			if got := strings.Count(stderr, "runs an older build of image "+alias); got != map[bool]int{true: 1, false: 0}[tc.wantWarn] {
				t.Errorf("%d outdated-image warnings, want warn=%v; stderr:\n%s", got, tc.wantWarn, stderr)
			}
		})
	}
}

func TestListImageOutdated(t *testing.T) {
	listJSON := `[` +
		`{"name":"coi-a-1","status":"Stopped","config":{"volatile.base_image":"oldfp"}},` +
		`{"name":"coi-b-1","status":"Running","config":{"volatile.base_image":"newfp"}},` +
		`{"name":"coi-c-1","status":"Running","config":{}}]`
	for _, tc := range []struct {
		name, alias string
		want        map[string]bool
	}{
		{"alias exists", "list-img", map[string]bool{"coi-a-1": true, "coi-b-1": false, "coi-c-1": false}},
		{"alias no longer exists", "list-gone", map[string]bool{"coi-a-1": false, "coi-b-1": false, "coi-c-1": false}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			fakeIncusCases(t, "none", "", "", imageListCase("list-img", "newfp")+
				`  *"list "*"--format=json"*) echo '`+listJSON+`' ;;
`)
			containers, err := listActiveContainers()
			if err != nil {
				t.Fatal(err)
			}
			markOutdatedImages(containers, tc.alias)

			out := captureOutput(t, &os.Stdout, func() {
				if err := outputJSON(containers, nil, nil, nil); err != nil {
					t.Error(err)
				}
			})
			var parsed struct {
				Containers []struct {
					Name          string `json:"name"`
					ImageOutdated *bool  `json:"image_outdated"`
				} `json:"active_containers"`
			}
			if err := json.Unmarshal([]byte(out), &parsed); err != nil {
				t.Fatalf("%v: %s", err, out)
			}
			if len(parsed.Containers) != len(tc.want) {
				t.Fatalf("got %d containers, want %d: %s", len(parsed.Containers), len(tc.want), out)
			}
			for _, c := range parsed.Containers {
				if c.ImageOutdated == nil || *c.ImageOutdated != tc.want[c.Name] {
					t.Errorf("%s image_outdated = %v, want %v", c.Name, c.ImageOutdated, tc.want[c.Name])
				}
			}

			text := captureOutput(t, &os.Stdout, func() {
				if err := outputText(containers, nil, nil, nil, ""); err != nil {
					t.Error(err)
				}
			})
			if got, want := strings.Count(text, "Image outdated:"), map[bool]int{true: 1, false: 0}[tc.want["coi-a-1"]]; got != want {
				t.Errorf("%d outdated markers in text output, want %d:\n%s", got, want, text)
			}
		})
	}
}
