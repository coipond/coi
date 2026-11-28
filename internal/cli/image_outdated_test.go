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
		persistent bool
		wantWarns  int
	}{
		{"image rebuilt", "oldfp", true, 1},
		{"same image", "newfp", true, 0},
		{"existing non-persistent container", "oldfp", false, 0},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Setenv("HOME", t.TempDir())
			ws := t.TempDir()
			name := "run-img-" + strings.ReplaceAll(tc.name, " ", "-")
			alias := name + "-alias"
			fakeIncusCases(t, name,
				"config:\n  user.coi.image: "+alias+"\n  volatile.base_image: "+tc.base+"\ndevices:\n  workspace:\n    path: /workspace\n    source: "+ws+"\n    type: disk\n",
				"STOPPED", imageListCase(alias, "newfp"))
			cfg := config.GetDefaultConfig()
			cfg.Network.Mode = config.NetworkModeOpen
			cfg.Security.DisableProtection = true
			a := &App{cfg: cfg, persistent: tc.persistent}
			s := &runState{absWorkspace: ws, containerName: name, img: alias, slot: 1}

			stderr := captureOutput(t, &os.Stderr, func() {
				_, _ = a.launchContainerRunPhase(s).Run(context.Background())
			})
			if got := strings.Count(stderr, "runs an older build of image "+alias); got != tc.wantWarns {
				t.Errorf("%d outdated-image warnings, want %d; stderr:\n%s", got, tc.wantWarns, stderr)
			}
		})
	}
}

func TestListImageOutdated(t *testing.T) {
	listJSON := `[` +
		`{"name":"coi-a-1","status":"Stopped","config":{"user.coi.image":"list-img","volatile.base_image":"oldfp"}},` +
		`{"name":"coi-b-1","status":"Running","config":{"user.coi.image":"list-img","volatile.base_image":"newfp"}},` +
		`{"name":"coi-c-1","status":"Running","config":{"user.coi.image":"list-rust","volatile.base_image":"rustfp"}},` +
		`{"name":"coi-d-1","status":"Running","config":{"user.coi.image":"list-gone","volatile.base_image":"oldfp"}},` +
		`{"name":"coi-e-1","status":"Running","config":{"volatile.base_image":"oldfp"}},` +
		`{"name":"coi-f-1","status":"Running","config":{}},` +
		`{"name":"coi-g-1","status":"Running","config":{"user.coi.image":"list-img"}}]`
	want := map[string]bool{"coi-a-1": true, "coi-b-1": false, "coi-c-1": false, "coi-d-1": false, "coi-e-1": false, "coi-f-1": false, "coi-g-1": false}
	fakeIncusCases(t, "none", "", "",
		`  *"image list"*) echo '[{"fingerprint":"newfp","aliases":[{"name":"list-img"}]},{"fingerprint":"rustfp","aliases":[{"name":"list-rust"}]}]' ;;
  *"list "*"--format=json"*) echo '`+listJSON+`' ;;
`)
	containers, err := listActiveContainers()
	if err != nil {
		t.Fatal(err)
	}
	markOutdatedImages(containers)

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
	if len(parsed.Containers) != len(want) {
		t.Fatalf("got %d containers, want %d: %s", len(parsed.Containers), len(want), out)
	}
	for _, c := range parsed.Containers {
		if c.ImageOutdated == nil || *c.ImageOutdated != want[c.Name] {
			t.Errorf("%s image_outdated = %v, want %v", c.Name, c.ImageOutdated, want[c.Name])
		}
	}

	text := captureOutput(t, &os.Stdout, func() {
		if err := outputText(containers, nil, nil, nil, ""); err != nil {
			t.Error(err)
		}
	})
	if got := strings.Count(text, "Image outdated: list-img was rebuilt"); got != 1 {
		t.Errorf("%d outdated markers in text output, want 1:\n%s", got, text)
	}
}

func TestListImageOutdated_NoImageListWithoutImageKeys(t *testing.T) {
	logPath := fakeIncusCases(t, "none", "", "", `  *"image list"*) echo '[]' ;;
  *"list "*"--format=json"*) echo '[{"name":"coi-a-1","config":{"volatile.base_image":"oldfp"}},{"name":"coi-b-1","config":{"user.coi.image":"x"}}]' ;;
`)
	containers, err := listActiveContainers()
	if err != nil {
		t.Fatal(err)
	}
	markOutdatedImages(containers)
	b, _ := os.ReadFile(logPath)
	if strings.Contains(string(b), "image list") {
		t.Errorf("image list without a container that has both image keys; calls:\n%s", b)
	}
}
