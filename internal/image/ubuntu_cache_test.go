package image

import (
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
)

func TestPlanUbuntuCachePrune(t *testing.T) {
	keep := map[string]bool{"26.04": true}
	tests := []struct {
		name   string
		images []cachedImage
		inUse  map[string]bool
		want   ubuntuCachePrune
	}{
		{
			name:   "superseded cache goes whole",
			images: []cachedImage{{Fingerprint: "a", Aliases: []string{"coi-ubuntu-24.04"}}},
			want:   ubuntuCachePrune{Images: []string{"coi-ubuntu-24.04"}},
		},
		{
			name:   "kept version stays",
			images: []cachedImage{{Fingerprint: "a", Aliases: []string{"coi-ubuntu-26.04"}}},
		},
		{
			name:   "image with another alias loses only the cache alias",
			images: []cachedImage{{Fingerprint: "a", Aliases: []string{"coi-ubuntu-24.04", "my-base"}}},
			want:   ubuntuCachePrune{Aliases: []string{"coi-ubuntu-24.04"}},
		},
		{
			name:   "image shared with a kept cache alias loses only the stale alias",
			images: []cachedImage{{Fingerprint: "a", Aliases: []string{"coi-ubuntu-24.04", "coi-ubuntu-26.04"}}},
			want:   ubuntuCachePrune{Aliases: []string{"coi-ubuntu-24.04"}},
		},
		{
			name:   "image an instance uses is left alone",
			images: []cachedImage{{Fingerprint: "a", Aliases: []string{"coi-ubuntu-24.04"}}},
			inUse:  map[string]bool{"a": true},
		},
		{
			name: "aliases coi does not cache are ignored",
			images: []cachedImage{
				{Fingerprint: "a", Aliases: []string{"coi-default"}},
				{Fingerprint: "b", Aliases: []string{"coi-ubuntu-custom"}},
				{Fingerprint: "c", Aliases: []string{"my-coi-ubuntu-24.04"}},
				{Fingerprint: "d"},
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := planUbuntuCachePrune(tt.images, keep, tt.inUse)
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("got %+v, want %+v", got, tt.want)
			}
		})
	}
}

func TestKeptUbuntuVersions(t *testing.T) {
	meta := map[string]BuildMeta{
		"coi-default": {BaseImage: BaseImage},
		"custom-old":  {BaseImage: "ubuntu:24.04"},
		"gone":        {BaseImage: "ubuntu:22.04"},
		"child":       {BaseImage: "coi-default"},
		"other-distr": {BaseImage: "images:debian/13"},
	}
	images := []cachedImage{
		{Aliases: []string{"coi-default"}},
		{Aliases: []string{"custom-old"}},
		{Aliases: []string{"child"}},
		{Aliases: []string{"other-distr"}},
	}
	got := keptUbuntuVersions(meta, images)
	want := map[string]bool{strings.TrimPrefix(BaseImage, "ubuntu:"): true, "24.04": true}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("got %v, want %v", got, want)
	}
}

func TestPruneUbuntuCache(t *testing.T) {
	cur := "coi-ubuntu-" + strings.TrimPrefix(BaseImage, "ubuntu:")
	logPath := fakeIncusCases(t, `  *"image list"*) echo '[{"fingerprint":"old","aliases":[{"name":"coi-ubuntu-20.04"}]},{"fingerprint":"cur","aliases":[{"name":"`+cur+`"}]},{"fingerprint":"used","aliases":[{"name":"coi-ubuntu-22.04"}]}]' ;;
  *"list --format=json --all-projects"*) echo '[{"config":{"volatile.base_image":"used"}},{"config":{}}]' ;;
  *"image delete"*) echo boom >&2; exit 1 ;;`)

	var logs []string
	PruneUbuntuCache(t.TempDir(), func(s string) { logs = append(logs, s) })

	data, err := os.ReadFile(logPath)
	if err != nil {
		t.Fatal(err)
	}
	calls := string(data)
	if !strings.Contains(calls, "image delete coi-ubuntu-20.04") {
		t.Errorf("superseded cache not deleted:\n%s", calls)
	}
	for _, kept := range []string{cur, "coi-ubuntu-22.04"} {
		if strings.Contains(calls, "delete "+kept) {
			t.Errorf("%s deleted:\n%s", kept, calls)
		}
	}
	if len(logs) != 1 || !strings.HasPrefix(logs[0], "Warning: could not remove unused Ubuntu base image 'coi-ubuntu-20.04'") {
		t.Errorf("want one removal warning, got %q", logs)
	}
}

func TestPruneUbuntuCacheKeepsRecordedBase(t *testing.T) {
	logPath := fakeIncusCases(t, `  *"image list"*) echo '[{"fingerprint":"a","aliases":[{"name":"coi-ubuntu-24.04"}]},{"fingerprint":"b","aliases":[{"name":"custom"}]}]' ;;
  *"list --format=json --all-projects"*) echo '[]' ;;`)
	dir := t.TempDir()
	RecordBuild(dir, "custom", "ubuntu:24.04")

	PruneUbuntuCache(dir, nil)

	data, err := os.ReadFile(logPath)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(data), "delete") {
		t.Errorf("base of an existing recorded build deleted:\n%s", data)
	}
	if _, err := os.Stat(filepath.Join(dir, metaFileName)); err != nil {
		t.Fatal(err)
	}
}
