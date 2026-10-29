package cli

import (
	"strings"
	"testing"
)

// [container] image must be a local alias (phaseResolveImage checks
// container.ImageExists), so the hint must copy a remote image first and
// never suggest a remote name as the image value.
func TestFormatImageHints(t *testing.T) {
	got := formatImageHints("default")

	for _, want := range []string{
		"incus image copy images:ubuntu/24.04 local: --alias my-ubuntu\n",
		`[container] image = "my-ubuntu"`,
		"coi build --profile <name>",
	} {
		if !strings.Contains(got, want) {
			t.Errorf("hint missing %q; got:\n%s", want, got)
		}
	}
	for _, bad := range []string{`image = "ubuntu:24.04"`, "coi build custom", "--target-project"} {
		if strings.Contains(got, bad) {
			t.Errorf("hint contains %q; got:\n%s", bad, got)
		}
	}
}

func TestFormatImageHints_NonDefaultProject(t *testing.T) {
	got := formatImageHints("coi")

	want := "incus image copy images:ubuntu/24.04 local: --alias my-ubuntu --target-project coi\n"
	if !strings.Contains(got, want) {
		t.Errorf("hint missing %q; got:\n%s", want, got)
	}
}
