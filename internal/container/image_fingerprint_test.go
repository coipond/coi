package container

import (
	"os"
	"strings"
	"testing"
)

func TestOutdatedImageAlias(t *testing.T) {
	for _, tc := range []struct {
		name, alias, base, want string
	}{
		{"image rebuilt", "img", "oldfp", "img"},
		{"same image", "img", "newfp", ""},
		{"alias no longer exists", "gone", "oldfp", ""},
		{"no base image recorded", "img", "", ""},
		{"no alias recorded", "", "oldfp", ""},
	} {
		t.Run(tc.name, func(t *testing.T) {
			name := "fp-" + strings.ReplaceAll(tc.name, " ", "-")
			lines := []string{"config:"}
			want := ""
			if tc.alias != "" {
				lines = append(lines, "  "+ImageAliasConfigKey+": "+name+"-"+tc.alias)
			}
			if tc.base != "" {
				lines = append(lines, "  "+BaseImageConfigKey+": "+tc.base)
			}
			if tc.want != "" {
				want = name + "-" + tc.want
			}
			fakeIncusScript(t, `case "$*" in
  *"image list"*) echo '[{"fingerprint":"newfp","aliases":[{"name":"`+name+`-img"}]},{"fingerprint":"otherfp","aliases":[]}]' ;;
  *"config show "*) printf '%s\n' '`+strings.Join(lines, "' '")+`' ;;
esac`)
			if got := OutdatedImageAlias(name); got != want {
				t.Errorf("OutdatedImageAlias = %q, want %q", got, want)
			}
		})
	}
}

func TestImageFingerprint_CachesFoundAlias(t *testing.T) {
	log := fakeIncusScript(t, `case "$*" in
  *"image list"*) echo '[{"aliases":[{"name":"fp-nofp"}]},{"fingerprint":"abc","aliases":[{"name":"fp-cached"}]}]' ;;
esac`)
	if exists, err := ImageExists("fp-cached"); err != nil || !exists {
		t.Fatalf("ImageExists = %v, %v; want true", exists, err)
	}
	if fp, err := ImageFingerprint("fp-cached"); err != nil || fp != "abc" {
		t.Errorf("ImageFingerprint = %q, %v; want abc", fp, err)
	}
	if exists, err := ImageExists("fp-nofp"); err != nil || !exists {
		t.Errorf("ImageExists without a fingerprint in the list = %v, %v; want true", exists, err)
	}
	if fp, err := ImageFingerprint("fp-missing"); err != nil || fp != "" {
		t.Errorf("ImageFingerprint of a missing alias = %q, %v; want empty", fp, err)
	}
	b, _ := os.ReadFile(log)
	if n := strings.Count(string(b), "image list"); n != 3 {
		t.Errorf("%d image lists, want 3 (fp-cached once, fp-nofp, fp-missing); calls:\n%s", n, b)
	}
}
