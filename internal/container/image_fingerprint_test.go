package container

import (
	"os"
	"strings"
	"testing"
)

func TestImageOutdated(t *testing.T) {
	for _, tc := range []struct {
		name, alias, base string
		want              bool
	}{
		{"image rebuilt", "img", "oldfp", true},
		{"same image", "img", "newfp", false},
		{"alias no longer exists", "gone", "oldfp", false},
		{"no base image recorded", "img", "", false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			name := "fp-" + strings.ReplaceAll(tc.name, " ", "-")
			cfg := "config: {}"
			if tc.base != "" {
				cfg = "config:\n  volatile.base_image: " + tc.base
			}
			fakeIncusScript(t, `case "$*" in
  *"image list"*) echo '[{"fingerprint":"newfp","aliases":[{"name":"`+name+`-img"}]},{"fingerprint":"otherfp","aliases":[]}]' ;;
  *"config show "*) printf '%s\n' '`+strings.ReplaceAll(cfg, "\n", "' '")+`' ;;
esac`)
			if got := ImageOutdated(name, name+"-"+tc.alias); got != tc.want {
				t.Errorf("ImageOutdated = %v, want %v", got, tc.want)
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
