package image

import (
	"strings"
	"testing"
)

// coi mounts tool data dirs over ~/.local/{share,state}/opencode and
// ~/.opencode/plan (#929). Their parents must exist, owned by code, in every
// image — whichever agents it installs (opencode v1 is opt-in once opencode2
// is the default), or the mount target leaves a root-owned parent behind. So
// the pre-creation lives in create_code_user, ahead of its chown -R, not in an
// agent installer.
func TestBuildScriptPreCreatesToolDataParents(t *testing.T) {
	user := stripShellComments(extractShellFunc(t, string(embeddedCoiBuildScript), "create_code_user"))
	chown := strings.Index(user, `chown -R "$CODE_USER:$CODE_USER" "/home/$CODE_USER"`)
	if chown < 0 {
		t.Fatalf("create_code_user no longer chowns the home dir:\n%s", user)
	}
	for _, dir := range []string{`"/home/$CODE_USER/.local/share"`, `"/home/$CODE_USER/.local/state"`, `"/home/$CODE_USER/.opencode"`} {
		i := strings.Index(user, dir)
		if i < 0 {
			t.Errorf("create_code_user must create %s", dir)
		} else if i > chown {
			t.Errorf("create_code_user creates %s after the chown -R, so it stays root-owned", dir)
		}
	}

	installer := stripShellComments(extractShellFunc(t, string(embeddedCoiBuildScript), "install_opencode"))
	if strings.Contains(installer, ".local/state") {
		t.Error("install_opencode creates ~/.local/state; it must not depend on which agents are installed")
	}
}
