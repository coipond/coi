package network

import "testing"

// NftPasswordlessSudo must ignore a cached sudo credential (`sudo -k -n`):
// otherwise a recent `sudo` makes it pass while no NOPASSWD rule exists.
func TestNftPasswordlessSudo_IgnoresCachedCredential(t *testing.T) {
	orig := runSudoProbe
	t.Cleanup(func() { runSudoProbe = orig })
	var got []string
	runSudoProbe = func(args ...string) error { got = args; return nil }

	prev := SudoEnabled()
	t.Cleanup(func() { SetSudoAllowed(prev) })
	SetSudoAllowed(true)
	if !NftPasswordlessSudo() {
		t.Fatal("probe success should report true")
	}
	if len(got) < 2 || got[0] != "-k" || got[1] != "-n" {
		t.Errorf("must run `sudo -k -n nft ...`, got %v", got)
	}

	got = nil
	SetSudoAllowed(false)
	if NftPasswordlessSudo() || got != nil {
		t.Errorf("use_sudo=false must not invoke sudo (ran %v)", got)
	}
}
