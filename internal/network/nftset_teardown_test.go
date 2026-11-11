package network

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// fakeSetTeardownSudo puts a `sudo` on PATH that records every nft call in
// the returned log. `nft -t list sets table ip coi` prints listing, or fails
// as a missing table when listing is empty. `delete set` exits with
// deleteErr's message when it is set.
func fakeSetTeardownSudo(t *testing.T, listing, deleteErr string) string {
	t.Helper()
	dir := t.TempDir()
	logPath := filepath.Join(dir, "calls.log")
	listAnswer := `echo "Error: No such file or directory" >&2; exit 1`
	if listing != "" {
		listPath := filepath.Join(dir, "sets.txt")
		if err := os.WriteFile(listPath, []byte(listing), 0o600); err != nil {
			t.Fatal(err)
		}
		listAnswer = fmt.Sprintf("cat %q", listPath)
	}
	deleteAnswer := ":"
	if deleteErr != "" {
		deleteAnswer = fmt.Sprintf("echo %q >&2; exit 1", deleteErr)
	}
	script := fmt.Sprintf(`#!/bin/sh
shift 2
echo "$*" >> %q
case "$*" in
"-t list sets table ip coi") %s ;;
"delete set "*) %s ;;
esac
exit 0
`, logPath, listAnswer, deleteAnswer)
	if err := os.WriteFile(filepath.Join(dir, "sudo"), []byte(script), 0o700); err != nil { //nolint:gosec // test fake must be executable
		t.Fatal(err)
	}
	t.Setenv("PATH", dir+string(os.PathListSeparator)+os.Getenv("PATH"))
	prev := SudoEnabled()
	SetSudoAllowed(true)
	t.Cleanup(func() { SetSudoAllowed(prev) })
	return logPath
}

// Terse `list sets` output: declarations only, no elements.
const teardownSetsListing = `table ip coi {
	set coi_s_10_0_0_2 {
		type ipv4_addr
		flags interval
	}
	set coi_dp_10_0_0_2 {
		type ipv4_addr . inet_service
		flags timeout
	}
	set coi_d_10_0_0_23 {
		type ipv4_addr
		flags timeout
	}
	set coi_d_10_0_0_3 {
		type ipv4_addr
		flags timeout
	}
}
`

func TestRemoveAllowlistSetsForIP(t *testing.T) {
	t.Run("deletes only the listed sets of the IP", func(t *testing.T) {
		logPath := fakeSetTeardownSudo(t, teardownSetsListing, "")
		if err := removeAllowlistSetsForIP("10.0.0.2"); err != nil {
			t.Fatalf("removeAllowlistSetsForIP: %v", err)
		}
		want := "-t list sets table ip coi\n" +
			"delete set ip coi coi_s_10_0_0_2\n" +
			"delete set ip coi coi_dp_10_0_0_2\n"
		if got := readCalls(t, logPath); got != want {
			t.Errorf("calls:\n%s\nwant:\n%s", got, want)
		}
	})

	t.Run("no sets for the IP costs one listing", func(t *testing.T) {
		logPath := fakeSetTeardownSudo(t, teardownSetsListing, "")
		if err := removeAllowlistSetsForIP("10.0.0.9"); err != nil {
			t.Fatalf("removeAllowlistSetsForIP: %v", err)
		}
		if got := readCalls(t, logPath); got != "-t list sets table ip coi\n" {
			t.Errorf("calls:\n%s\nwant only the listing", got)
		}
	})

	t.Run("absent table tries every set and absent sets are no error", func(t *testing.T) {
		logPath := fakeSetTeardownSudo(t, "", "Error: No such file or directory")
		if err := removeAllowlistSetsForIP("10.0.0.2"); err != nil {
			t.Fatalf("removeAllowlistSetsForIP: %v", err)
		}
		calls := readCalls(t, logPath)
		for _, name := range []string{"coi_s_10_0_0_2", "coi_d_10_0_0_2", "coi_sp_10_0_0_2", "coi_dp_10_0_0_2"} {
			if !strings.Contains(calls, "delete set ip coi "+name+"\n") {
				t.Errorf("set %s not deleted; calls:\n%s", name, calls)
			}
		}
	})

	t.Run("a failed delete is returned", func(t *testing.T) {
		fakeSetTeardownSudo(t, teardownSetsListing, "Error: Device or resource busy")
		err := removeAllowlistSetsForIP("10.0.0.2")
		if err == nil || !strings.Contains(err.Error(), "resource busy") {
			t.Errorf("err = %v, want the busy error", err)
		}
	})

	t.Run("empty IP runs nothing", func(t *testing.T) {
		logPath := fakeSetTeardownSudo(t, teardownSetsListing, "")
		if err := removeAllowlistSetsForIP(""); err != nil {
			t.Fatalf("removeAllowlistSetsForIP: %v", err)
		}
		if _, err := os.Stat(logPath); !os.IsNotExist(err) {
			t.Errorf("nft ran for an empty IP")
		}
	})
}
