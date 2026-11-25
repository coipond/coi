package cli

import (
	"fmt"
	"os"
	"strings"
	"testing"

	"github.com/coipond/coi/internal/config"
)

func TestPrintProfileContainer_KeepOnFailedSave(t *testing.T) {
	for _, keep := range []bool{true, false} {
		p := &config.ProfileConfig{Container: config.ContainerConfig{KeepOnFailedSave: &keep}}
		out := captureOutput(t, &os.Stdout, func() { printProfileContainer(p) })
		want := fmt.Sprintf("[container]\nkeep_on_failed_save = %v\n", keep)
		if !strings.Contains(out, want) {
			t.Errorf("keep=%v: output %q does not contain %q", keep, out, want)
		}
	}
}
