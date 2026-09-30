package session

import (
	"errors"
	"testing"

	"github.com/coipond/coi/internal/config"
)

// fakeTmpfsSizer records how ApplyTmpfsSizing drives the container.
type fakeTmpfsSizer struct {
	explicitSize string // arg passed to SetTmpfsSize
	called       bool
	err          error
}

func (f *fakeTmpfsSizer) SetTmpfsSize(size string) error {
	f.called = true
	f.explicitSize = size
	return f.err
}

func TestApplyTmpfsSizing(t *testing.T) {
	log := func(string) {}

	t.Run("explicit tmpfs_size is applied verbatim", func(t *testing.T) {
		f := &fakeTmpfsSizer{}
		cfg := &config.LimitsConfig{}
		cfg.Disk.TmpfsSize = "8GiB"
		ApplyTmpfsSizing(f, cfg, log)
		if !f.called || f.explicitSize != "8GiB" {
			t.Errorf("SetTmpfsSize called=%v arg=%q, want true/8GiB", f.called, f.explicitSize)
		}
	})

	t.Run("unset tmpfs_size is a no-op (no default RAM tmpfs)", func(t *testing.T) {
		f := &fakeTmpfsSizer{}
		ApplyTmpfsSizing(f, &config.LimitsConfig{}, log) // TmpfsSize == ""
		if f.called {
			t.Errorf("SetTmpfsSize must not run when tmpfs_size is unset (arg %q)", f.explicitSize)
		}
	})

	t.Run("nil limits config is a no-op", func(t *testing.T) {
		f := &fakeTmpfsSizer{}
		ApplyTmpfsSizing(f, nil, log)
		if f.called {
			t.Error("nil config must not size /tmp")
		}
	})

	t.Run("errors are swallowed (non-fatal)", func(t *testing.T) {
		f := &fakeTmpfsSizer{err: errors.New("boom")}
		cfg := &config.LimitsConfig{}
		cfg.Disk.TmpfsSize = "2GiB"
		ApplyTmpfsSizing(f, cfg, log) // must not panic
	})
}
