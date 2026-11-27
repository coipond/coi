package session

import (
	"errors"
	"strings"
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

// fakeTmpCleaner records how ApplyTmpCleanup drives the container.
type fakeTmpCleaner struct {
	maxSize, maxAge string
	called          bool
	err             error
}

func (f *fakeTmpCleaner) SetTmpCleanup(maxSize, maxAge string) error {
	f.called = true
	f.maxSize, f.maxAge = maxSize, maxAge
	return f.err
}

func TestApplyTmpCleanup(t *testing.T) {
	var logged []string
	log := func(s string) { logged = append(logged, s) }

	t.Run("limits are passed through", func(t *testing.T) {
		f := &fakeTmpCleaner{}
		cfg := &config.LimitsConfig{}
		cfg.Disk.TmpMaxSize, cfg.Disk.TmpMaxAge = "1GiB", "2d"
		ApplyTmpCleanup(f, cfg, log)
		if !f.called || f.maxSize != "1GiB" || f.maxAge != "2d" {
			t.Errorf("SetTmpCleanup called=%v args=%q,%q, want true/1GiB,2d", f.called, f.maxSize, f.maxAge)
		}
	})

	t.Run("nil limits config still sets the defaults", func(t *testing.T) {
		f := &fakeTmpCleaner{}
		ApplyTmpCleanup(f, nil, log)
		if !f.called || f.maxSize != "" || f.maxAge != "" {
			t.Errorf("SetTmpCleanup called=%v args=%q,%q, want true with empty args", f.called, f.maxSize, f.maxAge)
		}
	})

	t.Run("a container without SetTmpCleanup is skipped", func(t *testing.T) {
		ApplyTmpCleanup(&fakeTmpfsSizer{}, nil, log) // must not panic
	})

	t.Run("errors are logged (non-fatal)", func(t *testing.T) {
		logged = nil
		ApplyTmpCleanup(&fakeTmpCleaner{err: errors.New("boom")}, nil, log)
		if len(logged) != 1 || !strings.Contains(logged[0], "boom") {
			t.Errorf("logged %q, want one warning naming the error", logged)
		}
	})
}
