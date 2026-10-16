package image

import (
	"errors"
	"strings"
	"sync"
	"testing"
	"time"
)

func TestWithProgress_ReportsUntilDone(t *testing.T) {
	var mu sync.Mutex
	var logged []string
	logf := func(msg string) {
		mu.Lock()
		defer mu.Unlock()
		logged = append(logged, msg)
	}

	wantErr := errors.New("publish failed")
	err := withProgress(logf, 10*time.Millisecond, "Still creating image", func() error {
		time.Sleep(55 * time.Millisecond)
		return wantErr
	})
	if !errors.Is(err, wantErr) {
		t.Fatalf("got error %v, want %v", err, wantErr)
	}

	mu.Lock()
	n := len(logged)
	mu.Unlock()
	if n == 0 {
		t.Fatal("expected progress lines while fn ran, got none")
	}
	for _, msg := range logged {
		if !strings.HasPrefix(msg, "Still creating image... (") {
			t.Errorf("unexpected progress line %q", msg)
		}
	}

	time.Sleep(30 * time.Millisecond)
	mu.Lock()
	defer mu.Unlock()
	if len(logged) != n {
		t.Errorf("progress kept logging after fn returned: %v", logged[n:])
	}
}

func TestWithProgress_QuietWhenFast(t *testing.T) {
	err := withProgress(func(msg string) { t.Errorf("unexpected progress line %q", msg) },
		time.Hour, "Still creating image", func() error { return nil })
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
}
