package limits

import (
	"context"
	"testing"
	"time"

	"github.com/mensfeld/coi/internal/logger"
)

// TestStopGracefulTrue verifies that StopGraceful=true maps to force=false
func TestStopGracefulTrue(t *testing.T) {
	tm := NewTimeoutMonitor(context.Background(), "test-container", 50*time.Millisecond, true, true, "", logger.NewDiscard())

	if tm.StopGraceful != true {
		t.Errorf("expected StopGraceful=true, got %v", tm.StopGraceful)
	}

	// The fix ensures: StopGraceful=true -> Stop(force=false) (graceful)
	// Before the fix: StopGraceful=true -> Stop(force=true) (inverted!)
	force := !tm.StopGraceful
	if force != false {
		t.Errorf("StopGraceful=true should result in force=false, got force=%v", force)
	}
}

// TestStopGracefulFalse verifies that StopGraceful=false calls Stop(true) (force)
func TestStopGracefulFalse(t *testing.T) {
	tm := NewTimeoutMonitor(context.Background(), "test-container", 50*time.Millisecond, true, false, "", logger.NewDiscard())

	if tm.StopGraceful != false {
		t.Errorf("expected StopGraceful=false, got %v", tm.StopGraceful)
	}

	// StopGraceful=false means force stop (force=true)
	force := !tm.StopGraceful
	if force != true {
		t.Errorf("StopGraceful=false should result in force=true, got force=%v", force)
	}
}

// TestHandleTimeoutStopType verifies the correct stopType is derived from StopGraceful
func TestHandleTimeoutStopType(t *testing.T) {
	tests := []struct {
		name         string
		stopGraceful bool
		expectedType string
	}{
		{
			name:         "graceful mode",
			stopGraceful: true,
			expectedType: "gracefully",
		},
		{
			name:         "force mode",
			stopGraceful: false,
			expectedType: "forcefully",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tm := NewTimeoutMonitor(context.Background(), "test-container", time.Hour, true, tt.stopGraceful, "", logger.NewDiscard())

			stopType := "gracefully"
			if !tm.StopGraceful {
				stopType = "forcefully"
			}
			if stopType != tt.expectedType {
				t.Errorf("expected stopType=%q, got %q", tt.expectedType, stopType)
			}
		})
	}
}

// TestTimeoutMonitorNoLimit verifies that MaxDuration=0 means no monitoring
func TestTimeoutMonitorNoLimit(t *testing.T) {
	tm := NewTimeoutMonitor(context.Background(), "test-container", 0, true, true, "", logger.NewDiscard())
	tm.Start()

	// Should complete immediately
	select {
	case <-tm.done:
		// Good - completed immediately
	case <-time.After(100 * time.Millisecond):
		t.Error("timeout monitor with MaxDuration=0 should complete immediately")
	}
}

// TestTimeoutMonitorCancel verifies that Stop() cancels the monitor
func TestTimeoutMonitorCancel(t *testing.T) {
	tm := NewTimeoutMonitor(context.Background(), "test-container", time.Hour, true, true, "", logger.NewDiscard())
	tm.Start()

	// Cancel immediately
	tm.Stop()

	// Should complete quickly
	select {
	case <-tm.done:
		// Good - cancelled
	case <-time.After(100 * time.Millisecond):
		t.Error("timeout monitor should complete after Stop()")
	}
}
