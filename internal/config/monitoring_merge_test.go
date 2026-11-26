package config

import (
	"testing"

	"github.com/BurntSushi/toml"
)

// A config file's rejected_burst_* keys override the earlier layer; an unset
// key keeps it.
func TestMergeMonitoring_RejectedBurst(t *testing.T) {
	base := &Config{Monitoring: MonitoringConfig{RejectedBurstDestinations: 10, RejectedBurstWindowSec: 60}}
	var other Config
	if _, err := toml.Decode("[monitoring]\nrejected_burst_destinations = 4\nrejected_burst_window_sec = 15\n", &other); err != nil {
		t.Fatal(err)
	}
	base.Merge(&other)
	if base.Monitoring.RejectedBurstDestinations != 4 || base.Monitoring.RejectedBurstWindowSec != 15 {
		t.Errorf("want 4 / 15, got %d / %d", base.Monitoring.RejectedBurstDestinations, base.Monitoring.RejectedBurstWindowSec)
	}
	base.Merge(&Config{})
	if base.Monitoring.RejectedBurstDestinations != 4 || base.Monitoring.RejectedBurstWindowSec != 15 {
		t.Errorf("unset keys must keep 4 / 15, got %d / %d", base.Monitoring.RejectedBurstDestinations, base.Monitoring.RejectedBurstWindowSec)
	}
}
