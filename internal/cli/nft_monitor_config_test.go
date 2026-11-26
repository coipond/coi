package cli

import (
	"testing"

	"github.com/coipond/coi/internal/config"
)

// The nft monitor gets the [monitoring] rejected_burst_* settings.
func TestNFTMonitorConfig_RejectedBurst(t *testing.T) {
	cfg := &config.Config{Monitoring: config.MonitoringConfig{RejectedBurstDestinations: 4, RejectedBurstWindowSec: 15}}
	got := nftMonitorConfig(cfg, "c1", "10.0.0.2", "10.0.0.1", "/tmp/c1-nft.jsonl", nil, nil, nil)
	if got.RejectedBurstDestinations != 4 || got.RejectedBurstWindowSec != 15 {
		t.Errorf("want 4 / 15, got %d / %d", got.RejectedBurstDestinations, got.RejectedBurstWindowSec)
	}
}
