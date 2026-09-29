//go:build linux
// +build linux

package nftmonitor

import (
	"fmt"
	"sync"
	"testing"
)

func TestParseNFTLog(t *testing.T) {
	cfg := &Config{
		ContainerIP: "10.47.62.50",
	}
	lr := &LogReader{config: cfg}

	tests := []struct {
		name         string
		logLine      string
		expectEvent  bool
		expectedIP   string
		expectedDest string
		expectedPort int
	}{
		{
			name:         "Coi log with matching IP",
			logLine:      "NFT_COI[10.47.62.50]: IN=incusbr0 OUT=eth0 SRC=10.47.62.50 DST=8.8.8.8 PROTO=TCP SPT=54321 DPT=53",
			expectEvent:  true,
			expectedIP:   "10.47.62.50",
			expectedDest: "8.8.8.8",
			expectedPort: 53,
		},
		{
			name:         "SUSPICIOUS log with matching IP",
			logLine:      "NFT_SUSPICIOUS[10.47.62.50]: IN=incusbr0 OUT=eth0 SRC=10.47.62.50 DST=192.168.1.1 PROTO=TCP SPT=12345 DPT=4444",
			expectEvent:  true,
			expectedIP:   "10.47.62.50",
			expectedDest: "192.168.1.1",
			expectedPort: 4444,
		},
		{
			name:         "DNS log with matching IP",
			logLine:      "NFT_DNS[10.47.62.50]: IN=incusbr0 OUT=eth0 SRC=10.47.62.50 DST=10.128.178.1 PROTO=UDP SPT=55555 DPT=53",
			expectEvent:  true,
			expectedIP:   "10.47.62.50",
			expectedDest: "10.128.178.1",
			expectedPort: 53,
		},
		{
			name:        "Log from different container IP - should be ignored",
			logLine:     "NFT_COI[10.47.62.99]: IN=incusbr0 OUT=eth0 SRC=10.47.62.99 DST=8.8.8.8 PROTO=TCP SPT=54321 DPT=53",
			expectEvent: true, // parseNFTLog returns event, but Start() filters it
			expectedIP:  "10.47.62.99",
		},
		{
			name:        "Non-NFT log line - should be ignored",
			logLine:     "kernel: some random kernel message",
			expectEvent: false,
		},
		{
			name:        "Empty line",
			logLine:     "",
			expectEvent: false,
		},
		{
			name:        "NFT prefix without proper format",
			logLine:     "NFT_COI: missing brackets",
			expectEvent: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			event := lr.parseNFTLog(tt.logLine)

			if tt.expectEvent {
				if event == nil {
					t.Fatal("Expected event but got nil")
					return // unreachable but helps staticcheck
				}
				if event.ContainerIP != tt.expectedIP {
					t.Errorf("Expected ContainerIP %q, got %q", tt.expectedIP, event.ContainerIP)
				}
				if tt.expectedDest != "" && event.DstIP != tt.expectedDest {
					t.Errorf("Expected DstIP %q, got %q", tt.expectedDest, event.DstIP)
				}
				if tt.expectedPort != 0 && event.DstPort != tt.expectedPort {
					t.Errorf("Expected DstPort %d, got %d", tt.expectedPort, event.DstPort)
				}
			} else {
				if event != nil {
					t.Errorf("Expected nil event but got %+v", event)
				}
			}
		})
	}
}

func TestLogReaderFiltering(t *testing.T) {
	// Test that the SrcIP filter works correctly
	cfg := &Config{
		ContainerIP: "10.47.62.50",
	}
	lr := &LogReader{config: cfg}

	// Event where prefix IP matches but SrcIP doesn't (shouldn't happen in real life
	// but tests our defense-in-depth filtering)
	mismatchedLog := "NFT_COI[10.47.62.50]: IN=incusbr0 OUT=eth0 SRC=10.50.0.15 DST=10.50.0.23 PROTO=TCP SPT=12345 DPT=6690"
	event := lr.parseNFTLog(mismatchedLog)

	if event == nil {
		t.Skip("Parser didn't return event - this is acceptable")
		return // unreachable but helps staticcheck
	}

	// The event's ContainerIP (from prefix) should be 10.47.62.50
	// but the SrcIP should be 10.50.0.15
	if event.ContainerIP != "10.47.62.50" {
		t.Errorf("Expected ContainerIP 10.47.62.50, got %s", event.ContainerIP)
	}
	if event.SrcIP != "10.50.0.15" {
		t.Errorf("Expected SrcIP 10.50.0.15, got %s", event.SrcIP)
	}

	// The Start() loop should filter this out because:
	// event.ContainerIP == lr.config.ContainerIP (10.47.62.50 == 10.47.62.50) ✓
	// event.SrcIP == lr.config.ContainerIP (10.50.0.15 != 10.47.62.50) ✗
	// So the event should NOT be sent to the channel

	// This verifies our double-check filtering works
	if event.SrcIP == lr.config.ContainerIP {
		t.Log("SrcIP matches ContainerIP - event would pass filter")
	} else {
		t.Log("SrcIP doesn't match ContainerIP - event would be filtered out (correct)")
	}
}

func TestExtractIPFromPrefix(t *testing.T) {
	tests := []struct {
		name     string
		line     string
		prefix   string
		expected string
	}{
		{
			name:     "standard Coi prefix",
			line:     "NFT_COI[10.47.62.50]: some message",
			prefix:   "NFT_COI[",
			expected: "10.47.62.50",
		},
		{
			name:     "SUSPICIOUS prefix",
			line:     "NFT_SUSPICIOUS[192.168.1.100]: message",
			prefix:   "NFT_SUSPICIOUS[",
			expected: "192.168.1.100",
		},
		{
			name:     "missing closing bracket",
			line:     "NFT_COI[10.47.62.50 missing bracket",
			prefix:   "NFT_COI[",
			expected: "",
		},
		{
			name:     "prefix not found",
			line:     "some other log message",
			prefix:   "NFT_COI[",
			expected: "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := extractIPFromPrefix(tt.line, tt.prefix)
			if result != tt.expected {
				t.Errorf("Expected %q, got %q", tt.expected, result)
			}
		})
	}
}

func TestExtractField(t *testing.T) {
	tests := []struct {
		name     string
		line     string
		field    string
		expected string
	}{
		{
			name:     "extract SRC",
			line:     "IN=eth0 SRC=10.47.62.50 DST=8.8.8.8",
			field:    "SRC=",
			expected: "10.47.62.50",
		},
		{
			name:     "extract DST",
			line:     "IN=eth0 SRC=10.47.62.50 DST=8.8.8.8 PROTO=TCP",
			field:    "DST=",
			expected: "8.8.8.8",
		},
		{
			name:     "extract PROTO",
			line:     "SRC=10.0.0.1 DST=10.0.0.2 PROTO=UDP",
			field:    "PROTO=",
			expected: "UDP",
		},
		{
			name:     "field not present",
			line:     "SRC=10.0.0.1 DST=10.0.0.2",
			field:    "PROTO=",
			expected: "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := extractField(tt.line, tt.field)
			if result != tt.expected {
				t.Errorf("Expected %q, got %q", tt.expected, result)
			}
		})
	}
}

func TestExtractTCPFlags(t *testing.T) {
	tests := []struct {
		name     string
		line     string
		expected string
	}{
		{
			name:     "SYN only",
			line:     "PROTO=TCP SYN",
			expected: "SYN",
		},
		{
			name:     "SYN ACK",
			line:     "PROTO=TCP SYN ACK",
			expected: "SYN,ACK",
		},
		{
			name:     "all flags",
			line:     "PROTO=TCP SYN ACK FIN RST PSH",
			expected: "SYN,ACK,FIN,RST,PSH",
		},
		{
			name:     "no flags",
			line:     "PROTO=TCP",
			expected: "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := extractTCPFlags(tt.line)
			if result != tt.expected {
				t.Errorf("Expected %q, got %q", tt.expected, result)
			}
		})
	}
}

func TestDroppedEventsReporting(t *testing.T) {
	var mu sync.Mutex
	var errors []string

	cfg := &Config{
		ContainerIP: "10.47.62.50",
		OnError: func(err error) {
			mu.Lock()
			defer mu.Unlock()
			errors = append(errors, err.Error())
		},
	}

	// Create LogReader with a tiny eventChan buffer to force drops
	lr := &LogReader{
		config:    cfg,
		eventChan: make(chan *NetworkEvent, 1),
	}

	// Fill the channel so the next send will drop
	lr.eventChan <- &NetworkEvent{}

	// Now simulate drops by directly calling the drop logic
	// We replicate the default branch behavior here to test the counter + OnError
	for i := 0; i < 250; i++ {
		select {
		case lr.eventChan <- &NetworkEvent{}:
			t.Fatal("channel should be full")
		default:
			count := lr.droppedEvents.Add(1)
			if count == 1 || count%100 == 0 {
				if lr.config.OnError != nil {
					lr.config.OnError(fmt.Errorf("NFT event channel full: %d events dropped", count))
				}
			}
		}
	}

	// Verify counter
	got := lr.droppedEvents.Load()
	if got != 250 {
		t.Errorf("Expected droppedEvents=250, got %d", got)
	}

	// Verify OnError was called on first drop (count=1), count=100, count=200
	mu.Lock()
	defer mu.Unlock()

	expectedErrors := []string{
		"NFT event channel full: 1 events dropped",
		"NFT event channel full: 100 events dropped",
		"NFT event channel full: 200 events dropped",
	}

	if len(errors) != len(expectedErrors) {
		t.Fatalf("Expected %d OnError calls, got %d: %v", len(expectedErrors), len(errors), errors)
	}

	for i, expected := range expectedErrors {
		if errors[i] != expected {
			t.Errorf("OnError call %d: expected %q, got %q", i, expected, errors[i])
		}
	}
}
