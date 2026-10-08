//go:build linux
// +build linux

package nftmonitor

import (
	"context"
	"fmt"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

// debugf is defined in journalctl.go

// LogReader reads and parses nftables logs from journald
type LogReader struct {
	config        *Config
	journal       *JournalReader
	eventChan     chan *NetworkEvent
	journalChan   chan string
	closeOnce     sync.Once
	droppedEvents atomic.Int64
}

// NewLogReader creates a new log reader
func NewLogReader(cfg *Config) (*LogReader, error) {
	journal, err := NewJournalReader()
	if err != nil {
		return nil, fmt.Errorf("failed to create journal reader: %w", err)
	}

	return &LogReader{
		config:      cfg,
		journal:     journal,
		eventChan:   make(chan *NetworkEvent, 1000),
		journalChan: make(chan string, 1000),
	}, nil
}

// Start begins reading and parsing logs
func (lr *LogReader) Start(ctx context.Context) error {
	debugf("LogReader.Start called, container IP: %s", lr.config.ContainerIP)

	// Start journal streaming in background. Don't return before it has
	// stopped: it closes the sd-journal handle on exit, and the daemon's Stop
	// runs nft right after Start returns — that must not overlap the C
	// library tearing the journal down (see JournalReader).
	streamDone := make(chan struct{})
	go func() {
		defer close(streamDone)
		if err := lr.journal.StreamLogs(ctx, lr.journalChan); err != nil {
			if ctx.Err() == nil && lr.config.OnError != nil {
				lr.config.OnError(fmt.Errorf("journal streaming error: %w", err))
			}
		}
	}()
	defer func() { <-streamDone }()

	// Parse incoming log messages
	for {
		select {
		case <-ctx.Done():
			debugf("LogReader context done")
			return ctx.Err()
		case msg := <-lr.journalChan:
			debugf("LogReader received message from journal")
			if event := lr.parseNFTLog(msg); event != nil {
				debugf("Parsed event: ContainerIP=%s SrcIP=%s DstIP=%s DstPort=%d",
					event.ContainerIP, event.SrcIP, event.DstIP, event.DstPort)
				// Filter to only this container's IP
				// Check both the prefix IP and the actual SRC IP match
				if event.ContainerIP == lr.config.ContainerIP &&
					event.SrcIP == lr.config.ContainerIP {
					debugf("Event matches container IP, sending to event channel")
					select {
					case lr.eventChan <- event:
						debugf("Event sent to channel")
					case <-ctx.Done():
						return ctx.Err()
					default:
						count := lr.droppedEvents.Add(1)
						debugf("Event channel full, dropping event (total dropped: %d)", count)
						if count == 1 || count%100 == 0 {
							if lr.config.OnError != nil {
								lr.config.OnError(fmt.Errorf("NFT event channel full: %d events dropped", count))
							}
						}
					}
				} else {
					debugf("Event IP mismatch: event.ContainerIP=%s event.SrcIP=%s config.ContainerIP=%s",
						event.ContainerIP, event.SrcIP, lr.config.ContainerIP)
				}
			} else {
				// Check if the message contains NFT prefix but parsing failed
				if strings.Contains(msg, "NFT_") {
					debugf("Message contains NFT_ but parsing returned nil: %s", msg)
				}
			}
		}
	}
}

// Events returns the channel for receiving parsed network events
func (lr *LogReader) Events() <-chan *NetworkEvent {
	return lr.eventChan
}

// Close closes the log reader (safe to call multiple times)
func (lr *LogReader) Close() error {
	var closeErr error
	lr.closeOnce.Do(func() {
		// Close journal first - this will cause StreamLogs to exit
		if lr.journal != nil {
			closeErr = lr.journal.Close()
		}
		// Note: Don't close channels here as StreamLogs goroutine may still
		// be trying to write. Let them be garbage collected when no longer referenced.
	})
	return closeErr
}

// parseNFTLog parses a nftables kernel log message into a NetworkEvent
// Example log: "NFT_COI[10.47.62.50]: IN=incusbr0 OUT=eth0 SRC=10.47.62.50 DST=8.8.8.8 PROTO=TCP SPT=54321 DPT=53 SYN"
func (lr *LogReader) parseNFTLog(line string) *NetworkEvent {
	// Check for our log prefixes
	var containerIP string
	if strings.Contains(line, "NFT_COI[") {
		containerIP = extractIPFromPrefix(line, "NFT_COI[")
	} else if strings.Contains(line, "NFT_DNS[") {
		containerIP = extractIPFromPrefix(line, "NFT_DNS[")
	} else if strings.Contains(line, "NFT_SUSPICIOUS[") {
		containerIP = extractIPFromPrefix(line, "NFT_SUSPICIOUS[")
	} else {
		return nil
	}

	if containerIP == "" {
		return nil
	}

	// Extract fields
	event := &NetworkEvent{
		Timestamp:   time.Now(),
		ContainerIP: containerIP,
		SrcIP:       extractField(line, "SRC="),
		DstIP:       extractField(line, "DST="),
		Protocol:    extractField(line, "PROTO="),
		Interface:   extractField(line, "IN=") + "/" + extractField(line, "OUT="),
	}

	// Extract ports
	if spt := extractField(line, "SPT="); spt != "" {
		if port, err := strconv.Atoi(spt); err == nil {
			event.SrcPort = port
		}
	}
	if dpt := extractField(line, "DPT="); dpt != "" {
		if port, err := strconv.Atoi(dpt); err == nil {
			event.DstPort = port
		}
	}

	// Extract TCP flags
	event.Flags = extractTCPFlags(line)

	return event
}

// extractIPFromPrefix extracts IP from prefix like "NFT_COI[10.47.62.50]"
func extractIPFromPrefix(line, prefix string) string {
	start := strings.Index(line, prefix)
	if start == -1 {
		return ""
	}
	start += len(prefix)
	end := strings.Index(line[start:], "]")
	if end == -1 {
		return ""
	}
	return line[start : start+end]
}

// extractField extracts a field value from log line
// Example: "SRC=10.47.62.50" -> "10.47.62.50"
func extractField(line, field string) string {
	re := regexp.MustCompile(field + `([^\s]+)`)
	matches := re.FindStringSubmatch(line)
	if len(matches) > 1 {
		return matches[1]
	}
	return ""
}

// extractTCPFlags extracts TCP flags from log line
func extractTCPFlags(line string) string {
	flags := []string{}
	if strings.Contains(line, " SYN ") || strings.HasSuffix(line, " SYN") {
		flags = append(flags, "SYN")
	}
	if strings.Contains(line, " ACK ") || strings.HasSuffix(line, " ACK") {
		flags = append(flags, "ACK")
	}
	if strings.Contains(line, " FIN ") || strings.HasSuffix(line, " FIN") {
		flags = append(flags, "FIN")
	}
	if strings.Contains(line, " RST ") || strings.HasSuffix(line, " RST") {
		flags = append(flags, "RST")
	}
	if strings.Contains(line, " PSH ") || strings.HasSuffix(line, " PSH") {
		flags = append(flags, "PSH")
	}
	return strings.Join(flags, ",")
}
