package container

import (
	"context"
	"strings"
	"time"
)

// StartLogErrors returns the first maxLines ERROR lines of the container's last
// start log (`incus info --show-log`, i.e. lxc.log). The first errors are the
// cause (e.g. a mount that failed); the later ones are its fallout (setup
// failed, state ABORTING, ...). It is a diagnostic: any failure to read the log
// yields nil.
func StartLogErrors(containerName string, maxLines int) []string {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	out, err := IncusOutputContext(ctx, "info", "--show-log", containerName)
	if err != nil {
		return nil
	}
	return parseStartLogErrors(out, maxLines)
}

// parseStartLogErrors extracts the ERROR entries from `incus info --show-log`
// output. Each lxc.log line reads
//
//	lxc <container> <timestamp> ERROR    <component> - <source> - <message>
//
// and is returned from the level on ("ERROR utils - ... - Failed to mount ..."),
// with runs of spaces collapsed.
func parseStartLogErrors(out string, maxLines int) []string {
	_, logPart, found := strings.Cut(out, "Log (lxc.log):")
	if !found {
		return nil
	}
	var errs []string
	for _, line := range strings.Split(logPart, "\n") {
		idx := strings.Index(line, " ERROR ")
		if idx < 0 {
			continue
		}
		errs = append(errs, strings.Join(strings.Fields(line[idx+1:]), " "))
	}
	if maxLines > 0 && len(errs) > maxLines {
		errs = errs[:maxLines]
	}
	return errs
}
