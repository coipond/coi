package audit

import (
	"context"
	"time"
)

// tailFollow polls c's file for new content until ctx is done, emitting each
// newly completed line through c. It returns nil when ctx is done, and an
// error on a hard read error or a write error (EOF is slept through; a partial
// line waits in c until completed).
//
// Implementation is a 1-second poll loop — fsnotify would be more efficient
// but pulls in a dependency. Audit logs are low-frequency (1 record per
// monitor poll interval, default 5s) so polling overhead is negligible.
func tailFollow(ctx context.Context, c *hostAuditCopier) error {
	ticker := time.NewTicker(time.Second)
	defer ticker.Stop()
	for {
		if err := c.drain(); err != nil {
			return err
		}
		select {
		case <-ctx.Done():
			return nil
		case <-ticker.C:
		}
	}
}
