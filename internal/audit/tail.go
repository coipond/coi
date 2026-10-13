package audit

import (
	"time"
)

// tailFollow polls c's file for new content forever, emitting each newly
// completed line through c. It returns only on a hard read error or a write
// error (EOF is slept through; a partial line waits in c until completed).
//
// Implementation is a 1-second sleep loop — fsnotify would be more efficient
// but pulls in a dependency. Audit logs are low-frequency (1 record per
// monitor poll interval, default 5s) so polling overhead is negligible.
func tailFollow(c *hostAuditCopier) error {
	for {
		if err := c.drain(); err != nil {
			return err
		}
		time.Sleep(time.Second)
	}
}
