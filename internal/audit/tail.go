package audit

import (
	"io"
	"os"
	"time"
)

// tailFollow polls f for new content forever, decoding each new JSON line and
// re-emitting it on out with sessionID/container stamped on. It returns only
// on a hard read error (other than EOF, which it sleeps through).
//
// Implementation is a 1-second sleep loop — fsnotify would be more efficient
// but pulls in a dependency. Audit logs are low-frequency (1 record per
// monitor poll interval, default 5s) so polling overhead is negligible.
func tailFollow(f *os.File, sessionID, container string, out io.Writer) error {
	for {
		err := copyHostAuditLines(f, sessionID, container, out)
		if err != nil && err != io.EOF {
			return err
		}
		time.Sleep(time.Second)
	}
}
