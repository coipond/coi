package container

import (
	"archive/tar"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path"
	"path/filepath"
	"strings"

	"github.com/coipond/coi/internal/timing"
)

// Limits on a streamed directory pull. The stream is container-controlled, so
// it must not be able to fill the host disk or exhaust inodes.
const (
	maxTarPullBytes   int64 = 8 << 30 // 8 GiB of file content
	maxTarPullEntries       = 500_000
)

// errTarPullUnsafe marks a stream the extractor refused (path escape, limit).
var errTarPullUnsafe = errors.New("unsafe tar stream")

// PullDirectoryTar copies containerPath (a directory) from a RUNNING
// container to localPath in ONE `incus exec … tar -c` stream, instead of
// `incus file pull -r`, which walks the tree file by file over SFTP and takes
// seconds for a busy ~/.claude.
//
// The stream is untrusted, so extraction is strict: only directories and
// regular files are materialized (symlinks, hard links, devices, FIFOs are
// dropped — the same rule sanitizePulledTree applies to `file pull`), every
// name must stay inside the pulled directory, modes keep only rwx bits, and
// total size and entry count are capped. Extraction goes to a temp directory
// first, so a failed pull never leaves a partial tree at localPath. Like
// PullDirectory, it refuses an existing localPath.
func (m *Manager) PullDirectoryTar(containerPath, localPath string) error {
	if _, err := os.Lstat(localPath); err == nil {
		return fmt.Errorf("destination %q already exists; remove it or choose another name", localPath)
	} else if !os.IsNotExist(err) {
		return err
	}
	clean := path.Clean(containerPath)
	parent, base := path.Dir(clean), path.Base(clean)
	if !path.IsAbs(clean) || base == "/" || base == "." || base == ".." {
		return fmt.Errorf("invalid container directory %q", containerPath)
	}

	tempDir, err := os.MkdirTemp(filepath.Dir(localPath), ".coi-pull-*")
	if err != nil {
		return err
	}
	defer os.RemoveAll(tempDir)

	argv := buildIncusCommand("exec", m.ContainerName, "--", "tar", "-C", parent, "-cf", "-", base)
	cmd := execIncusCommand(argv)
	var stderr strings.Builder
	cmd.Stderr = &stderr
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		return err
	}
	stop := timing.Start(timing.CatIncus, "exec tar -c "+clean)
	defer stop()
	if err := cmd.Start(); err != nil {
		return err
	}
	extractErr := extractTarStrict(stdout, tempDir, base)
	if extractErr != nil {
		_ = cmd.Process.Kill()
		_, _ = io.Copy(io.Discard, stdout)
	}
	waitErr := cmd.Wait()
	if extractErr != nil {
		return fmt.Errorf("tar pull of %s: %w", clean, extractErr)
	}
	if waitErr != nil && !tarSoftFailure(waitErr) {
		msg := strings.TrimSpace(stderr.String())
		return fmt.Errorf("tar pull of %s failed: %w: %s", clean, waitErr, msg)
	}

	pulled := filepath.Join(tempDir, base)
	if fi, err := os.Lstat(pulled); err != nil || !fi.IsDir() {
		return fmt.Errorf("tar pull of %s: no directory in stream", clean)
	}
	return os.Rename(pulled, localPath)
}

// tarSoftFailure reports GNU tar's exit status 1 ("some files differ" — a file
// changed while being read, routine for a live tool config dir): the archive
// is complete and usable.
func tarSoftFailure(err error) bool {
	var exitErr *exec.ExitError
	return errors.As(err, &exitErr) && exitErr.ExitCode() == 1
}

// extractTarStrict extracts r into dir, accepting only directories and regular
// files whose names lie inside base/ (see PullDirectoryTar).
func extractTarStrict(r io.Reader, dir, base string) error {
	tr := tar.NewReader(r)
	var total int64
	entries := 0
	for {
		hdr, err := tr.Next()
		if err == io.EOF {
			return nil
		}
		if err != nil {
			return err
		}
		entries++
		if entries > maxTarPullEntries {
			return fmt.Errorf("%w: more than %d entries", errTarPullUnsafe, maxTarPullEntries)
		}

		rel, ok := safeTarName(hdr.Name, base)
		if !ok {
			return fmt.Errorf("%w: entry %q escapes %s", errTarPullUnsafe, hdr.Name, base)
		}
		target := filepath.Join(dir, filepath.FromSlash(rel))
		mode := os.FileMode(hdr.Mode & 0o777) //nolint:gosec // G115: masked to the 9 permission bits

		switch hdr.Typeflag {
		case tar.TypeDir:
			if err := os.MkdirAll(target, 0o700); err != nil {
				return err
			}
			// Owner keeps full access so later entries can be written; the
			// pulled tree only ever needs to be read back by coi.
			if err := os.Chmod(target, mode|0o700); err != nil {
				return err
			}
		case tar.TypeReg, tar.TypeRegA: //nolint:staticcheck // TypeRegA: old archives
			total += hdr.Size
			if hdr.Size < 0 || total > maxTarPullBytes {
				return fmt.Errorf("%w: more than %d bytes", errTarPullUnsafe, maxTarPullBytes)
			}
			if err := os.MkdirAll(filepath.Dir(target), 0o700); err != nil {
				return err
			}
			f, err := os.OpenFile(target, os.O_CREATE|os.O_EXCL|os.O_WRONLY, mode|0o600) //nolint:gosec // G304: target validated by safeTarName
			if err != nil {
				return err
			}
			_, copyErr := io.CopyN(f, tr, hdr.Size)
			closeErr := f.Close()
			if copyErr != nil {
				return copyErr
			}
			if closeErr != nil {
				return closeErr
			}
		default:
			// symlink / hard link / device / FIFO / other: never materialized.
			fmt.Fprintf(os.Stderr, "Warning: dropping non-regular entry from pulled content: %s\n", hdr.Name)
		}
	}
}

// safeTarName validates a tar member name: it must be base or lie under base/,
// relative, with no "..", and returns it cleaned (slash-separated).
func safeTarName(name, base string) (string, bool) {
	if name == "" || strings.HasPrefix(name, "/") || strings.Contains(name, "\x00") {
		return "", false
	}
	for _, seg := range strings.Split(name, "/") {
		if seg == ".." {
			return "", false
		}
	}
	clean := path.Clean(strings.TrimPrefix(name, "./"))
	if clean != base && !strings.HasPrefix(clean, base+"/") {
		return "", false
	}
	return clean, true
}
