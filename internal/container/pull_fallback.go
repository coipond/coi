package container

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"os"
	"path"
	"path/filepath"
	"sort"
	"strings"
	"time"
)

// ErrPullTimedOut marks a PullDirectoryBounded that hit its deadline. The
// entries pulled before the stall are kept at localPath.
var ErrPullTimedOut = errors.New("pull timed out")

// pullBatchSize caps the sources of one `incus file pull` call.
const pullBatchSize = 200

// treeListTimeout bounds the in-container listing of a pulled tree.
const treeListTimeout = 30 * time.Second

// PullDirectoryBounded is PullDirectory for a container-controlled tree that
// may hold special files. `incus file pull -r` opens every entry that is not a
// directory or symlink, so a FIFO blocks it forever and a socket fails it.
// When the container runs, the tree is listed first: FIFOs, sockets and
// devices are skipped (each reported to debug), and only the directories
// that hold one are walked entry by entry. The whole pull is bounded by
// timeout: on expiry the pull is stopped, what was pulled is kept at
// localPath and the error wraps ErrPullTimedOut with the stalled path.
func (m *Manager) PullDirectoryBounded(containerPath, localPath string, timeout time.Duration, debug func(string)) error {
	if !strings.HasPrefix(containerPath, "/") {
		containerPath = "/" + containerPath
	}
	containerPath = path.Clean(containerPath)
	if _, err := os.Lstat(localPath); err == nil {
		return fmt.Errorf("destination %q already exists; remove it or choose another name", localPath)
	} else if !os.IsNotExist(err) {
		return err
	}

	tempDir, err := os.MkdirTemp("", "coi-pull-*")
	if err != nil {
		return err
	}
	defer os.RemoveAll(tempDir)

	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()

	root := filepath.Join(tempDir, path.Base(containerPath))
	var pullErr error
	tree := m.listTree(ctx, containerPath)
	if tree == nil || len(tree.dirty) == 0 {
		pullErr = m.pullSources(ctx, []string{containerPath}, tempDir, true)
	} else {
		if err := os.Mkdir(root, 0o700); err != nil {
			return err
		}
		pullErr = m.pullDirtyDir(ctx, tree, containerPath, "", root, debug)
	}

	timedOut := ctx.Err() != nil
	if pullErr != nil && !timedOut {
		return pullErr
	}
	if _, err := os.Lstat(root); err != nil {
		if timedOut {
			return fmt.Errorf("%w: %v", ErrPullTimedOut, pullErr)
		}
		return fmt.Errorf("no files pulled")
	}
	sanitizePulledTree(root)
	if err := os.MkdirAll(filepath.Dir(localPath), 0o755); err != nil {
		return err
	}
	if err := renameOrCopy(root, localPath, copyDirRecursive); err != nil {
		return err
	}
	if timedOut {
		return fmt.Errorf("%w: %v", ErrPullTimedOut, pullErr)
	}
	return nil
}

// pulledTree is a container directory listing: entry type by relative path,
// and the directories (relative, "" for the root) that hold a special file.
type pulledTree struct {
	types    map[string]byte
	children map[string][]string
	dirty    map[string]bool
}

// listTree lists containerPath with find in the container. It returns nil
// when the listing fails (the container is stopped, find is missing).
func (m *Manager) listTree(ctx context.Context, containerPath string) *pulledTree {
	ctx, cancel := context.WithTimeout(ctx, treeListTimeout)
	defer cancel()
	argv := buildIncusCommand("exec", m.ContainerName, "--",
		"find", containerPath, "-mindepth", "1", "-printf", `%y/%P\0`)
	cmd := execIncusCommandContext(ctx, argv)
	var stdout bytes.Buffer
	cmd.Stdout = &stdout
	if err := runIncus(cmd); err != nil {
		return nil
	}
	return parseTreeListing(stdout.Bytes())
}

// parseTreeListing parses find's `%y/%P\0` records (see listTree).
func parseTreeListing(out []byte) *pulledTree {
	tree := &pulledTree{types: map[string]byte{}, children: map[string][]string{}, dirty: map[string]bool{}}
	for _, rec := range bytes.Split(out, []byte{0}) {
		if len(rec) < 3 || rec[1] != '/' {
			continue
		}
		rel := string(rec[2:])
		tree.types[rel] = rec[0]
		parent := path.Dir(rel)
		if parent == "." {
			parent = ""
		}
		tree.children[parent] = append(tree.children[parent], rel)
		if isSpecialType(rec[0]) {
			for d := parent; ; d = path.Dir(d) {
				if d == "." {
					d = ""
				}
				tree.dirty[d] = true
				if d == "" {
					break
				}
			}
		}
	}
	return tree
}

// isSpecialType reports whether a find %y type is neither a directory, a
// regular file nor a symlink (FIFO, socket, device, door, unknown).
func isSpecialType(t byte) bool {
	return t != 'd' && t != 'f' && t != 'l'
}

// pullDirtyDir pulls the directory rel (local copy at local), skipping
// special files and walking only subdirectories that hold one.
func (m *Manager) pullDirtyDir(ctx context.Context, tree *pulledTree, base, rel, local string, debug func(string)) error {
	var files, dirs []string
	entries := tree.children[rel]
	sort.Strings(entries)
	for _, e := range entries {
		src := path.Join(base, e)
		switch t := tree.types[e]; {
		case t == 'd' && tree.dirty[e]:
			sub := filepath.Join(local, path.Base(e))
			if err := os.Mkdir(sub, 0o700); err != nil {
				return err
			}
			if err := m.pullDirtyDir(ctx, tree, base, e, sub, debug); err != nil {
				return err
			}
		case t == 'd':
			dirs = append(dirs, src)
		case t == 'f':
			files = append(files, src)
		case t == 'l':
			// Dropped from every pulled tree (sanitizePulledTree).
		default:
			if debug != nil {
				debug(fmt.Sprintf("Skipping special file %s (type %c)", src, t))
			}
		}
	}
	if err := m.pullBatches(ctx, files, local, false); err != nil {
		return err
	}
	return m.pullBatches(ctx, dirs, local, true)
}

// pullBatches runs pullSources over sources, pullBatchSize at a time.
func (m *Manager) pullBatches(ctx context.Context, sources []string, localDir string, recursive bool) error {
	for len(sources) > 0 {
		n := min(len(sources), pullBatchSize)
		if err := m.pullSources(ctx, sources[:n], localDir, recursive); err != nil {
			return err
		}
		sources = sources[n:]
	}
	return nil
}

// pullSources pulls container paths into localDir in one `incus file pull`.
// On a deadline the error names the first source not yet on the host, the
// one the pull stalled on.
func (m *Manager) pullSources(ctx context.Context, sources []string, localDir string, recursive bool) error {
	args := []string{"file", "pull"}
	if recursive {
		args = append(args, "-r")
	}
	for _, s := range sources {
		args = append(args, m.ContainerName+s)
	}
	cmd := execIncusCommandContext(ctx, buildIncusCommand(append(args, localDir+"/")...))
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	err := runIncus(cmd)
	if err == nil {
		return nil
	}
	if ctx.Err() != nil {
		stalled := sources[len(sources)-1]
		for _, s := range sources {
			if _, statErr := os.Lstat(filepath.Join(localDir, path.Base(s))); statErr != nil {
				stalled = s
				break
			}
		}
		return fmt.Errorf("stalled on %s", stalled)
	}
	if msg := strings.TrimSpace(stderr.String()); msg != "" {
		return fmt.Errorf("%s: %w", msg, err)
	}
	return err
}
