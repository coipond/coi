package container

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/url"
	"os"
	"path"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"
)

// ErrPullTimedOut marks a PullDirectoryBounded that hit its total limit. The
// entries pulled before it are kept at localPath.
var ErrPullTimedOut = errors.New("pull timed out")

// ErrPullSourceMissing marks a PullDirectoryBounded whose container
// directory does not exist.
var ErrPullSourceMissing = errors.New("container directory does not exist")

// pullBatchSize caps the sources of one `incus file pull` call.
const pullBatchSize = 200

// treeListTimeout bounds the in-container listing of a pulled tree.
const treeListTimeout = 30 * time.Second

// pullTotalLimit caps a bounded pull that keeps making progress (a device
// that streams forever); a stall is caught much sooner by the stall timeout.
var pullTotalLimit = 30 * time.Minute

// pullMaxSkips caps the entries a bounded pull skips after a stall.
const pullMaxSkips = 64

// pullProgressInterval is how often a running pull is checked for progress.
var pullProgressInterval = time.Second

// PullDirectoryBounded is PullDirectory for a container-controlled tree that
// may hold special files. `incus file pull -r` opens every entry that is not a
// directory or symlink, so a FIFO blocks it forever and a socket fails it.
//
// When the container runs, the tree is listed first: FIFOs, sockets and
// devices are skipped (each reported to debug), and only the directories that
// hold one are walked. A pull that makes no progress for stall (no new entry,
// no new bytes) is stopped; the entry it stalled on is reported to warn,
// skipped, and the pull runs again. A pull that goes on past pullTotalLimit is
// stopped, what was pulled is kept at localPath and the error wraps
// ErrPullTimedOut.
func (m *Manager) PullDirectoryBounded(containerPath, localPath string, stall time.Duration, debug, warn func(string)) error {
	if !strings.HasPrefix(containerPath, "/") {
		containerPath = "/" + containerPath
	}
	containerPath = path.Clean(containerPath)
	if _, err := os.Lstat(localPath); err == nil {
		return fmt.Errorf("destination %q already exists; remove it or choose another name", localPath)
	} else if !os.IsNotExist(err) {
		return err
	}
	if debug == nil {
		debug = func(string) {}
	}
	if warn == nil {
		warn = func(string) {}
	}

	tempDir, err := os.MkdirTemp("", "coi-pull-*")
	if err != nil {
		return err
	}
	defer os.RemoveAll(tempDir)

	ctx, cancel := context.WithTimeout(context.Background(), pullTotalLimit)
	defer cancel()

	p := &boundedPull{m: m, base: containerPath, stall: stall, skip: map[string]bool{}}
	if tree := m.listTree(ctx, containerPath); tree != nil {
		p.tree = tree
		for _, rel := range tree.specials {
			src := path.Join(containerPath, rel)
			p.skip[src] = true
			debug(fmt.Sprintf("Skipping special file %s (type %c)", src, tree.types[rel]))
		}
	}

	root := filepath.Join(tempDir, path.Base(containerPath))
	var pullErr error
	for {
		if err := os.RemoveAll(root); err != nil {
			return err
		}
		pullErr = p.pull(ctx, root)
		var se *stallError
		if !errors.As(pullErr, &se) || ctx.Err() != nil {
			break
		}
		if se.path == containerPath || p.skip[se.path] || len(p.skip) >= pullMaxSkips {
			return fmt.Errorf("pull of %s stalled on %s", containerPath, se.path)
		}
		warn(fmt.Sprintf("Skipping %s: the pull stalled on it for %s", se.path, stall))
		p.skip[se.path] = true
	}

	timedOut := ctx.Err() != nil
	if pullErr != nil && !timedOut {
		if isNotFoundText(pullErr.Error()) {
			if kind, err := m.PathKind(containerPath); err == nil && kind == PathNone {
				return fmt.Errorf("%w: %s", ErrPullSourceMissing, containerPath)
			}
		}
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
		return fmt.Errorf("%w after %s: %v", ErrPullTimedOut, pullTotalLimit, pullErr)
	}
	return nil
}

// boundedPull is one PullDirectoryBounded: the container directory, the
// in-container listing (nil on a stopped container) and the skipped paths.
type boundedPull struct {
	m     *Manager
	base  string
	tree  *pulledTree
	stall time.Duration
	skip  map[string]bool
}

// stallError names the container path a pull stalled on.
type stallError struct {
	path string
}

func (e *stallError) Error() string { return "pull stalled on " + e.path }

// pull pulls base into root, walking only the directories above a skipped
// path.
func (p *boundedPull) pull(ctx context.Context, root string) error {
	if len(p.skip) == 0 {
		return p.pullSources(ctx, []string{p.base}, filepath.Dir(root))
	}
	dirty := map[string]bool{}
	for s := range p.skip {
		for d := path.Dir(s); strings.HasPrefix(d+"/", p.base+"/"); d = path.Dir(d) {
			dirty[d] = true
		}
	}
	return p.pullDirtyDir(ctx, dirty, p.base, root)
}

// pullDirtyDir pulls the container directory dir to local, skipping skipped
// entries and walking only subdirectories that hold one.
func (p *boundedPull) pullDirtyDir(ctx context.Context, dirty map[string]bool, dir, local string) error {
	if err := os.Mkdir(local, 0o700); err != nil {
		return err
	}
	entries, err := p.children(dir)
	if err != nil {
		return err
	}
	var batch []string
	for _, src := range entries {
		switch {
		case p.skip[src]:
		case dirty[src]:
			if err := p.pullDirtyDir(ctx, dirty, src, filepath.Join(local, path.Base(src))); err != nil {
				return err
			}
		case p.tree != nil && p.tree.types[p.rel(src)] == 'l':
			// Dropped from every pulled tree (sanitizePulledTree).
		default:
			batch = append(batch, src)
		}
	}
	for len(batch) > 0 {
		n := min(len(batch), pullBatchSize)
		if err := p.pullSources(ctx, batch[:n], local); err != nil {
			return err
		}
		batch = batch[n:]
	}
	return nil
}

// rel is src relative to base.
func (p *boundedPull) rel(src string) string {
	return strings.TrimPrefix(strings.TrimPrefix(src, p.base), "/")
}

// children lists the container directory dir: from the in-container listing,
// or from the Incus files API on a stopped container.
func (p *boundedPull) children(dir string) ([]string, error) {
	var names []string
	if p.tree != nil {
		for _, rel := range p.tree.children[p.rel(dir)] {
			names = append(names, path.Base(rel))
		}
	} else {
		q := fmt.Sprintf("/1.0/instances/%s/files?project=%s&path=%s",
			url.PathEscape(p.m.ContainerName), url.QueryEscape(IncusProject), url.QueryEscape(dir))
		out, err := p.m.incusQuery("GET", q, "")
		if err != nil {
			return nil, fmt.Errorf("list %s: %w", dir, err)
		}
		if err := json.Unmarshal([]byte(out), &names); err != nil {
			return nil, fmt.Errorf("list %s: %w", dir, err)
		}
	}
	sort.Strings(names)
	srcs := make([]string, len(names))
	for i, n := range names {
		srcs[i] = path.Join(dir, n)
	}
	return srcs, nil
}

// pullSources pulls container paths into localDir in one
// `incus file pull --verbose -r`. The verbose log names each entry as the
// pull reaches it; a pull with no new entry and no new bytes for p.stall is
// stopped with a stallError naming its last entry. Entries listed in the
// container that are gone by the pull are dropped from the batch and pulled
// again without them.
func (p *boundedPull) pullSources(ctx context.Context, sources []string, localDir string) error {
	for {
		err := p.pullOnce(ctx, sources, localDir)
		if err == nil || p.tree == nil || !isNotFoundText(err.Error()) {
			return err
		}
		var kept []string
		for _, s := range sources {
			if ok, statErr := p.m.PathKind(s); statErr != nil || ok == PathNone {
				p.skip[s] = true
				continue
			}
			kept = append(kept, s)
		}
		if len(kept) == len(sources) {
			return err
		}
		if len(kept) == 0 {
			return nil
		}
		sources = kept
	}
}

// pullOnce runs one `incus file pull` with stall detection (see pullSources).
func (p *boundedPull) pullOnce(ctx context.Context, sources []string, localDir string) error {
	args := []string{"file", "pull", "--verbose", "-r"}
	for _, s := range sources {
		args = append(args, p.m.ContainerName+s)
	}
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	cmd := execIncusCommandContext(ctx, buildIncusCommand(append(args, localDir+"/")...))
	pr, pw := io.Pipe()
	cmd.Stderr = pw
	stop := noteIncusCommand(incusArgv(cmd))
	defer stop()
	if err := cmd.Start(); err != nil {
		return err
	}

	var mu sync.Mutex
	var lastSource, lastTarget string
	var errLines []string
	lastProgress := time.Now()
	scanDone := make(chan struct{})
	go func() {
		defer close(scanDone)
		sc := bufio.NewScanner(pr)
		for sc.Scan() {
			line := sc.Text()
			mu.Lock()
			if target, source, ok := parsePullingLine(line, p.base); ok {
				lastTarget, lastSource = target, source
				lastProgress = time.Now()
			} else {
				errLines = append(errLines, line)
			}
			mu.Unlock()
		}
	}()

	stalled := ""
	waitDone := make(chan error, 1)
	go func() {
		err := cmd.Wait()
		_ = pw.Close()
		<-scanDone
		waitDone <- err
	}()
	ticker := time.NewTicker(pullProgressInterval)
	defer ticker.Stop()
	var lastSize int64 = -1
	for {
		select {
		case err := <-waitDone:
			if stalled != "" {
				return &stallError{path: stalled}
			}
			if err == nil {
				return nil
			}
			if ctx.Err() != nil {
				return ctx.Err()
			}
			mu.Lock()
			msg := strings.TrimSpace(strings.Join(errLines, "\n"))
			mu.Unlock()
			if msg != "" {
				return fmt.Errorf("%s: %w", msg, err)
			}
			return err
		case <-ticker.C:
			mu.Lock()
			if fi, err := os.Lstat(lastTarget); err == nil && fi.Mode().IsRegular() && fi.Size() != lastSize {
				lastSize = fi.Size()
				lastProgress = time.Now()
			}
			if stalled == "" && time.Since(lastProgress) > p.stall {
				stalled = lastSource
				if stalled == "" {
					stalled = sources[0]
				}
				cancel()
			}
			mu.Unlock()
		}
	}
}

// parsePullingLine parses the `incus --verbose file pull` line logged as the
// pull reaches an entry: "Pulling <target> from <source> (<type>)". base
// anchors the source, so a " from " inside the target cannot split it.
func parsePullingLine(line, base string) (target, source string, ok bool) {
	i := strings.Index(line, "Pulling ")
	if i < 0 {
		return "", "", false
	}
	rest := line[i+len("Pulling "):]
	j := strings.LastIndex(rest, " from "+base)
	if j < 0 {
		return "", "", false
	}
	target, rest = rest[:j], rest[j+len(" from "):]
	k := strings.LastIndex(rest, " (")
	if k < 0 {
		return "", "", false
	}
	return target, rest[:k], true
}

// isNotFoundText reports whether an incus error says a path does not exist.
func isNotFoundText(msg string) bool {
	msg = strings.ToLower(msg)
	return strings.Contains(msg, "not found") || strings.Contains(msg, "no such file") || strings.Contains(msg, "does not exist")
}

// pulledTree is a container directory listing: entry type and children by
// relative path ("" for the root), and the special files.
type pulledTree struct {
	types    map[string]byte
	children map[string][]string
	specials []string
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
	tree := &pulledTree{types: map[string]byte{}, children: map[string][]string{}}
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
			tree.specials = append(tree.specials, rel)
		}
	}
	return tree
}

// isSpecialType reports whether a find %y type is neither a directory, a
// regular file nor a symlink (FIFO, socket, device, door, unknown).
func isSpecialType(t byte) bool {
	return t != 'd' && t != 'f' && t != 'l'
}
