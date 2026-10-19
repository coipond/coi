package container

import (
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"syscall"
)

// stagePushTree recreates the tree at src under dst for `incus file push -r`,
// keeping what the push sends for each entry: mode and owner. Files are hard
// links when src and dst share a filesystem (same inode, no copy), else exact
// copies. Directories are created writable and get their own mode only after
// their contents, so a read-only directory can still be staged.
func stagePushTree(src, dst string) error {
	type dirMode struct {
		path string
		mode fs.FileMode
	}
	var dirs []dirMode
	// WalkDir does not descend into a symlinked root.
	if resolved, err := filepath.EvalSymlinks(src); err == nil {
		src = resolved
	}

	err := filepath.WalkDir(src, func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		rel, err := filepath.Rel(src, p)
		if err != nil {
			return err
		}
		target := filepath.Join(dst, rel)
		info, err := d.Info()
		if err != nil {
			return err
		}
		switch {
		case d.IsDir():
			if err := os.Mkdir(target, 0o700); err != nil {
				return err
			}
			chownLike(target, info)
			dirs = append(dirs, dirMode{target, info.Mode()})
		case d.Type()&fs.ModeSymlink != 0:
			if err := copySymlink(p, target); err != nil {
				return err
			}
			chownLike(target, info)
		case d.Type().IsRegular():
			if os.Link(p, target) == nil { //nolint:gosec // G122: p is in the user's own source tree, target in our private stage dir
				return nil
			}
			if err := copyFileExact(p, target, info); err != nil {
				return err
			}
		}
		// Other entries (FIFOs, sockets, devices) are not staged.
		return nil
	})
	if err != nil {
		return err
	}
	// Deepest first: a parent made read-only must not block its children.
	for i := len(dirs) - 1; i >= 0; i-- {
		if err := os.Chmod(dirs[i].path, dirs[i].mode.Perm()|dirs[i].mode&(fs.ModeSetuid|fs.ModeSetgid|fs.ModeSticky)); err != nil {
			return err
		}
	}
	return nil
}

// copyFileExact copies src to dst with src's mode (not masked by the umask)
// and, when permitted, its owner.
func copyFileExact(src, dst string, info fs.FileInfo) error {
	in, err := os.Open(src)
	if err != nil {
		return err
	}
	defer in.Close()
	out, err := os.OpenFile(dst, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return err
	}
	if _, err := io.Copy(out, in); err != nil {
		_ = out.Close()
		return err
	}
	if err := out.Close(); err != nil {
		return err
	}
	chownLike(dst, info)
	return os.Chmod(dst, info.Mode().Perm()|info.Mode()&(fs.ModeSetuid|fs.ModeSetgid|fs.ModeSticky))
}

// chownLike gives p the owner of info, best-effort: a non-root user can only
// keep its own files' owner, which is then already right.
func chownLike(p string, info fs.FileInfo) {
	if st, ok := info.Sys().(*syscall.Stat_t); ok {
		_ = os.Lchown(p, int(st.Uid), int(st.Gid))
	}
}

// removeStage removes a staged tree, first making its directories writable
// (stagePushTree may have made some read-only). Hard-linked files are only
// unlinked, never changed.
func removeStage(root string) {
	_ = filepath.WalkDir(root, func(p string, d fs.DirEntry, err error) error {
		if err == nil && d.IsDir() {
			_ = os.Chmod(p, 0o700) //nolint:gosec // G122: p is in the private stage dir this process created
		}
		return nil
	})
	_ = os.RemoveAll(root)
}
