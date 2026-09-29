package cli

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/mensfeld/coi/internal/container"
	"github.com/spf13/cobra"
)

// fileCmd is the parent command for all file operations
var fileCmd = &cobra.Command{
	Use:   "file",
	Short: "Transfer files to/from containers",
	Long:  `Push and pull files and directories between the host and containers.`,
}

// filePushCmd pushes files/directories into a container
var filePushCmd = &cobra.Command{
	Use:   "push <local-path> <container>:<remote-path>",
	Short: "Push a file or directory into a container",
	Long: `Push a file or directory from the host into a container.

Examples:
  # Push file
  coi file push ./config.json my-container:/workspace/config.json

  # Push directory
  coi file push -r ./src my-container:/workspace/src`,
	Args: cobra.ExactArgs(2),
	RunE: func(cmd *cobra.Command, args []string) error {
		localPath := args[0]
		destination := args[1]

		recursive, _ := cmd.Flags().GetBool("recursive")

		// Parse destination (container:path)
		parts := strings.SplitN(destination, ":", 2)
		if len(parts) != 2 {
			return &ExitCodeError{Code: 2, Message: "destination must be in format 'container:path'"}
		}
		containerName := parts[0]
		remotePath := parts[1]

		mgr := container.NewManager(containerName)

		// Check if source exists
		info, err := os.Stat(localPath)
		if err != nil {
			return fmt.Errorf("source does not exist: %v", err)
		}

		// Push file or directory
		if info.IsDir() {
			if !recursive {
				return &ExitCodeError{Code: 2, Message: "source is a directory, use -r flag"}
			}
			if err := mgr.PushDirectory(localPath, remotePath); err != nil {
				return fmt.Errorf("failed to push directory: %v", err)
			}
			fmt.Fprintf(os.Stderr, "Pushed directory %s -> %s:%s\n", localPath, containerName, remotePath)
		} else {
			if err := mgr.PushFile(localPath, remotePath); err != nil {
				return fmt.Errorf("failed to push file: %v", err)
			}
			fmt.Fprintf(os.Stderr, "Pushed file %s -> %s:%s\n", localPath, containerName, remotePath)
		}

		return nil
	},
}

// filePullCmd pulls files/directories from a container
var filePullCmd = &cobra.Command{
	Use:   "pull <container>:<remote-path> <local-path>",
	Short: "Pull a file or directory from a container",
	Long: `Pull a file or directory from a container to the host.

Examples:
  # Pull a file into the current directory
  coi file pull my-container:/tmp/results.txt .

  # Pull a file to an exact path (overwrites an existing file)
  coi file pull my-container:/tmp/results.txt ./results-v2.txt

  # Pull a directory (e.g., save Claude session data)
  coi file pull -r my-container:/root/.claude ./saved-sessions/session-123`,
	Args: cobra.ExactArgs(2),
	RunE: func(cmd *cobra.Command, args []string) error {
		source := args[0]
		localPath := args[1]

		recursive, _ := cmd.Flags().GetBool("recursive")

		// Parse source (container:path)
		parts := strings.SplitN(source, ":", 2)
		if len(parts) != 2 {
			return &ExitCodeError{Code: 2, Message: "source must be in format 'container:path'"}
		}
		containerName := parts[0]
		remotePath := parts[1]

		// Resolve the exact final target and enforce the overwrite policy
		// before any transfer, so a bad destination fails with nothing touched.
		target, err := resolvePullDestination(localPath, remotePath, recursive)
		if err != nil {
			return &ExitCodeError{Code: 2, Message: err.Error()}
		}

		mgr := container.NewManager(containerName)

		if recursive {
			if err := mgr.PullDirectory(remotePath, target); err != nil {
				return fmt.Errorf("failed to pull directory: %v", err)
			}
			fmt.Fprintf(os.Stderr, "Pulled directory %s:%s -> %s\n", containerName, remotePath, target)
		} else {
			if err := mgr.PullFile(remotePath, target); err != nil {
				if errors.Is(err, container.ErrRemoteIsDirectory) {
					return fmt.Errorf("failed to pull file: %v (to pull a directory, use -r)", err)
				}
				return fmt.Errorf("failed to pull file: %v", err)
			}
			fmt.Fprintf(os.Stderr, "Pulled file %s:%s -> %s\n", containerName, remotePath, target)
		}

		return nil
	},
}

// resolvePullDestination enforces the overwrite policy for `coi file pull`,
// returning the final host path the pulled entry will be renamed to.
//
// Rules:
//   - A trailing separator requires an existing directory: fail fast otherwise.
//   - An existing-directory destination means "place the pulled entry inside it",
//     like cp/scp/incus convention: final target is <localPath>/<base(remote)>.
//   - The final target must not already exist, with one exception:
//     a single file pull may overwrite an existing non-directory.
//   - Symlinks are never followed: a symlink destination is treated as the link
//     itself (a single file pull replaces the link; it is never written through
//     into the link's target), so content can never land outside the given tree.
//   - Nothing is ever deleted on the user's behalf:
//     replacing a directory always requires removing it explicitly first.
func resolvePullDestination(localPath, remotePath string, recursive bool) (string, error) {
	base := filepath.Base(strings.TrimSuffix(remotePath, "/"))
	if base == "/" || base == "." || base == ".." || base == "" {
		return "", fmt.Errorf("cannot derive a file name from remote path %q", remotePath)
	}

	trailingSep := strings.HasSuffix(localPath, "/")
	// Lstat a slash-trimmed path, never Stat: judge a symlink as the link itself and
	// never follow it. Stat — or even Lstat on a path with a trailing slash, which
	// the kernel resolves as a directory — would follow a symlink-to-directory and
	// write the pulled entry THROUGH the link, landing content outside the visible
	// tree. Only a real directory means "place inside"; a symlink is handled by the
	// overwrite policy below (a single-file pull may replace the link; recursive
	// refuses), so content can never escape the given path.
	statPath := strings.TrimRight(localPath, "/")
	if statPath == "" {
		statPath = localPath
	}
	info, statErr := os.Lstat(statPath)
	switch {
	case statErr == nil && info.IsDir():
		localPath = filepath.Join(statPath, base)
	case statErr == nil && trailingSep:
		return "", fmt.Errorf("destination %q is not a directory", localPath)
	case statErr != nil && !os.IsNotExist(statErr):
		return "", statErr
	case statErr != nil && trailingSep:
		return "", fmt.Errorf("destination %q does not exist: a trailing slash requires an existing directory (create it first, or drop the slash to pull to that exact path)", localPath)
	default:
		// Fall-through (nonexistent exact path, or an existing non-directory the
		// overwrite policy will judge): use the trimmed path so the Lstat below never
		// follows a trailing-slash symlink either.
		localPath = statPath
	}

	// Overwrite policy at the final target. Lstat: a symlink counts as the
	// link itself, which a single-file pull may replace (never write through).
	fi, err := os.Lstat(localPath)
	if os.IsNotExist(err) {
		return localPath, nil
	}
	if err != nil {
		return "", err
	}
	if fi.IsDir() {
		return "", fmt.Errorf("destination %q already exists; remove it or choose another name", localPath)
	}
	if recursive {
		return "", fmt.Errorf("destination %q already exists and is not a directory; remove it or choose another name", localPath)
	}
	return localPath, nil
}

func init() {
	// Add flags to push command
	filePushCmd.Flags().BoolP("recursive", "r", false, "Push directory recursively")

	// Add flags to pull command
	filePullCmd.Flags().BoolP("recursive", "r", false, "Pull directory recursively")

	// Add subcommands to file command
	fileCmd.AddCommand(filePushCmd)
	fileCmd.AddCommand(filePullCmd)
}
