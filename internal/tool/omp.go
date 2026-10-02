package tool

import (
	"path/filepath"
)

// OmpTool implements Tool for Oh My Pi (https://github.com/can1357/oh-my-pi)
type OmpTool struct {
	permissionMode  string
	contextFilePath string
	binary          string // [tool] binary override; empty means "omp"
}

// NewOmp creates a new omp tool instance
func NewOmp() Tool { return &OmpTool{} }

// Name returns "omp".
func (o *OmpTool) Name() string { return "omp" }

// Binary returns the executable to launch: the [tool] binary override if set,
// else "omp".
func (o *OmpTool) Binary() string {
	if o.binary != "" {
		return o.binary
	}
	return "omp"
}

// SetBinary implements ToolWithBinary: the executable to launch instead of
// "omp" ([tool] binary). An empty or unsafe value leaves the default.
func (o *OmpTool) SetBinary(path string) {
	if path != "" && ValidateBinary(path) == nil {
		o.binary = path
	}
}

// ConfigDirName returns the config directory for omp (~/.omp).
func (o *OmpTool) ConfigDirName() string { return mustBundle("omp").ConfigDir }

// SessionsDirName returns "sessions-omp".
func (o *OmpTool) SessionsDirName() string { return "sessions-omp" }

// BuildCommand builds the omp launch command.
func (o *OmpTool) BuildCommand(sessionID string, resume bool, resumeSessionID string) []string {
	cmd := []string{o.Binary()}
	if resume {
		cmd = append(cmd, "--continue")
	}
	return cmd
}

// PreLaunch implements ToolWithPreLaunch.
func (o *OmpTool) PreLaunch() [][]string {
	if o.contextFilePath == "" {
		return nil
	}
	homeDir := filepath.Dir(o.contextFilePath)
	ompDir := filepath.Join(homeDir, ".omp")
	linkTarget := filepath.Join(ompDir, "APPEND_SYSTEM.md")

	return [][]string{
		{"mkdir", "-p", ompDir},
		{"ln", "-sf", o.contextFilePath, linkTarget},
	}
}

// DiscoverSessionID returns "" because omp resumes its last session itself
// via --continue.
func (o *OmpTool) DiscoverSessionID(stateDir string) string { return "" }

// GetSandboxSettings returns an empty map; omp needs no settings injection.
// Context injection is handled via PreLaunch (symlinks APPEND_SYSTEM.md).
func (o *OmpTool) GetSandboxSettings() map[string]interface{} {
	return map[string]interface{}{}
}

// SetPermissionMode implements ToolWithPermissionMode. The mode is stored but
// currently has no effect on BuildCommand or GetSandboxSettings.
func (o *OmpTool) SetPermissionMode(mode string) {
	o.permissionMode = mode
}

// SetAutoContextPath implements ToolWithAutoContextPath. It stores the
// absolute path to the sandbox context file for PreLaunch to symlink;
// relative paths are ignored.
func (o *OmpTool) SetAutoContextPath(path string) {
	if !filepath.IsAbs(path) {
		return
	}
	o.contextFilePath = path
}

// EssentialConfigFiles implements ToolWithConfigDirFiles, returning the files
// listed in omp's credential bundle.
func (o *OmpTool) EssentialConfigFiles() []string {
	return mustBundle("omp").Files
}

// SandboxSettingsFileName implements ToolWithConfigDirFiles.
func (o *OmpTool) SandboxSettingsFileName() string { return mustBundle("omp").SandboxSettingsFile }

// StateConfigFileName implements ToolWithConfigDirFiles.
func (o *OmpTool) StateConfigFileName() string { return mustBundle("omp").StateFile }

// AlwaysSetupConfig implements ToolWithConfigDirFiles.
func (o *OmpTool) AlwaysSetupConfig() bool { return mustBundle("omp").AlwaysSetup }

// GetContainerEnv implements ToolWithContainerEnv. It sets OMP_SESSION_DIR to
// .omp-sessions under the workspace mount so sessions persist across
// ephemeral container recreations.
func (o *OmpTool) GetContainerEnv(workspacePath string) map[string]string {
	return map[string]string{
		"OMP_SESSION_DIR": filepath.Join(workspacePath, ".omp-sessions"),
	}
}
