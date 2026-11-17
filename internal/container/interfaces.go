package container

// ContainerLifecycle covers creating, starting, stopping and deleting containers.
type ContainerLifecycle interface {
	Launch(image string, ephemeral bool, pool string) error
	LaunchWithPolicy(image string, ephemeral bool, pool string, policy HardeningPolicy) error
	LaunchWithPreStart(image string, ephemeral bool, pool string, preStart func() error) error
	LaunchWithPreStartPolicy(image string, ephemeral bool, pool string, preStart func() error, policy HardeningPolicy) error
	Stop(force bool) error
	Delete(force bool) error
	Start() error
	Running() (bool, error)
	Stopped() (bool, error)
	Exists() (bool, error)
}

// ContainerExecution covers running commands inside a container.
type ContainerExecution interface {
	Exec(args ...string) error
	ExecArgs(commandArgs []string, opts ExecCommandOptions) error
	ExecArgsCapture(commandArgs []string, opts ExecCommandOptions) (string, error)
	ExecCommand(command string, opts ExecCommandOptions) (string, error)
	ExecHostCommand(command string, capture bool) (string, error)
}

// ContainerDevices covers mounting disks and managing proxy/device attachments.
type ContainerDevices interface {
	MountDisk(name, source, path string, shift, readonly bool) error
	AddProxyDevice(name, connect, listen string, uid, gid int) error
	AddHostPortDevice(name, listenAddr string, hostPort, containerPort int) error
	RemoveDevice(name string) error
	ListDevices() ([]string, error)
	SetTmpfsSize(size string) error
}

// ContainerFiles covers file operations on the container filesystem: pushing and
// pulling between host and container, creating files in-container, ownership
// changes, existence checks, and workspace path resolution.
type ContainerFiles interface {
	GetWorkspacePath() string
	GetWorkspaceSource() string
	PushFile(source, destination string) error
	PullFile(containerPath, localPath string) error
	PullDirectory(containerPath, localPath string) error
	PushDirectory(localPath, containerPath string) error
	Chown(path string, uid, gid int) error
	DirExists(path string) (bool, error)
	FileExists(path string) (bool, error)
	CreateFile(containerPath, content string) error
	CreateFileWithOwner(containerPath, content string, uid, gid int, mode string) error
}

// ContainerSnapshot covers snapshot lifecycle operations.
type ContainerSnapshot interface {
	CreateSnapshot(name string, stateful bool) error
	ListSnapshots() ([]SnapshotInfo, error)
	RestoreSnapshot(name string, stateful bool) error
	DeleteSnapshot(name string) error
	SnapshotExists(name string) (bool, error)
	GetSnapshotInfo(name string) (*SnapshotInfo, error)
}

// ContainerManager is the full interface implemented by *Manager.
// Callers that only need a subset of operations should accept one of the
// narrower sub-interfaces (ContainerLifecycle, ContainerExecution,
// ContainerDevices, ContainerFiles, ContainerSnapshot) instead.
type ContainerManager interface {
	ContainerLifecycle
	ContainerExecution
	ContainerDevices
	ContainerFiles
	ContainerSnapshot
}

// Compile-time assertion: *Manager must satisfy ContainerManager.
var _ ContainerManager = (*Manager)(nil)
