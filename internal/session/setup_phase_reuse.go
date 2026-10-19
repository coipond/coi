package session

import (
	"context"
	"fmt"
	"time"

	"github.com/coipond/coi/internal/container"
)

// 4. Check if the container already exists and decide whether to reuse,
// restart, or delete-and-recreate it; sets skipLaunch accordingly.
func (st *setupState) phaseReconcileExisting(_ context.Context) (Teardown, error) {
	exists, err := st.result.Manager.Exists()
	if err != nil {
		return nil, fmt.Errorf("failed to check if container exists: %w", err)
	}

	// An explicitly named container (--container) is attached to, never
	// created — so it must already exist. Without this guard a missing name
	// silently skips both the reuse branch (exists is false) and the
	// creation branch (skipLaunch is true), then fails with a misleading
	// "container not ready" only after the full ready_timeout wait.
	if st.opts.ContainerName != "" {
		if !exists {
			return nil, container.SentinelError(container.ErrContainerNotFound,
				fmt.Sprintf("container '%s' not found - omit --container to launch a new container for this workspace", st.opts.ContainerName))
		}
		st.skipLaunch = true
		st.opts.Logger("Using existing container, skipping creation...")
	}

	if exists {
		// Check if container is currently running
		running, err := st.result.Manager.Running()
		if err != nil {
			return nil, fmt.Errorf("failed to check if container is running: %w", err)
		}

		if running {
			// Container is running - this is an active session!
			if st.opts.Persistent || st.opts.ContainerName != "" || st.opts.ResumeFromID != "" {
				// Reuse running container if: persistent mode, --container flag, or explicit resume.
				// The resume case covers post-reboot Incus stateful restore: a non-persistent
				// container may be Running because Incus restored it; --resume should reuse it.
				// A RUNNING container cannot be remounted safely, so refuse
				// to attach when it still has a DIFFERENT workspace mounted —
				// the normal hazard for a named session (session_name) whose
				// previous checkout's session is still live. Attaching would
				// silently hand this launch the other checkout's files.
				// An EXPLICIT --container is exempt: naming the container is
				// the user saying "attach to that container as it is",
				// wherever it was created from (the documented testing flow).
				if st.opts.ContainerName == "" {
					if src := st.result.Manager.GetWorkspaceSource(); src == "" {
						st.opts.Logger("Warning: could not determine the running container's workspace source; skipping the workspace-match check")
					} else if !SameWorkspaceSource(src, st.opts.WorkspacePath) {
						return nil, fmt.Errorf(
							"container %s is running with a different workspace mounted (%s); "+
								"stop that session first (coi shutdown %s) or launch from that workspace",
							st.result.ContainerName, src, st.result.ContainerName)
					}
				}
				st.opts.Logger("Container already running, reusing...")
				// A RUNNING container's kernel-surface settings cannot be
				// changed (nesting is rejected, the deny list is racy), so
				// only surface a config mismatch instead of applying it. Skip
				// for an explicit --container attach: that means "use it as it
				// is", and its config may legitimately come from an Incus
				// profile we neither manage nor should second-guess.
				if st.opts.ContainerName == "" {
					warnHardeningMismatch(st.result.ContainerName, hardeningPolicyFrom(&st.opts), st.opts.Logger)
				}
				// Strip the previous session's port devices NOW, before the
				// port preflight below bind-probes: their live forkproxy
				// listeners would otherwise make the session collide with its
				// own ports (pinned entries hard-fail, pool numbers drift).
				RemoveStalePortDevices(st.result.Manager, st.opts.Logger)
				// Deliberately do NOT reconcile protect-* devices here. This
				// branch reuses an already-RUNNING container, so (a) there is no
				// Start(), hence no "Missing source path" start-validation to
				// prevent — the #610 wedge only bites the stopped branch below —
				// and (b) hot-removing a protect-* device from a live container
				// would DROP a read-only protection mid-session: a source that
				// went missing while still mounted keeps writes blocked, but
				// RemoveDevice would reopen it to a possibly-malicious agent.
				// Reconciliation happens on the next stopped->start cycle.
				st.skipLaunch = true
			} else {
				// A running container exists for this slot but we're not resuming or in
				// persistent mode — AllocateSlot() should have avoided this slot.
				return nil, fmt.Errorf("slot %d is already in use by a running container %s - this should not happen (bug in slot allocation)", st.opts.Slot, st.result.ContainerName)
			}
		} else {
			// Container exists but is stopped
			if st.opts.Persistent || st.opts.ContainerName != "" {
				// Restart the stopped container
				// This includes: persistent containers OR containers specified via --container flag
				if err := restartStoppedContainer(st.result, &st.opts, st.result.ContainerName); err != nil {
					return nil, err
				}
				st.skipLaunch = true
			} else {
				// Delete the stopped leftover container
				st.opts.Logger("Found stopped leftover container from previous session, deleting...")
				if err := st.result.Manager.Delete(true); err != nil {
					return nil, fmt.Errorf("failed to delete leftover container: %w", err)
				}
				// Brief pause to let Incus fully delete
				time.Sleep(500 * time.Millisecond)
			}
		}
	}
	return nil, nil
}

// 4.6 Defense-in-depth: gate untrusted out-of-workspace mounts, forwarded
// sockets, ad-hoc credential entries, and port publications at the single
// chokepoint every caller passes through. Runs on reuse paths too.
func (st *setupState) phaseFilterTrusted(_ context.Context) (Teardown, error) {
	gatedMC, droppedM, gatedSC, droppedS, gatedCC, droppedC, gatedPC, droppedP := FilterTrusted(st.opts.MountConfig, st.opts.Network.Sockets, st.opts.CredentialConfig, st.opts.Network.Ports, st.opts.WorkspacePath)
	if st.skipLaunch && len(droppedM) > 0 {
		st.opts.Logger(fmt.Sprintf(
			"Warning: %d untrusted mount(s) remain attached from when this container was created; recreate it (coi kill + relaunch) to apply mount-trust changes",
			len(droppedM),
		))
	} else {
		for _, m := range droppedM {
			st.opts.Logger(fmt.Sprintf(
				"Warning: ignoring untrusted mount from %s: %s -> %s (resolves outside the workspace; run 'coi trust' or set %s=1)",
				m.SourcePath, m.HostPath, m.ContainerPath, TrustEnvVar,
			))
		}
	}
	for _, s := range droppedS {
		st.opts.Logger(fmt.Sprintf(
			"Warning: ignoring untrusted socket from %s: %s -> %s (run 'coi trust' or set %s=1)",
			s.SourcePath, s.HostPath, s.ContainerPath, TrustEnvVar,
		))
	}
	for _, c := range droppedC {
		st.opts.Logger(fmt.Sprintf(
			"Warning: ignoring untrusted credential entry from %s: %s -> %s (run 'coi trust' or set %s=1)",
			c.SourcePath, c.HostPath, c.ContainerPath, TrustEnvVar,
		))
	}
	for _, p := range droppedP {
		st.opts.Logger(fmt.Sprintf(
			"Warning: ignoring untrusted %s from %s (a repo declaring host listeners can squat localhost ports; run 'coi trust' or set %s=1)",
			DescribeDroppedPort(p), p.SourcePath, TrustEnvVar,
		))
	}
	st.opts.MountConfig = gatedMC
	st.opts.Network.Sockets = gatedSC
	st.opts.CredentialConfig = gatedCC
	st.opts.Network.Ports = gatedPC

	// On reuse, [[mounts]] devices persist from creation and are never re-added
	// (like mount-trust above), so a changed per-mount `shift` would otherwise
	// be a silent no-op. Warn when an attached mount device's shift no longer
	// matches the current config (#604).
	if st.skipLaunch && st.opts.MountConfig != nil {
		WarnMountShiftDrift(st.result.ContainerName, st.opts.MountConfig.Mounts, st.opts.Logger)
	}
	return nil, nil
}

// 4.7 Preflight the port plan BEFORE any container is created (fresh path) and
// AFTER stale port devices were stripped (reuse path).
func (st *setupState) phasePreflightPorts(_ context.Context) (Teardown, error) {
	resolvedPorts, err := ResolvePorts(st.opts.Network.Ports, st.opts.WorkspacePath, st.opts.SessionName, st.opts.Slot)
	if err != nil {
		return nil, fmt.Errorf("port preflight failed: %w", err)
	}
	st.resolvedPorts = resolvedPorts
	return nil, nil
}
