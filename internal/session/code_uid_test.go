package session

import (
	"errors"
	"testing"

	"github.com/coipond/coi/internal/container"
)

// fakeExec implements container.ContainerExecution with a canned
// ExecArgsCapture response; the other methods are unused by ResolveCodeUID.
type fakeExec struct {
	out string
	err error
}

func (f *fakeExec) Exec(args ...string) error { return nil }
func (f *fakeExec) ExecArgs(commandArgs []string, opts container.ExecCommandOptions) error {
	return nil
}

func (f *fakeExec) ExecArgsCapture(commandArgs []string, opts container.ExecCommandOptions) (string, error) {
	return f.out, f.err
}

func (f *fakeExec) ExecCommand(command string, opts container.ExecCommandOptions) (string, error) {
	return "", nil
}
func (f *fakeExec) ExecHostCommand(command string, capture bool) (string, error) { return "", nil }

func TestResolveCodeUID(t *testing.T) {
	tests := []struct {
		name    string
		out     string
		err     error
		want    int
		wantErr bool
	}{
		{name: "default code uid", out: "1000\n", want: 1000},
		{name: "remapped uid", out: "501\n", want: 501},
		{name: "surrounding whitespace", out: "  1000  \n", want: 1000},
		// `id` itself reporting a missing user (recognized by ITS stderr)
		// is the only case that may fall back to root: images without a
		// code user run sessions (and tmux) as root
		{
			name: "no code user falls back to root (coreutils)",
			err:  &container.ExitError{ExitCode: 1, Stderr: "id: 'code': no such user"},
			want: 0,
		},
		{
			name: "no code user falls back to root (busybox)",
			err:  &container.ExitError{ExitCode: 1, Stderr: "id: unknown user code"},
			want: 0,
		},
		// incus-level failures ALSO surface as *container.ExitError from
		// the CLI exec path (daemon down, container stopped, permission
		// denied — commands.go wraps every non-zero exit); they must NOT
		// silently become root — that is the exact misdirection the
		// resolver exists to prevent (#588)
		{
			name:    "incus-level exit error propagates",
			err:     &container.ExitError{ExitCode: 1, Stderr: "Error: The instance is not running"},
			wantErr: true,
		},
		{
			name:    "missing binary exit error propagates",
			err:     &container.ExitError{ExitCode: 127, Stderr: "sh: 1: incus: not found"},
			wantErr: true,
		},
		{name: "connectivity error propagates", err: errors.New("incus unreachable"), wantErr: true},
		{name: "garbage output is an error", out: "not-a-uid\n", wantErr: true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := ResolveCodeUID(&fakeExec{out: tt.out, err: tt.err}, "code")
			if tt.wantErr {
				if err == nil {
					t.Fatalf("ResolveCodeUID(out=%q, err=%v) expected error, got uid %d", tt.out, tt.err, got)
				}
				return
			}
			if err != nil {
				t.Fatalf("ResolveCodeUID(out=%q, err=%v) unexpected error: %v", tt.out, tt.err, err)
			}
			if got != tt.want {
				t.Errorf("ResolveCodeUID(out=%q) = %d, want %d", tt.out, got, tt.want)
			}
		})
	}
}

// TestDetectCodeUser pins the shared probe's classification through the
// second consumer: existence, id-reported absence, and incus-level failures
// must be told apart identically to ResolveCodeUID (single probeCodeUser).
func TestDetectCodeUser(t *testing.T) {
	exists, err := DetectCodeUser(&fakeExec{out: "1000\n"}, "code")
	if err != nil || !exists {
		t.Errorf("existing user: got (%v, %v), want (true, nil)", exists, err)
	}

	exists, err = DetectCodeUser(&fakeExec{err: &container.ExitError{ExitCode: 1, Stderr: "id: 'code': no such user"}}, "code")
	if err != nil || exists {
		t.Errorf("missing user: got (%v, %v), want (false, nil)", exists, err)
	}

	if _, err = DetectCodeUser(&fakeExec{err: &container.ExitError{ExitCode: 1, Stderr: "Error: websocket: bad handshake"}}, "code"); err == nil {
		t.Error("incus-level failure should propagate as error, not classify as missing user")
	}
}
