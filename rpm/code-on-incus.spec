# RPM spec for code-on-incus (the `coi` command), published to Fedora Copr.
#
# Copr's build farm HAS network access (unlike Fedora's Koji), so Go modules are
# fetched on the fly at build time — no vendoring needed.
#
# Targets Fedora 43+ / rawhide, whose packaged `golang` is >= 1.25. That lets the
# build run with GOTOOLCHAIN=local (Fedora's default since F43): the distro Go
# compiles our `go 1.25.0` module directly, with no toolchain download.
# To also target Fedora <=42 or EPEL (older Go), set GOTOOLCHAIN=auto so `go`
# fetches the 1.25 toolchain over the network — network-dependent, so left off.

%global goipath github.com/mensfeld/code-on-incus

# Go binaries carry no useful DWARF for RPM's debuginfo machinery, and dwz cannot
# compress it. Strip at link time (-s -w) and skip the debug subpackage entirely.
%global debug_package %{nil}

Name:           code-on-incus
Version:        0.10.2
Release:        1%{?dist}
Summary:        Isolated machines for AI coding agents, with active defense

License:        MIT
URL:            https://github.com/mensfeld/code-on-incus
Source0:        %{url}/archive/v%{version}/%{name}-%{version}.tar.gz

BuildRequires:  golang >= 1.25
BuildRequires:  gcc
BuildRequires:  git
BuildRequires:  pkgconf-pkg-config
# coi uses cgo to read the systemd journal (internal/nftmonitor/journalctl.go).
BuildRequires:  systemd-devel

# coi shells out to the `incus` CLI and is non-functional without it.
Requires:       incus
# Used on the host for privileged ops, git identity, and SSH-credential mounting;
# coi still partly functions without each, so Recommends rather than Requires.
Recommends:     sudo
Recommends:     git
Recommends:     openssh-clients

%description
Code on Incus (the "coi" command) gives each AI coding agent its own machine:
a full Incus system container with root access, systemd, Docker, and the
ability to install anything. Agents work as they would on a real server -
run services, manage packages, use cron - without touching the host.

Host credentials (SSH keys, environment variables, Git tokens) are never
exposed to the agent unless explicitly mounted. coi watches each container
and can pause or kill it automatically on suspicious activity such as reverse
shells, credential scanning, or data exfiltration.

%prep
%autosetup -n %{name}-%{version}

%build
# Stage the go:embed assets, mirroring the upstream Makefile `build` target.
mkdir -p internal/image/embedded internal/config/embedded
cp profiles/default/config.toml internal/config/embedded/default_config.toml
cp testdata/dummy/dummy internal/image/embedded/dummy

export CGO_ENABLED=1
export GOTOOLCHAIN=local
export GOFLAGS='-trimpath'
go build -buildmode=pie \
    -ldflags "-s -w -X %{goipath}/internal/cli.Version=%{version}" \
    -o coi ./cmd/coi

%install
install -D -m0755 coi %{buildroot}%{_bindir}/coi

%files
%license LICENSE
%doc README.md
%{_bindir}/coi

%changelog
* Sat Jul 18 2026 Maciej Mensfeld <maciej@mensfeld.pl> - 0.10.2-1
- Initial Copr packaging.
