# Packaging & publishing `coi` on Fedora Copr

This document describes how `code-on-incus` (the `coi` command) is packaged as a
Fedora RPM and published to a [Copr](https://copr.fedorainfracloud.org) project,
both manually and via CI.

## How it works

Copr does not host prebuilt binaries you upload. You submit a **source RPM**
(`.src.rpm`); Copr's build farm compiles it per-chroot (per Fedora release,
per-architecture) and publishes a `dnf` repository users can enable.

Two facts keep the build simple:

1. **Copr builders have network access** (unlike Fedora's Koji). Go modules are
   therefore fetched on the fly during the build — no vendoring, no committed
   `vendor/`.
2. **`go.mod` requires Go 1.25.** Fedora **43 and newer** ship `golang` >= 1.25,
   and since F43 the packaged Go defaults to `GOTOOLCHAIN=local` — so the distro
   toolchain compiles our module directly, with no toolchain download. This is
   why the chroot matrix is F43+ only (see below).

The build also needs `gcc` + `systemd-devel` (cgo: `coi` reads the systemd
journal), and the runtime needs the `incus` CLI — both declared in
`rpm/code-on-incus.spec`.

## Chroots (build targets)

Configured on the Copr **project**, not in the workflow. Use only chroots whose
packaged Go is >= 1.25:

- `fedora-43-x86_64`, `fedora-43-aarch64`
- `fedora-44-x86_64`, `fedora-44-aarch64`
- `fedora-rawhide-x86_64`, `fedora-rawhide-aarch64`

> To also target Fedora <= 42 or EPEL (older Go), the spec's `%build` would need
> `GOTOOLCHAIN=auto` so `go` downloads the 1.25 toolchain over the network. That
> is a network-dependent build the Fedora guidelines discourage, so it is left
> off — see the note in `rpm/code-on-incus.spec`.

## One-time setup (manual, only you can do this)

### 1. Fedora accounts

Copr uses the [Fedora Accounts](https://accounts.fedoraproject.org) system (FAS).
Everyone who will own or upload to the group needs a FAS account:

- **You (the person creating the project)** — create an account and log in to
  <https://copr.fedorainfracloud.org>.
- **The maintainer (`@mensfeld`)** — create a FAS account at
  <https://accounts.fedoraproject.org/> so they can be added to the
  `code-on-incus` group and manage the project.

### 2. Create the group and project

Copr **group projects** live under a [FAS](https://accounts.fedoraproject.org)
group, and FAS groups are not self-serve:

1. **Request the FAS group `code-on-incus`** by opening a
   [fedora-infrastructure ticket](https://forge.fedoraproject.org/infra/tickets).
   List the initial members (their FAS usernames) — at least yourself and
   `@mensfeld` once their FAS account (step 1) exists. Skip this if the group
   already exists and you are a member.
2. **Activate the group in Copr.** After the group exists and you are a member,
   log out and back in to Copr (FAS sync can take a few minutes), then go to
   <https://copr.fedorainfracloud.org/groups/list/my> and click **Activate this
   group**.
3. **Create the project** (`dnf install copr-cli`):

   ```bash
   copr-cli create '@code-on-incus/code-on-incus' \
     --chroot fedora-43-x86_64   --chroot fedora-43-aarch64 \
     --chroot fedora-44-x86_64   --chroot fedora-44-aarch64 \
     --chroot fedora-rawhide-x86_64 --chroot fedora-rawhide-aarch64 \
     --description 'Isolated machines for AI coding agents, with active defense'
   ```

   (Or create it in the web UI and tick the same chroots.)

### 3. Get an API token

Visit <https://copr.fedorainfracloud.org/api/> and copy the token block. It is
the full contents of a `~/.config/copr` file:

```ini
[copr-cli]
login = <your-login>
username = <your-fas-username>
token = <your-token>
copr_url = https://copr.fedorainfracloud.org
```

For manual use, save it to `~/.config/copr`. For CI, paste the whole block into
the GitHub secret below (do **not** commit it).

### 4. GitHub secret + variable

Configure once in **GitHub repo → Settings** (in the repo that owns the release
tags — i.e. upstream once merged):

| Kind     | Name             | Value                                                     |
|----------|------------------|-----------------------------------------------------------|
| Secret   | `COPR_API_TOKEN` | the full `~/.config/copr` token block from step 3         |
| Variable | `COPR_PROJECT`   | `@code-on-incus/code-on-incus`                            |

## Manual build & submit

From a Fedora host (or an `fedora` [distrobox](https://distrobox.it) on another
distro), with `~/.config/copr` in place:

```bash
dnf install -y copr-cli rpm-build git
VERSION=0.10.2                                  # the release version

RT=~/rpmbuild; mkdir -p "$RT"/{SPECS,SOURCES,SRPMS}
sed -E "s/^(Version:[[:space:]]+).*/\1${VERSION}/" \
  rpm/code-on-incus.spec > "$RT/SPECS/code-on-incus.spec"
git archive --format=tar.gz --prefix="code-on-incus-${VERSION}/" \
  -o "$RT/SOURCES/code-on-incus-${VERSION}.tar.gz" HEAD
rpmbuild --define "_topdir $RT" -bs "$RT/SPECS/code-on-incus.spec"

copr-cli build '@code-on-incus/code-on-incus' \
  "$RT"/SRPMS/code-on-incus-*.src.rpm
```

Watch the build on the project page. Once green, users install with:

```bash
sudo dnf copr enable '@code-on-incus/code-on-incus'
sudo dnf install code-on-incus                 # provides the `coi` command
```

## Automated build & submit (CI)

`.github/workflows/publish-copr.yml` builds the source RPM and submits it for
every release. It runs on the **same `v*.*.* release tags as `release.yml`**, so
cutting a release also publishes to Copr (plus manual dispatch). The job
**no-ops unless `COPR_PROJECT` is set**, so a fork or upstream without Copr
credentials is never failed by it.

A release then publishes to Copr automatically:

```bash
git tag v0.10.2 && git push origin v0.10.2
```

The workflow submits with `--nowait` (fire-and-forget). Drop `--nowait` in the
workflow if you want CI to wait on — and fail with — the Copr build.

## Reproducing the full build locally

`rpmbuild -bs` (above) only makes the source RPM. To compile the binary RPM the
way Copr does, on a Fedora host:

```bash
dnf install -y rpm-build gcc golang git systemd-devel
# after producing the SRPM as above:
rpmbuild --define "_topdir $RT" --rebuild "$RT"/SRPMS/code-on-incus-*.src.rpm
# -> $RT/RPMS/<arch>/code-on-incus-<version>-1.<dist>.<arch>.rpm
```

## Notes / limitations

- **No vendoring.** Copr has network, so modules are fetched at build time. If
  `coi` is ever submitted to official Fedora (Koji, network-less), the spec must
  switch to vendored sources + `go-rpm-macros`.
- **Chroot matrix is F43+.** It must stay in sync with which Fedora releases ship
  `golang` >= 1.25. Older chroots need the `GOTOOLCHAIN=auto` change noted above.
- **`Requires: incus`.** `coi` shells out to the `incus` CLI and is
  non-functional without it. `incus` is in the Fedora archive, so `dnf` pulls it
  in automatically.
- Other host tools are handled without extra hard dependencies:
  - `nftables`, `iproute2`, `iptables`, `shadow-utils`, `rsync`, and `systemd`
    are pulled in transitively by `incus`, so `coi`'s firewall/monitoring/cleanup
    paths get them for free.
  - `sudo`, `git`, and `openssh-clients` are `Recommends`: installed by default,
    but `coi` still partly functions without each.
  - Container-side tools run *inside* the Incus container via `incus exec`, so
    they come from the container image, not the host package.
- The `debug_package` subpackage is disabled: Go binaries are stripped at link
  time (`-s -w`) and carry no RPM-usable DWARF.
- Integration tests need a live Incus daemon and are not run during the build.
