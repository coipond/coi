# Packaging & publishing `coi` on Launchpad

This document describes how `code-on-incus` (the `coi` command) is packaged as a
Debian `.deb` and published to a [Launchpad](https://launchpad.net) PPA, both
manually and via CI.

## How it works

Launchpad does not accept prebuilt binaries. You upload a **signed source
package**; Launchpad's build farm compiles it per-architecture, per-Ubuntu-series,
and publishes an apt repository users can add.

Two facts drive this project's packaging:

1. **`go.mod` requires Go 1.25**, and `golang-1.25-go` is only in the archive on
   the newest series — resolute (26.04) has it in *universe*, while jammy (22.04)
   and noble (24.04) do not. For those two it comes from
   [`ppa:longsleep/golang-backports`](https://launchpad.net/~longsleep/+archive/ubuntu/golang-backports),
   added to our PPA as an **archive dependency** so the builders can resolve it.
   The archive dependency is therefore load-bearing for the LTS builds, not for
   resolute.
2. **Launchpad builders have no network.** Go modules are therefore *vendored*
   (`go mod vendor`) into the source tarball, and the build runs with
   `GOPROXY=off`. `vendor/` is intentionally not committed (see `.gitignore`);
   it is generated as a build prerequisite locally and in CI.

The build also needs `pkg-config` + `libsystemd-dev` (cgo), and the runtime
needs `libsystemd0` — `coi`'s NFT monitor `dlopen`s `libsystemd.so`, so that
dependency is declared explicitly in `debian/control`.

See `debian/README.source` for the short version.

## One-time setup (manual, only you can do this)

### 1. Launchpad account

Create an account at <https://launchpad.net>. Uploading to a PPA does **not**
require an SSH key or signing the Code of Conduct.

### 2. Create a GPG key

The package `Maintainer` is the upstream author, `Maciej Mensfeld
<maciej@mensfeld.pl>`. There is deliberately no `XSBC-Original-Maintainer`: that
field exists to preserve the *original* maintainer when a derivative takes over
the `Maintainer` slot, so with upstream already named there it would only repeat
the same person.

Bug reports do **not** go to that inbox — `debian/control` sets
`XB-Bugs: https://github.com/mensfeld/code-on-incus/issues`, which lands in the
binary package as `Bugs:` and is what `reportbug`/`apt` surface. (The `XB-`
prefix is required; dpkg rejects a bare `Bugs:` in `debian/control` and only
`XB-*` fields propagate into the binary control.)

The signing key does **not** need to match either field — Launchpad validates
the *signature*, not the maintainer. What matters is that the key belongs to a
Launchpad account (yours) with upload rights to the PPA. Use your own identity
on the key:

```bash
gpg --full-generate-key
#   Key type: RSA (default), 4096 bits, no expiry (or your preference)
#   Real name: <your-name>
#   Email:     <your-email>

# Note the fingerprint / long key id:
gpg --list-secret-keys --keyid-format=long
```

> **CI note:** the CI workflow signs non-interactively, so use a **passphrase-less**
> key (or a dedicated passphrase-less signing subkey) if you want automated
> uploads. A passphrase-protected key is fine for manual uploads.

### 3. Register the key with Launchpad

```bash
# publish the public key to the keyserver Launchpad reads
gpg --keyserver keyserver.ubuntu.com --send-keys <FINGERPRINT>
```

Then go to <https://launchpad.net/~/+editpgpkeys>, paste the fingerprint, and
submit. Launchpad emails you an **encrypted** confirmation. Decrypt it and open
the link inside:

```bash
# paste the encrypted mail body, Ctrl-D to end
gpg --decrypt
```

### 4. The PPA

Already created: the **`code-on-incus`** team owns
[`ppa:code-on-incus/ppa`](https://launchpad.net/~code-on-incus/+archive/ubuntu/ppa).
Your Launchpad account (the PPA owner) has upload rights, so uploads signed by
your key are accepted — regardless of the package `Maintainer`.

> **No team mailing list exists.** `code-on-incus@lists.launchpad.net` is *not*
> configured — Launchpad does not provision team lists automatically — so it is
> deliberately not used anywhere. Launchpad addresses build and rejection mail
> to the **uploader** (whoever's key signed) and to `Changed-By` (`DEB_EMAIL`),
> both of which are real inboxes, so nothing depends on a list existing.

### 5. The Go 1.25 archive dependency (already added)

`ppa:longsleep/golang-backports` is configured as an archive dependency on the
PPA. It is what lets the **jammy and noble** builders resolve `golang-1.25-go`;
resolute finds it in universe and does not need it.

If it is ever removed, those two builds fail with "golang-1.25-go has no
installation candidate" while resolute still succeeds — a half-green run that
reads like a flake rather than a missing prerequisite. To re-add it:

1. Open <https://launchpad.net/~code-on-incus/+archive/ubuntu/ppa/+edit-dependencies>.
2. Under "add a new dependency", add **`ppa:longsleep/golang-backports`**.
3. Save, then re-trigger the failed builds.

## Manual upload

From this directory, for a single series (repeat per series with distinct
versions — Launchpad rejects re-uploading the same version to two series):

```bash
go mod vendor                                   # make source offline-buildable

# set the version + target series in the changelog
dch -b -v "0.10.2~ubuntu24.04.1" -D noble "Build 0.10.2 for noble."

debuild --no-lintian -S -sa -d -k<YOUR_KEY_ID>  # build + sign the SOURCE package
                                                # -d: source-only, skip build-dep check
dput ppa:code-on-incus/ppa \
     ../code-on-incus_0.10.2~ubuntu24.04.1_source.changes
```

### Version scheme

Per-series versions are `<upstream>~ubuntu<XX.YY>.<N>` — e.g. `0.10.2~ubuntu24.04.1`.

- **Numeric series, not the codename.** Codenames sort alphabetically and Ubuntu
  restarts the alphabet every cycle (…zesty → artful). Under a `~noble1` style
  scheme the next cycle's series would sort *below* the current one, so `apt`
  would see a downgrade and refuse the upgrade after `do-release-upgrade`.
  `ubuntu24.04` → `ubuntu26.04` → `ubuntu28.04` always sorts forward.
- **No Debian revision.** `3.0 (native)` forbids a hyphen in the version, so the
  usual `0.10.2-1~ubuntu24.04.1` form is not available here.
- **`~` keeps these below a real archive version**, so if `code-on-incus` ever
  lands in Ubuntu proper, the archive package wins over the PPA build.
- **Bump the trailing `.N`** to re-upload the same upstream version to the same
  series (Launchpad rejects a duplicate version).

Watch the build at your PPA's page. Once green, users install with:

```bash
sudo add-apt-repository ppa:code-on-incus/ppa
sudo apt update && sudo apt install code-on-incus   # provides the `coi` command
```

## Automated upload (CI)

`.github/workflows/publish-ppa.yml` builds and uploads a signed source package
for every series. It runs on the **same `v*.*.*` release tags as `release.yml`**,
so cutting a release also publishes to the PPA (plus manual dispatch). The PPA
target is hardcoded to `ppa:code-on-incus/ppa`. The job **no-ops unless
`DEB_EMAIL` is set**, so a fork or upstream without PPA credentials is never
failed by it.

### Relationship to `release.yml`

The two workflows are **independent by design** — both fire on the same tag and
run in parallel, and neither gates the other. Chaining them via `workflow_run`
would break the version: that trigger runs in the default-branch context, so
`GITHUB_REF_NAME` would be `master` and the tag-derived version would silently
fall back to the committed changelog version.

Two consequences worth knowing before cutting a tag:

- **A failed `release.yml` does not prevent the PPA upload.** They are separate
  jobs on the same trigger.
- **Launchpad uploads are irreversible.** A version number can never be reused,
  even after deleting the package from the PPA. Recovering from a bad upload
  means bumping the trailing `.N` (`0.10.2~ubuntu24.04.2`), not re-uploading the
  same version.

`release.yml` also force-pushes a `latest` tag at the end. That does not match
the `v*.*.*` filter, so it does not retrigger PPA publishing — keep that filter
specific if the tag scheme ever changes.

### Supply-chain notes

Actions are pinned by commit SHA, matching `ci.yml` and `release.yml`. The Go
module cache is disabled (`cache: false`) because `go mod vendor` output ships
*inside* the source tarball Launchpad compiles — a poisoned cache would be baked
into the published package, not just a local build. The checkout uses
`persist-credentials: false` since the job never pushes.

Configure once in **GitHub repo → Settings** (in the repo that owns the release
tags — i.e. upstream once merged):

| Kind     | Name              | Value                                              |
|----------|-------------------|----------------------------------------------------|
| Secret   | `GPG_PRIVATE_KEY` | `gpg --armor --export-secret-keys <FPR>` output    |
| Variable | `GPG_KEY_ID`      | key fingerprint / long id used to sign (public, so not a secret) |
| Variable | `DEB_EMAIL`       | changelog Changed-By email (required; CI toggle)   |
| Variable | `DEB_FULLNAME`    | changelog Changed-By name (optional, default "Code on Incus") |

The signing key just needs upload rights to `ppa:code-on-incus/ppa`; it does not
need to match the changelog `Maintainer` or `DEB_EMAIL` (Launchpad checks the
signature, not those fields).

A release then publishes to the PPA automatically:

```bash
git tag v0.10.2 && git push origin v0.10.2
```

The workflow runs one job per series and uploads each in parallel.

## Reproducing the build locally

Building `.deb`s needs a Debian/Ubuntu-based system. On a non-Debian host
(Fedora, Arch, macOS, ...), run these steps inside an Ubuntu
[distrobox](https://distrobox.it) container (`distrobox enter <name>`) instead.
Either way this mirrors what Launchpad does (backport PPA → Go 1.25 → offline
build):

```bash
sudo add-apt-repository -y ppa:longsleep/golang-backports
sudo apt-get update
sudo apt-get install -y devscripts build-essential fakeroot dpkg-dev \
     debhelper pkg-config libsystemd-dev golang-1.25-go
cd /path/to/launchpad
go mod vendor
dpkg-buildpackage -us -uc -b        # produces ../code-on-incus_*.deb
```

## Notes / limitations

- Source format is `3.0 (native)` for PPA simplicity (one tarball, no
  orig/quilt split). For a real Debian-archive submission, switch to
  `3.0 (quilt)`.
- `debian/copyright` enumerates the licence of every vendored Go module
  (`vendor/`). If `go mod vendor` changes the dependency set, update the
  per-module `Files:` stanzas to match. Verify coverage with
  `licensecheck -r vendor/`.
- The series matrix in the workflow must stay in sync with what
  `longsleep/golang-backports` publishes.
- `coi` shells out to the `incus` CLI and is non-functional without it, so the
  package **`Depends: incus`**. `incus` is in the Ubuntu archive from noble
  (24.04) onward, so it installs automatically there. On **jammy (22.04)**
  `incus` is not in the archive; users must first add the
  [zabbly](https://github.com/zabbly/incus) repo (its package is also named
  `incus`), otherwise `apt install code-on-incus` reports `incus` as
  uninstallable — which correctly signals the missing prerequisite.
- **`libcap2-bin` is `Depends`, and `debian/postinst` runs `setcap`.** `coi`
  needs `CAP_LINUX_IMMUTABLE` to `chattr +i` host-side protected paths — the
  layer that stops a container root from bypassing a read-only bind mount with
  `unshare -m` + `umount` (`internal/session/immutable.go`). `install.sh` grants
  it with `setcap` after installing, but a `.deb` cannot carry file
  capabilities in the archive, so the package has to apply it from a maintainer
  script. dpkg also drops the capability on every upgrade (the binary is a new
  inode), which is why `postinst` re-applies on each `configure` rather than
  only on first install — and why `setcap` must be present at configure time,
  not merely at install time.

  The `setcap` call is **non-fatal**, matching `install.sh`: `ApplyImmutable`
  already degrades to read-only bind mounts with a warning when the capability
  is absent, so a host that cannot hold it (`/usr` on a `nosuid` or no-xattr
  mount, an unprivileged container without `CAP_SETFCAP`) gets a warning rather
  than a half-configured package. Verify after a local install with
  `getcap /usr/bin/coi` — expect `cap_linux_immutable=ep`. `coi doctor` reports
  the same thing as a SECURITY warning if it is missing.
- Other host tools are handled without extra hard dependencies:
  - `nftables`, `iproute2`, `iptables`, `uidmap`, `rsync`, and `systemd`
    (journalctl/systemctl) are pulled in transitively by `incus` (via
    `incus-base`), so `coi`'s firewall/monitoring/cleanup paths get them for
    free — no need to re-declare them.
  - **`sudo` is `Depends`.** The default `[network] mode = "restricted"` sets up
    nftables via passwordless `sudo -n nft`; `setupRestricted` fails closed when
    that is unavailable and the error aborts session setup
    (`internal/session/setup.go`). Running without sudo means deliberately
    disabling the isolation (`mode = "open"` or `use_sudo = false`), so a
    default-configured install genuinely requires it.
  - **`git` is `Recommends`.** Sessions still start without it, but the host
    git-identity read returns empty, so COI leaves the fail-closed
    `user.useConfigOnly=true` guard in place and commits *inside* the container
    fail rather than being attributed to a fabricated author (#556). That is a
    real degradation, not a crash, and it is recoverable without the package:
    `[git] name`/`email` pin an identity explicitly. Its only other user is
    `coi update patterns`; threat detection falls back to a compiled-in pattern
    set (`internal/monitor/procwatcher.go`), so detection still works.
  - **`openssh-client` is `Suggests`.** `coi` never executes an OpenSSH binary:
    agent forwarding reads `$SSH_AUTH_SOCK` and proxies that socket into the
    container via an Incus device. It is relevant only as the package that would
    supply the agent to begin with.
  - Container-side tools (`tmux`, the agent tooling) run *inside* the Incus
    container via `incus exec`, so they are provided by the container image,
    not the host package.
- Integration tests are skipped during the package build (they need a live
  Incus daemon).
- **The self-updater is disabled in packaged builds.** `debian/rules` stamps
  `-X internal/cli.InstallSource=deb` next to the version ldflag, and
  `coi update core` refuses when that is set to anything but `source`.
  Otherwise it would overwrite the dpkg-owned `/usr/bin/coi` in place —
  desyncing dpkg's file database, with the next `apt upgrade` silently
  reverting the update. `--force` does not override this; `--check` still
  works, as does `coi update patterns` (the detection databases are not
  shipped in the package). Any future packaging target (rpm, Arch, ...) gets
  the same protection by stamping its own `InstallSource` value; adding it to
  `packageUpdateCommands` in `internal/cli/update.go` upgrades the message
  from generic advice to that package manager's exact command.
- Lintian runs as a separate **non-fatal** CI step rather than via `debuild`,
  so packaging tags are visible in the log without a lintian regression
  blocking a release. Read it when you touch `debian/`.
