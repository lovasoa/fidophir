# Packaging

The repository builds RPM and DEB packages for Linux systems with systemd. These are experimental packages, not official distribution packages. Building does not install or start the service. For installation and first use, start with the [README](../README.md); physical acceptance is still pending.

## Build packages

For an RPM, install `rpmbuild` and the `BuildRequires` in `fidophir.spec` using your package manager, then run:

```sh
mkdir -p dist/rpmbuild/SOURCES
git ls-files -z | tar --null --files-from=- \
  --transform 's,^,fidophir-0.1.1/,' -czf dist/rpmbuild/SOURCES/fidophir-0.1.1.tar.gz
rpmbuild -ba --define "_topdir $(pwd)/dist/rpmbuild" packaging/fidophir.spec
```

For a DEB, install the build dependencies listed in `debian/control` and run from the checkout:

```sh
dpkg-buildpackage --build=binary --no-sign
```

To inspect the installation layout without installing a package, run `make install DESTDIR=/absolute/staging/path` after building.

## Installation behavior

The packages install the service template, a template dependency in `user@.service.wants` and an aggregate `fidophir.target`, device rules, polkit policy and service account. systemd starts `fidophir@UID.service` alongside each user manager and stops it with that manager. Existing logins are activated during installation. The RPM systemd macros and DEB `dh_installsystemd` manage the aggregate target; `PartOf=` propagates upgrades and removal to running instances without enumerating them. DEB activation respects `policy-rc.d`; its helper cannot directly start dependency-driven template instances, so the small installation hook consults the standard policy interface before activating existing logins. UHID is loaded and its device rules refreshed during installation, and modules-load handles subsequent boots. Package scripts tolerate chroots and unavailable hardware. No desktop account is modified, and no passkey is enrolled automatically.

Each instance runs as the dedicated `fidophir` account with supplementary `tss` access. `StateDirectory=` creates each private directory and supplies `$STATE_DIRECTORY` to the daemon; state is separate under `/var/lib/fidophir-users/UID/v2`. udev assigns each generated hidraw device to its user, mode 0600, without `uaccess` or shared client groups. Desktop approval selects that UID's unique active, local, unlocked graphical session; ambiguous sessions fail closed. SSH-only and lingering user managers may run an instance, but cannot approve operations without an eligible graphical session. All instances share the TPM's hardware dictionary-attack lockout.

See the [state format and maintenance instructions](../src/state/README.txt). Stopping or removing the package preserves state. Service accounts, root and the kernel remain trusted; this isolates desktop users, not compromised service processes. See the [physical acceptance checklist](../VALIDATION.md#remaining-physical-acceptance).

## Service sandbox

The daemon and its native libraries use the package architecture's syscall ABI (`SystemCallArchitectures=native`). `SystemCallFilter=~@debug` denies debugging and tracing syscalls, including `ptrace`, `perf_event_open` and `pidfd_getfd`. The daemon does not launch compatibility binaries or use these interfaces; TPM device I/O, UHID, local D-Bus and GLib event handling remain available. These controls require systemd built with seccomp support to enforce syscall restrictions.

## Crash recovery

Unexpected adapter states and failures in OpenSK's infallible signing/key-generation interfaces stop the daemon after a sanitized fatal log. `Restart=on-failure` retries after three seconds; `StartLimitIntervalSec=0` prevents repeated failures from exhausting a restart quota. A persistent hardware, configuration or storage failure still requires repair. Intentional stops, logout and package removal do not trigger recovery.

A restart closes the UHID descriptor and briefly disconnects the virtual key, then publishes a fresh device after initialization. Credentials remain on disk, while transient PIN authorization is lost. The interrupted browser operation may need to be retried; this policy provides automatic recovery rather than uninterrupted availability.

## Lifecycle tests

`bash tests/packaging.sh` checks installation-hook policy decisions without touching host services. It also runs with `make test`.

`tests/systemd_lifecycle.py` installs a package built through the normal distro recipe and runs its real daemon under the unchanged systemd sandbox. CI boots disposable containers using the pinned example build environments in `packaging/images/` with real user managers, logind, polkit and udev. A compile-time `systemd-tests` feature selects the system-bus TPM resource manager backed by swtpm; production builds remain fixed to `/dev/tpmrm0`. The test checks CTAP GetInfo through actual UHID/hidraw devices, user ownership, crash recovery, logout, package reinstall, target restart/removal and policy/mask denial. See [the test setup and limits](../tests/systemd/README.md).

## Release builds

The packages workflow tests and builds both formats from the same commit on pushes to `main` and publishes successful builds on [GitHub Releases](https://github.com/lovasoa/fidophir/releases). Pull requests build without release permissions. Download assets are named `fidophir.rpm` and `fidophir.deb`; the RPM release has no distribution tag, and their labels and package metadata include a version derived from the commit history. A source RPM and package checksums accompany the binaries. Simulator and package tests do not replace physical acceptance.

Dependency updates are ordinary pull requests: Dependabot handles actions and build images; the scheduled Cargo updater uses `peter-evans/create-pull-request` for compatible and major updates to `Cargo.toml` and `Cargo.lock`. Its major-update track also proposes updates to exact versions, including OpenSK and CBOR; an OpenSK version change requires the adapter contract review documented in `src/opensk_adapter.rs` and the contract tests. Repository Actions settings must allow GitHub Actions to create pull requests. Cargo PRs explicitly dispatch package checks because the default `GITHUB_TOKEN` does not trigger `pull_request` workflows. Updates stay open for review and merge through the repository's normal rules; there is no privileged merge workflow or direct automated update of `main`. Merging through the GitHub UI triggers the normal main build and publication.
