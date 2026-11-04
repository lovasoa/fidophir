# Packaging

The repository builds Fedora 44 RPM and Debian 13 DEB packages. These are experimental packages, not official distribution packages. Building does not install or start the service. For installation and first use, start with the [README](../README.md); physical acceptance is still pending.

## Build packages

First create an offline source bundle from a checkout with the submodule and Cargo caches populated:

```sh
python3 tools/source_bundle.py --output dist
```

For an RPM, install Fedora's `rpm-build` and the `BuildRequires` in `fidophir.spec`, then run:

```sh
mkdir -p dist/rpmbuild/SOURCES
cp dist/fidophir-0.1.1.tar.gz dist/rpmbuild/SOURCES/
rpmbuild -ba --define "_topdir $(pwd)/dist/rpmbuild" packaging/fidophir.spec
```

For a DEB, extract the source bundle and, inside it, install the build dependencies listed in `debian/control` and run:

```sh
dpkg-buildpackage --build=binary --no-sign
```

Package builds and tests run offline. The bundle includes pinned Rust sources, checksums, lockfiles, dependency inventory and licenses. Native GLib/GIO and TPM2-TSS libraries remain distribution-managed. `make install DESTDIR=/absolute/staging/path` stages files only.

## Installation behavior

The packages install the service template, a template dependency in `user@.service.wants` and an aggregate `fidophir.target`, device rules, polkit policy and service account. systemd starts `fidophir@UID.service` alongside each user manager and stops it with that manager. Existing logins are activated during installation. The RPM systemd macros and Debian `dh_installsystemd` manage the aggregate target; `PartOf=` propagates upgrades and removal to running instances without enumerating them. Debian activation respects `policy-rc.d`; its helper cannot directly start dependency-driven template instances, so the small installation hook consults the standard policy interface before activating existing logins. UHID is loaded and its device rules refreshed during installation, and modules-load handles subsequent boots. Package scripts tolerate chroots and unavailable hardware. No desktop account is modified, and no passkey is enrolled automatically.

Each instance runs as the dedicated `fidophir` account with supplementary `tss` access. `StateDirectory=` creates each private directory and supplies `$STATE_DIRECTORY` to the daemon; state is separate under `/var/lib/fidophir-users/UID/v1`. udev assigns each generated hidraw device to its user, mode 0600, without `uaccess` or shared client groups. Desktop approval selects that UID's unique active, local, unlocked graphical session; ambiguous sessions fail closed. SSH-only and lingering user managers may run an instance, but cannot approve operations without an eligible graphical session. All instances share the TPM's hardware dictionary-attack lockout.

Existing `/etc/fidophir/owner.conf` and `/var/lib/fidophir/v1` are preserved. The package creates a `StateDirectory=fidophir` override for the configured UID, preserving any existing administrator override; other users get separate stores. The daemon has no legacy configuration or path-selection code. Unassigned legacy state stays untouched and is never assigned to a newly logged-in user. Stopping or removing the package preserves all state. Service accounts, root and the kernel remain trusted; this isolates desktop users, not compromised service processes. See the [physical acceptance checklist](../VALIDATION.md#remaining-physical-acceptance).

## Lifecycle tests

`python3 tests/packaging.py` checks installation-hook policy decisions and legacy override generation without touching host services. It also runs with `make test`.

`tests/systemd_lifecycle.py` builds and installs small fixture packages using the production unit dependencies, sysusers declaration, preset, installation hook and distro lifecycle helpers. Run it as root only in a clean, disposable container booted with systemd: `python3 tests/systemd_lifecycle.py deb` on Debian 13 with `debhelper` and `dpkg-dev`, or `python3 tests/systemd_lifecycle.py rpm` on Fedora 44 with `rpm-build` and `systemd-rpm-macros`. Both need Python 3. A dummy worker and relaxed restart limit replace FIDO/TPM operations and service sandboxing, so these tests establish lifecycle and directory behavior, not hardware or confinement guarantees. They cover existing logins, matching UID dependencies, logout, upgrade, target restart/removal, legacy state retention and policy/mask denial.

## Release builds

The packages workflow tests and builds both formats on pushes to `main` and publishes successful builds on [GitHub Releases](https://github.com/lovasoa/fidophir/releases). Pull requests build without release permissions. Download assets are named `fidophir.rpm` and `fidophir.deb`; their labels and package metadata include a version derived from the commit history. Source bundles and checksums accompany the packages. Dependency automation proposes and tests updates; successful automated merges trigger the package workflow again. Simulator and package tests do not replace physical acceptance.
