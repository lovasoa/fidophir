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
cp dist/fidophir-0.1.0.tar.gz dist/rpmbuild/SOURCES/
rpmbuild -ba --define "_topdir $(pwd)/dist/rpmbuild" packaging/fidophir.spec
```

For a DEB, extract the source bundle and, inside it, install the build dependencies listed in `debian/control` and run:

```sh
dpkg-buildpackage --build=binary --no-sign
```

Package builds and tests run offline. The bundle includes pinned Rust sources, checksums, lockfiles, dependency inventory and licenses. Native GLib/GIO and TPM2-TSS libraries remain distribution-managed. `make install DESTDIR=/absolute/staging/path` stages files only.

## Installation behavior

The packages install the service, device rules, polkit policy, service accounts and example owner configuration. They do not configure the owner, add a desktop user to a group, enroll a credential or start/enable the service. Debian upgrades also require a manual restart. Stopping or removing the package preserves `/var/lib/fidophir`; unsupported state layouts fail closed.

The service runs as `fidophir`, with its private primary group and the unit's supplementary `tss` group. The configured desktop user needs only `fidophir-client`. The service uses `/dev/tpmrm0` and `/dev/uhid`; its generated hidraw device must be checked for the correct group and absence of a `uaccess` ACL on a real machine. See the [physical acceptance checklist](../VALIDATION.md#physical-acceptance-not-yet-run).

## Release builds

The packages workflow tests and builds both formats on pushes to `main` and publishes successful builds on [GitHub Releases](https://github.com/lovasoa/fidophir/releases). Pull requests build without release permissions. Source bundles and checksums accompany the packages. Dependency automation proposes and tests updates; successful automated merges trigger the package workflow again. Simulator and package tests do not replace physical acceptance.
