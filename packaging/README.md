# Fedora package contract

The source tree includes the implemented binary, patched standalone OpenSK library, install target and a local Fedora 44 RPM recipe. Nothing is installed or started by building it. Physical acceptance remains pending; see ../VALIDATION.md. This is a local bundled-source package, not an official Fedora package-policy submission.

Build an offline source bundle, then build the RPM with Fedora `rpm-build` and the `BuildRequires` in `fidophir.spec` installed:

```sh
python3 tools/source_bundle.py --output dist
mkdir -p dist/rpmbuild/SOURCES
cp dist/fidophir-0.1.0.tar.gz dist/rpmbuild/SOURCES/
rpmbuild -ba --define "_topdir $(pwd)/dist/rpmbuild" packaging/fidophir.spec
```

The source bundle contains Cargo source replacement configuration, both lockfiles, checksums, dependency inventory and complete third-party license files. The RPM build and checks run offline. Source generation also runs offline and requires previously fetched Cargo caches. The test transport is not installed. The disable preset prevents default activation under standard preset policy; an administrator can override presets.

## File ownership and destination

All package files are root-owned and normally mode 0644; the executable is 0755.

| Source | Installed destination |
|---|---|
| Built Rust host | `/usr/libexec/fidophir` |
| `fidophir.service` | `/usr/lib/systemd/system/fidophir.service` |
| `fidophir.sysusers` | `/usr/lib/sysusers.d/fidophir.conf` |
| `fidophir.modules-load` | `/usr/lib/modules-load.d/fidophir.conf` |
| `72-fidophir.rules` | `/usr/lib/udev/rules.d/72-fidophir.rules` |
| `org.local.fidophir.policy` | `/usr/share/polkit-1/actions/org.local.fidophir.policy` |
| `00-fidophir.preset` | `/usr/lib/systemd/system-preset/00-fidophir.preset` |
| `owner.conf.example` | `/usr/share/doc/fidophir/owner.conf.example` |

systemd creates `/var/lib/fidophir` as fidophir:fidophir, 0700. The binary creates its v1 record directory with mode 0700 and synchronizes the parent directory on initial creation. Numeric record files and GLib's transient replacements are 0600 under umask 0077. Hold the v1 directory fd's advisory flock for the process lifetime; do not lock a replaceable record-file inode. No tmpfiles rule, user service, D-Bus name/service registration, private PAM stack or desktop autostart entry is needed.

## Source layout we own

```text
src/main.rs       startup, shutdown, serialized core loop
src/env.rs        OpenSK Env, clock/RNG/profile, resident KeyStore, backend reference
src/io.rs         uhid-virt event mapping; existing core HID helpers while busy
src/state.rs      per-record Persist via I/O worker, durable writes/unlink, parent record
src/tpm.rs        scoped ESAPI jobs and validated TPM object templates
src/backend.rs    typed blocking worker, PinAuthority and opaque ECDSA key implementation
src/approval.rs   GIO login1/polkit calls, operation-scoped cancellation
patches/          complete OpenSK diff; three interface changes and resident-only guard
packaging/        the files in this directory
```

Automated tests use fake approval or a private login1/polkit D-Bus double, disposable swtpm and independent FIDO clients. Actual Fedora GNOME/browser acceptance checks are still required. No production simulator/remote-TCTI switch or software-key backend ships. One blocking-I/O worker executes TPM jobs and record reads/listing/writes/deletions, keeping blocking filesystem operations off the protocol thread. The filesystem is authoritative; there is no application-wide record cache to reconcile. Worker tasks are typed Rust closures over a bounded channel inside the same process, not a listening IPC endpoint. Use glib v2_66 for file_set_contents_full and nix fs for the directory flock; both crates are already dependencies. Deletion uses standard-library remove_file plus directory File::sync_all. No rusqlite/SQLite dependency or aggregate CBOR snapshot format remains.

## Initialization after RPM installation

Fedora 44 RPM automatically processes the installed sysusers file to create service accounts/groups and reloads declarative policy through standard package hooks. It does not enable/start the service or add a desktop user automatically. Runtime shared-library requirements come from the RPM's ELF dependency generator; require systemd/udev, polkit and tpm2-tss explicitly. Test with the host GNOME polkit agent installed. fprintd/PAM supplies optional biometrics; do not edit host authentication configuration in scriptlets.

For this owner, the administrator would create `/etc/fidophir/owner.conf` from the example, root:root 0600, add **ophir only to fidophir-client**, and start the service after a fresh login picks up membership. The service's private primary fidophir group grants UHID creation; its unit supplies SupplementaryGroups=tss for TPM access, with no redundant static membership. Never grant fidophir/tss to Firefox or the desktop user. Load uhid through the supplied modules-load configuration or the normal administrator module-loading command; no daemon CAP_SYS_MODULE.

The binary reads only FIDOPHIR_OWNER_UID/SEAT from the environment, validates a numeric non-service owner UID and seat, and connects to the fixed system-bus destinations. systemd parses the file, so we do not own an INI/TOML parser. TCTI is fixed in the binary, independent of environment variables.

Set/change the PIN in Firefox `about:webauthn`, then use the sites' normal passkey enrollment. No PKCS#11 provider is loaded into Firefox and no extension is installed.

## Exact prompt context

`operation` is one of `create a passkey`, `sign in`, `select the authenticator`, `initialize the authenticator PIN`, `reset the authenticator`. `rp` is either empty or ` for <escaped RP ID>` (leading space included). It never includes a caller-provided URL, executable name or arbitrary instruction. Display text is limited to a validated RP ID of at most 253 bytes; reject control characters. Values are data, never shell arguments or format strings. Native GNOME layout, translations of its controls, credential entry and biometric state remain outside our code.

The no-interaction polkit precheck must reject nonempty `polkit.retains_authorization_after_challenge`; interactive success must reject `polkit.temporary_authorization_id`. A nonempty `polkit.dismissed` is denial. These fields and CheckAuthorization/CancelCheckAuthorization are documented in the [polkit authority API](https://polkit.pages.freedesktop.org/polkit/eggdbus-interface-org.freedesktop.PolicyKit1.Authority.html). This still trusts host administrator policy and the agent/PAM path.

## Review and release checks

Validate the unit with systemd-analyze, rules with udevadm verify, XML against the installed polkit DTD, and sysusers in a temporary root. These checks do not establish runtime isolation. In the Fedora VM also inspect the created device with udevadm/getfacl, actual service credentials/capabilities and SELinux context, and /proc process maps/fds. Confirm only the owner can access the generated hidraw node. Confirm the private network namespace can still reach the system D-Bus Unix socket.

Before testing the owner path, use `udevadm test` on the actual generated hidraw sysfs path and confirm IMPORT{parent} supplies HID_UNIQ and the final ACL has no automatic uaccess grant. This depends on a real created UHID node and is not established by rule syntax validation. Reject package release if the match fails; do not widen it to all hidraw devices.

The unit intentionally has no manually curated syscall-number filter. GLib/GIO, Rust threads and ESAPI retain their normal required syscalls, with systemd's explicit filesystem/network/device restrictions. No application-specific SELinux policy is shipped or claimed. Keep enforcing mode in integration tests.

No build-time internet, git branch dependencies or runtime downloads. Include exact vendor hashes, Cargo.lock, license files and a dependency inventory in the source package. Cargo sources compile into the host; native GLib/GIO and TPM2-TSS remain Fedora-managed shared libraries. Fedora native-library security updates and Rust source dependency updates consequently have different rebuild requirements.

Upgrade preserves state and uses systemd RPM macros; restart invalidates transient authorizations and removes/recreates the device. Unsupported schema refuses startup. Remove/stop without deleting state. The service cannot reset the TPM or repair shared DA lockout. Administrator state deletion loses local credentials but cannot revoke copied parent blobs; revoke website registrations separately.

## Debian 13 package

`debian/` uses debhelper 13 for systemd lifecycle, sysusers integration and shared
library dependencies. Build from the offline source bundle, with the declared
native dependencies and Rust/Cargo >= 1.92:

```sh
dpkg-buildpackage --build=binary --no-sign
```

The build is offline and runs the host/core tests. Complete third-party licenses
and dependency inventory are included. The device TCTI is a runtime dlopen plugin,
so `libtss2-tcti-device0t64` and `tpm-udev` are explicit dependencies rather than
relying solely on ELF dependency detection. Debian 13 is the supported DEB baseline.

Debhelper does not start or enable this experimental service, including on upgrade.
After configuring and accepting a new package, start it explicitly; restart it
manually after Debian upgrades. The removal hook uses standard `deb-systemd-invoke`
to stop the unit; state is preserved. Account creation uses `dh_installsysusers`;
there are no PAM edits or desktop-user group changes.
