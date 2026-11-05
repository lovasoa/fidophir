# Validation

**Physical acceptance is partially complete.** Simulator tests do not show that Fidophir works with a real TPM, Firefox, GNOME or a particular website. Keep an independent account recovery method and use disposable accounts for testing.

## Evidence so far

On 4 November 2026, tests on Fedora 44 covered the following:

- OpenSK and host unit tests passed, including storage, locking, HID framing and cancellation. Clippy passed with warnings treated as errors.
- An independent FIDO client and disposable software TPM exercised PIN setup and failures, key creation and signatures, token expiry, credential management, restart and PIN changes. The tests confirmed that an old parent backup still works with its old PIN.
- The desktop adapter was tested against simulated login1 and polkit services on a private D-Bus. These tests covered denial, cancellation, unsuitable sessions and late responses; they did not use a real GNOME agent or PAM.
- An offline source bundle and RPM were built and inspected. The local RPM build did not verify its declared build dependencies in a clean Fedora build environment.

No independent audit, FIDO certification, power-loss qualification or resistance to a privileged attacker has been established. The simulator tests did not change the physical TPM or enroll website credentials; the separate physical checks below did.

## Storage v2 checks on 5 November 2026

The v2 layout passed host unit tests and the existing OpenSK and packaging suites. Disposable TPM integration tests exercised PIN changes, 300 credentials and full-store rejection, malformed metadata isolation across restart, immediate repair, administrator deletion across restart, cryptographically damaged signing blobs, missing shared-parent recovery, PIN retry persistence and token expiry. The private D-Bus desktop regression tests also passed. Clippy passed with warnings treated as errors. These checks used disposable state and did not access the hardware TPM.

A release-build benchmark on this machine's Btrfs/NVMe filesystem used 300 synthetic credentials and the real OpenSK lookup code and worker. Across 400 cached lookups with roughly 800-byte and 4096-byte records, median full scans took 7.6–8.5 ms and the largest observed sample was 21.1 ms. Twenty trials requesting file-data cache eviction had medians of 11.5–13.0 ms; filesystem metadata remained cached. These are measurements, not worst-case latency bounds. TPM signing and desktop approval were outside the timed interval. Physical acceptance and power-loss qualification of v2 remain pending.

## Unmodified OpenSK adapter checks on 5 November 2026

The host's 11 unit tests and all 346 unmodified OpenSK library tests passed, as did formatting, Clippy with warnings denied, the source-equivalence check and an optimized production build. Adapter tests cover the configured-PIN marker, retry-charge invariant failure diagnostics, unchanged HKDF output/request isolation, same-PIN hash reuse without another TPM call, and grant expiry.

The independent FIDO client and disposable software TPM passed the full suite with real 31-second expiry and 300-credential capacity. Added cases cover malformed encrypted candidates without TPM attempts, stale-token metadata reads/deletes after host revocation, tokens after restart, sanitized fail-stop signing errors, and recovery of healthy/repaired credentials. The private D-Bus desktop suite also passed. The raw TCP simulator needs transient-handle cleanup after an intentional crash; the fixture performs it only in that private simulator to model production's kernel TPM resource manager.

Real package lifecycle fixtures passed in disposable rootless Fedora 44 and Debian 13 systemd containers, including four consecutive crashes followed by automatic recovery under the production restart policy. These fixtures replace the authenticator worker, so they do not establish hardware or browser recovery. Physical UHID rediscovery, kernel TPM resource cleanup, and cancellation during an infallible signing callback still need acceptance testing. A cancellation reaching those infallible methods can restart the service.

## Physical checks on 4 November 2026

On this Fedora 44 GNOME desktop with Firefox 159, a locally built RPM was installed, upgraded, removed and reinstalled. Removal stopped the service, removed its virtual device and restored `/dev/uhid` to root:root mode 0600. State and the service account were retained. The generated hidraw device was owned by the desktop UID, group root, mode 0600 without an extra ACL. An independent FIDO client read its GetInfo response.

The tester successfully set a PIN with real desktop approval after the process-subject polkit fix. GetInfo confirmed the PIN was configured and polkit did not restart. A full browser restart restored discovery after a package upgrade. The tester also confirmed successful registration and authentication on webauthn.io in Firefox using a disposable test username. Polkit’s restart count stayed unchanged after the fix. A subsequent package upgrade preserved the configured PIN, as confirmed by GetInfo. Reboot, multiple users, Google/GitHub compatibility and the remaining checks below are still pending.

## Remaining physical acceptance

A tester with administrator access should perform these checks on a Fedora 44 GNOME test machine before treating Fidophir as a usable authenticator. Record the package, TPM, Firefox and operating system versions and the results. Keep existing recovery credentials. Do not reset or deliberately lock out a TPM that holds valuable keys.

1. Install and configure the package as described in the [README](README.md#install-for-testing). Confirm separate `fidophir@UID.service` instances start for two desktop users without account/group changes. Test installation during an existing login, subsequent login/logout, reboot, upgrade and removal.
2. Start the service and inspect its identity, capabilities, device access, open files, state permissions and SELinux behavior. Confirm it is nonroot, has no Linux capabilities or listening network socket, and can reach the system D-Bus under its service restrictions.
3. Find the generated hidraw device with `udevadm info` and test its actual sysfs path with `udevadm test`. Confirm the virtual device identity and `HID_PHYS=fidophir-v2`, `HID_UNIQ` equal to the numeric desktop UID, that UID as owner, group `root`, mode 0600 and no `uaccess` ACL (`getfacl`). Confirm another desktop user cannot open it, discover its credentials or exhaust its PIN retries. Test simultaneous seats, fast user switching and a previously opened descriptor after session lock/logout; approval must never move to another user. Rule syntax checks alone do not establish the final permissions.
4. Use `fido2-token -S /dev/fidophir-$(id -u)` to set the PIN and `fido2-token -C /dev/fidophir-$(id -u)` to change it. Verify a fresh desktop approval for initial setup, enrollment and sign-in. Test denial, cancellation, no agent, locking the screen, switching sessions and delayed responses. Record whether password and fingerprint approval work under the existing host policy.
5. Enroll and use passkeys on disposable Google and GitHub accounts. Test multiple accounts, selection, cancellation, wrong PIN, PIN changes, old tokens, service restart and reboot. Confirm this Firefox version works with ClientPIN v2 and required user verification.
6. Under load, check that TPM latency and HID keepalives do not cause incorrect responses or permit canceled operations. Verify the device disappears on stop and reappears on restart, credentials survive an upgrade, and authorization expires. Power-loss testing requires separate disposable state.

Package lifecycle fixtures have also been exercised with real systemd in rootless Fedora 44 and Debian 13 containers. They validate template UID propagation, systemd-managed state directories, account creation, upgrade/removal through the aggregate target, and policy/mask denial. Their dummy workers do not validate device access, TPM hardware or the production sandbox; see `tests/systemd_lifecycle.py`.
