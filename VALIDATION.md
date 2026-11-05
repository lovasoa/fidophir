# Validation

**Physical acceptance is partially complete.** Simulator tests do not show that Fidophir works with a real TPM, Firefox, GNOME or a particular website. Keep an independent account recovery method and use disposable accounts for testing.

## Automated checks

`make test` exercises storage durability and recovery, unsafe-file rejection, HID framing and cancellation, PIN-hash access, authorization expiry and package activation policy.

`make integration` runs an independent Python FIDO client against a disposable software TPM and a private D-Bus. It needs `swtpm`, `tpm2-tools`, `python3-fido2`, `python3-gobject` and `dbus-daemon`. It covers:

- PIN setup/change, malformed candidates, persistent retry limits and TPM dictionary-attack accounting.
- Independently verified registration and signing, token permissions, RP binding, expiry and stale-token rejection after host revocation.
- Credential management, corrupt-record isolation, repair, restart recovery and signing failures.
- Fresh desktop approval, denial, unsuitable sessions, cancellation and late replies.

For the full-store case, run `python3 tests/interop.py --binary target/debug/fidophir-integration --capacity`. The simulator handles synthetic credentials only. Its crash-recovery fixture clears transient handles in that private simulator to model the kernel TPM resource manager; it does not touch the host TPM.

`make integration-hid` checks registration, signing and credential management through UHID, hidraw and the FIDO command-line tools. It needs `swtpm`, `fido2-tools` and access to `/dev/uhid` and the generated hidraw device.

Package lifecycle fixtures check installation, logout, upgrade/removal and repeated crash recovery in disposable Fedora and Debian systemd containers. They use dummy workers, so they do not validate device access, TPM hardware or the production sandbox; see [packaging](packaging/README.md#lifecycle-tests).

## Physical coverage

Fedora 44 with GNOME and Firefox 159 has been tested for PIN setup with desktop approval, registration and authentication on webauthn.io, PIN persistence across package upgrades, device ownership, and package removal. Browser discovery after an upgrade required a full browser restart.

Reboot, multiple users, Google/GitHub compatibility, UHID rediscovery after crashes, kernel TPM resource cleanup, and signing-time cancellation remain unverified. Cancellation during an infallible signing callback can restart the service. No independent audit, FIDO certification, power-loss qualification or resistance to a privileged attacker has been established.

## Remaining physical acceptance

A tester with administrator access should perform these checks on a Fedora 44 GNOME test machine before treating Fidophir as a usable authenticator. Record the package, TPM, Firefox and operating system versions and the results. Keep existing recovery credentials. Do not reset or deliberately lock out a TPM that holds valuable keys.

1. Install and configure the package as described in the [README](README.md#install-for-testing). Confirm separate `fidophir@UID.service` instances start for two desktop users without account/group changes. Test installation during an existing login, subsequent login/logout, reboot, upgrade and removal.
2. Start the service and inspect its identity, capabilities, device access, open files, state permissions and SELinux behavior. Confirm it is nonroot, has no Linux capabilities or listening network socket, and can reach the system D-Bus under its service restrictions.
3. Find the generated hidraw device with `udevadm info` and test its actual sysfs path with `udevadm test`. Confirm the virtual device identity and `HID_PHYS=fidophir-v2`, `HID_UNIQ` equal to the numeric desktop UID, that UID as owner, group `root`, mode 0600 and no `uaccess` ACL (`getfacl`). Confirm another desktop user cannot open it, discover its credentials or exhaust its PIN retries. Test simultaneous seats, fast user switching and a previously opened descriptor after session lock/logout; approval must never move to another user. Rule syntax checks alone do not establish the final permissions.
4. Use `fido2-token -S /dev/fidophir-$(id -u)` to set the PIN and `fido2-token -C /dev/fidophir-$(id -u)` to change it. Verify a fresh desktop approval for initial setup, enrollment and sign-in. Test denial, cancellation, no agent, locking the screen, switching sessions and delayed responses. Record whether password and fingerprint approval work under the existing host policy.
5. Enroll and use passkeys on disposable Google and GitHub accounts. Test multiple accounts, selection, cancellation, wrong PIN, PIN changes, old tokens, service restart and reboot. Confirm this Firefox version works with ClientPIN v2 and required user verification.
6. Under load, check that TPM latency and HID keepalives do not cause incorrect responses or permit canceled operations. Verify the device disappears on stop and reappears on restart, credentials survive an upgrade, and authorization expires. Power-loss testing requires separate disposable state.
