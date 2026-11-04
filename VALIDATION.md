# Validation

**Physical acceptance has not been completed.** Simulator tests do not show that Fidophir works with a real TPM, Firefox, GNOME or a particular website. Keep an independent account recovery method and use disposable accounts for testing.

## Evidence so far

On 4 November 2026, tests on Fedora 44 covered the following:

- OpenSK and host unit tests passed, including storage, locking, HID framing and cancellation. Clippy passed with warnings treated as errors.
- An independent FIDO client and disposable software TPM exercised PIN setup and failures, key creation and signatures, token expiry, credential management, restart and PIN changes. The tests confirmed that an old parent backup still works with its old PIN.
- The desktop adapter was tested against simulated login1 and polkit services on a private D-Bus. These tests covered denial, cancellation, unsuitable sessions and late responses; they did not use a real GNOME agent or PAM.
- An offline source bundle and RPM were built and inspected. The local RPM build did not verify its declared build dependencies in a clean Fedora build environment.

No independent audit, FIDO certification, power-loss qualification or resistance to a privileged attacker has been established. The test run did not change the physical TPM or enroll website credentials.

## Physical acceptance (not yet run)

A tester with administrator access should perform these checks on a Fedora 44 GNOME test machine before treating Fidophir as a usable authenticator. Record the package, TPM, Firefox and operating system versions and the results. Keep existing recovery credentials. Do not reset or deliberately lock out a TPM that holds valuable keys.

1. Install and configure the package as described in the [README](README.md#install-for-testing). Confirm the owner is on the configured seat, is logged in locally with an unlocked session, and belongs to `fidophir-client` but not `fidophir` or `tss`.
2. Start the service and inspect its identity, capabilities, device access, open files, state permissions and SELinux behavior. Confirm it is nonroot, has no Linux capabilities or listening network socket, and can reach the system D-Bus under its service restrictions.
3. Find the generated hidraw device with `udevadm info` and test its actual sysfs path with `udevadm test`. Confirm the virtual device identity and `HID_UNIQ=fidophir-v1`, root ownership, group `fidophir-client`, mode 0660 and no `uaccess` ACL (`getfacl`). Confirm another desktop user cannot open it. Rule syntax checks alone do not establish the final permissions.
4. In Firefox `about:webauthn`, set and change the PIN. Verify a fresh desktop approval for initial setup, enrollment and sign-in. Test denial, cancellation, no agent, locking the screen, switching sessions and delayed responses. Record whether password and fingerprint approval work under the existing host policy.
5. Enroll and use passkeys on disposable Google and GitHub accounts. Test multiple accounts, selection, cancellation, wrong PIN, PIN changes, old tokens, service restart and reboot. Confirm this Firefox version works with ClientPIN v2 and required user verification.
6. Under load, check that TPM latency and HID keepalives do not cause incorrect responses or permit canceled operations. Verify the device disappears on stop and reappears on restart, credentials survive an upgrade, and authorization expires. Power-loss testing requires separate disposable state.
