# Validation record — 2026-11-04

This records what the tests establish and what still needs a real Fedora desktop.
No physical TPM, host policy, user groups or website credentials were modified.

## Automated evidence

* Rust 1.98.1; host Fedora 44; native GLib 2.88.4 and TPM2-TSS 4.1.5.
* Patched upstream library: 346/346 tests with `--no-default-features --features std
  --lib`; 393/393 with upstream defaults plus `std`. These include software crypto
  as upstream test infrastructure, not as the production signing backend.
* Host: 5/5 tests covering durable replace/delete/reopen, exclusive locking,
  rejection of symlinks/hardlinks/wrong permissions/noncanonical names, record
  bounds, validated crash-temp cleanup, busy-channel isolation, cancellation and exact report-ID normalization.
* `cargo clippy --all-targets --features integration-tests -- -D warnings` passes.
* `tests/interop.py --expiry`: independent Fedora python-fido2 client with synthetic
  accounts, disposable swtpm and test-only pipe transport. The Rust test runner
  allocates a real CTAPHID channel and fragments/reassembles messages through the
  upstream HID core. It exercises:
  * ClientPIN v2 setup and hardware rejection of an incorrect PIN, independently
    checked by reading the TPM DA counter; rejection of an all-zero candidate
    matching the public configured-PIN marker, also checked against TPM DA;
  * two TPM-generated resident keys, self-attestation and signatures independently
    verified using the returned COSE public keys;
  * always-UV, presence flags, zero counters, no software verifier record or clear
    PIN hash in state, resident-only rejection and RP-bound tokens;
  * actual 30-second token expiry and reauthorization;
  * PIN change preserving credential files, new-PIN success and old-PIN rejection
    across process restart, forced same-PIN rejection and removal of the forced-change
    flag after a successful change, plus standard credential enumeration;
  * a corrupted TPM private blob stopping the process with status 1; restart rejects
    old tokens and requires fresh PIN authorization before signing;
  * no loaded TPM objects/sessions left after graceful shutdown;
  * successful reuse of an old parent backup with its old PIN (documented limitation);
  * denied approval blocking registration/signing;
  * eight wrong attempts, per-process soft blocks and permanent retry exhaustion
    surviving restarts, including rejection of the correct PIN after exhaustion.
* `tests/desktop.py`: actual native GIO adapter on a **private D-Bus**, fake login1/
  polkit services and disposable swtpm. Tests typed wire calls, operation/RP context, denied initial PIN setup leaving
  configuration untouched,
  success, denied/silent/retained/temporary/no-agent results, locked/inactive/remote/
  wrong-owner/ambiguous sessions, and lock changes after approval. Cancellation
  reaches `CancelCheckAuthorization`; a deliberately late success cannot authorize
  a later denied operation. This does not exercise a real GNOME agent or PAM.

The optimized default executable builds from the source bundle with an empty Cargo
cache and offline source replacement. The bundle's own tests run offline too. Its
ELF is PIE with RELRO, immediate binding, nonexecutable stack and dynamic GIO/GLib/
TPM2-TSS dependencies. The complete upstream patch applies cleanly and reproduces
all modified source files. Unit syntax validates using the actual built executable
path in a temporary unit copy; this does not start the unit. Udev syntax, polkit XML
against Fedora's DTD, and account creation in a temporary sysusers root validate.

The binary and source RPM recipes build offline using workspace-extracted Fedora
RPM tools and native development files (no host package installation). The local
build skips RPM BuildRequires resolution because the Rust toolchain is supplied
by rustup; this is not a clean Fedora mock build. Package inspection confirms
native shared-library dependencies, RPM 6 sysusers user/group metadata, standard
systemd scriptlets, the disabled preset, root-owned files and no integration runner.
A normal Fedora build with its declared BuildRequires remains the packaging
qualification path.

No power-loss or privileged active-interposer resistance is established. The tests
do not constitute an independent security audit or FIDO conformance certification.

## Physical device access check

The default workspace sandbox hides the nodes. A read-only check outside it found
`/dev/tpmrm0` mode 0660 root:tss and `/dev/uhid` mode 0600 root:root. The current
user belongs to neither device group. An explicit device-TCTI capability query
failed with permission denied; `sudo -n tpm2_getcap` failed because a password is
required. No TPM commands were successfully issued and no device permissions were
changed. Physical tests therefore remain pending administrator installation of
the reviewed service, rather than absence of hardware.

## Required physical acceptance (not run here)

1. Install the reviewed package in an enforcing Fedora 44 GNOME test environment.
   Verify owner UID/seat and active unlocked graphical session. Confirm the owner
   has `fidophir-client` and neither `fidophir` nor `tss` membership. Start manually.
2. Inspect `systemctl show fidophir -p User -p Group -p SupplementaryGroups
   -p CapabilityBoundingSet -p AmbientCapabilities -p DevicePolicy -p DeviceAllow`.
   Inspect `/proc/$(systemctl show -p MainPID --value fidophir)/status`, fds and maps.
   Confirm nonroot service UID, zero effective/permitted/inheritable/ambient Linux
   capabilities, only intended device files, native shared libraries, nondumpability,
   no network listening socket and state ownership/modes.
3. Identify the generated node using `udevadm info` and its exact sysfs path; run
   `udevadm test` on that path. Confirm `HID_UNIQ=fidophir-v1`, the virtual bus/ID
   match, owner root, group fidophir-client, mode 0660 and **no uaccess ACL** with
   `getfacl`. Confirm a different desktop user cannot open it. Rule syntax validation
   alone cannot establish the parent-property import or final ACL.
4. Use Firefox `about:webauthn` to create/change the PIN. Verify a fresh GNOME
   `auth_self` prompt for initial PIN setup, enrollment and sign-in; test denial,
   cancellation, no agent, screen lock, session switching and delayed responses.
   Fingerprint availability is determined by host polkit/PAM; do not promise it
   based only on successful fingerprint login. Do not edit PAM to make a test pass.
5. Register and use disposable Google and GitHub passkeys through Firefox, including
   multiple accounts, discoverable account selection, cancellation, restarting the
   service and rebooting. Confirm PIN v2 and required-UV interoperability with this
   exact Firefox version. Test retained old tokens and PIN changes on the physical
   path. Keep original recovery credentials.
6. Observe real TPM latency and HID keepalives under load; no Firefox transport
   timeout, cross-channel response or hung approval may authorize a signature.
   Confirm the system-bus Unix socket remains reachable under the unit's private
   network namespace, and SELinux permits only the expected service behavior.
7. Stop and upgrade the service; the device must disappear/reappear, authorization
   must expire, and credentials must survive. Reboot and confirm recovery. Treat
   forced crash/power-loss testing as a separate qualification exercise on disposable
   state. Do not reset or deliberately lock out a TPM holding valuable other keys.

Ship/use as an accepted desktop authenticator only after these checks succeed.
