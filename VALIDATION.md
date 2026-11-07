# Validation

## Run checks

After installing the [build dependencies](README.md#build-and-test), run:

```sh
make test
```

For the software TPM and desktop approval integration tests, install `swtpm`, `tpm2-tools`, `python3-fido2`, `python3-gobject`, and `dbus-daemon` on Fedora, then run:

```sh
make integration
```

These tests use a disposable software TPM and a private D-Bus session. For package lifecycle tests in a disposable VM, see [the systemd test instructions](tests/systemd/README.md).

## Validated

Example test systems: Fedora 44 and 45.

- Host and OpenSK unit tests passed.
- Software TPM integration tests passed.
- Private D-Bus desktop tests passed.
- Formatting and Clippy passed.
- RPM build and package checks passed.
- Package install, removal, and reinstallation preserved state.
- Service and device permissions were checked.
- FIDO tools registered and authenticated a credential with the physical TPM.
- Valid and malformed HID packets were tested.
- webauthn.io registration and authentication passed in Firefox.
- webauthn.io registration and authentication passed in the in-app browser.
- Passkey sign-in succeeded on GitHub, Google, Microsoft, and Cloudflare.
- v2 state corruption and recovery were tested.
- Concurrent FIDO requests and service restarts were tested.
- [Issue #5](https://github.com/lovasoa/fidophir/issues/5) tracks incorrect free-slot reporting for malformed credentials.
- Sustained concurrent FIDO client use caused intermittent timeouts.

## Remaining physical acceptance

- Install and test the latest built RPM; physical checks used an earlier build.
- Reboot.
- Multiple users, sessions, lock, and logout.
- Desktop approval denial and cancellation.
- Power-loss recovery.
- Determine the cause of concurrent-client timeouts.
- Clean package builds with declared dependencies.
- Independent security audit.
- FIDO certification.
