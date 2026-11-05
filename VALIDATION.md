# Validation

## Validated

- Host and OpenSK unit tests passed.
- Software TPM integration tests passed.
- Private D-Bus desktop tests passed.
- Formatting and Clippy passed.
- RPM build and package checks passed.
- Fedora 44/45 install, removal, and reinstallation preserved state.
- Service and device permissions were checked.
- FIDO tools registered and authenticated a credential with the physical TPM.
- Valid and malformed HID packets were tested.
- webauthn.io registration and authentication passed in Firefox on Fedora 44.
- webauthn.io registration and authentication passed in the in-app browser on Fedora 45.
- v2 state corruption and recovery were tested.
- Concurrent FIDO requests and service restarts were tested.
- [Issue #5](https://github.com/lovasoa/fidophir/issues/5) tracks incorrect free-slot reporting for malformed credentials.
- Sustained concurrent FIDO client use caused intermittent timeouts.

## Remaining physical acceptance

- Install and test the latest built RPM; physical checks used an earlier build.
- Reboot.
- Multiple users, sessions, lock, and logout.
- Desktop approval denial and cancellation.
- Google and GitHub passkeys.
- Power-loss recovery.
- Determine the cause of concurrent-client timeouts.
- Clean Fedora build with declared dependencies.
- Independent security audit.
- FIDO certification.
