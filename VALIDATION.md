# Validation

## Validated

- Host and OpenSK tests, software-TPM integration, private D-Bus desktop tests, formatting, and Clippy passed.
- RPM build and checks passed. Fedora 44/45 package install, removal, and reinstallation preserved each version's state; service and device permissions were checked. The v1 store was not migrated to v2.
- A physical TPM, FIDO command-line tools, and valid and malformed HID packets were exercised. Registration and authentication worked on webauthn.io in Firefox on Fedora 44 and in the in-app browser on Fedora 45.
- v2 state corruption and recovery, concurrent clients, and service restarts were tested. [Issue #5](https://github.com/lovasoa/fidophir/issues/5) tracks incorrect free-slot reporting for malformed credentials. Sustained concurrent FIDO client use caused intermittent timeouts; the cause is unknown.

## Remaining physical acceptance

- Install and test the latest built RPM; physical checks used an earlier build.
- Reboot, multiple users and sessions, lock/logout, and desktop approval denial and cancellation.
- Google/GitHub passkeys, power-loss recovery, and the concurrent-client timeouts.
- A clean Fedora build with declared dependencies, independent security audit, and FIDO certification.
