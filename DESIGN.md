# Design

Fidophir is an experimental Linux host for the [OpenSK](https://github.com/google/OpenSK) authenticator library. Firefox sees a virtual security key; OpenSK handles the FIDO protocol, while Fidophir connects it to the TPM, local storage and the desktop approval system.

## Components

- `src/env.rs` and `src/main.rs` connect OpenSK to the Linux host and run its protocol loop.
- `src/io.rs` exposes a virtual HID device. `src/backend.rs` runs blocking storage and TPM work without stopping protocol keepalives.
- `src/tpm.rs` creates and uses TPM keys. `src/state.rs` stores records on disk.
- `src/approval.rs` asks login1 and polkit for a fresh approval in the configured owner's local, active, unlocked session.
- [The OpenSK patch](patches/README.md) adds the hooks needed for TPM-backed PIN verification and signing.
- [Packaging](packaging/README.md) provides the service, permissions and build recipes.

The production profile supports discoverable ES256 passkeys only, with a limit of 300, a minimum PIN length of eight Unicode code points, ClientPIN v2, and required user verification. It uses a zero signature counter, zero AAGUID and self-attestation. It does not support CTAP1, non-discoverable credentials, TPM migration or sync. Compatibility with particular browsers and websites remains to be tested.

## Security boundaries

The TPM generates each credential's private key and keeps its scalar non-exportable. The disk holds TPM-wrapped key blobs and account metadata. A PIN-authorized TPM parent protects the credential keys; wrong PINs reach the TPM's dictionary-attack protection. There is no software PIN verifier on disk. TPM sessions protect secret parameters where the command supports it.

The daemon temporarily holds authorization material in memory while an OpenSK token is valid. Expiry, relevant errors, PIN changes and restart clear the cached grant. This does not guarantee removal of all copies from native libraries, the kernel or a compromised machine. PIN setup and change also process the PIN in daemon memory.

When CTAP requests user presence, Fidophir requires a fresh desktop challenge; it rejects silent or retained authorization and unsuitable sessions. Operations that request `up=false` do not gain a physical touch. Approval and the PIN are separate checks. Prompt context comes from the client, and the session lock check is not atomic with signing.

The design trusts root, the kernel, the service account, browser, desktop agent and host polkit/PAM policy. A compromised daemon can bypass software approval checks. It does not claim protection against privileged live malware, active TPM interposition, physical attacks, or rollback of state. There is no PCR policy or anti-rollback counter.

An old copy of the TPM parent can still be used with its old PIN on the same TPM after a PIN change. Deleting local state does not revoke a copied credential. Revoke credentials at the website when necessary. Losing either the TPM or state loses access to these passkeys. TPM lockout is shared with other applications; Fidophir does not clear or reconfigure it.

## Storage and failure handling

State is stored under `/var/lib/fidophir/v1/` in private, bounded files, one per OpenSK record. A directory lock prevents concurrent instances. Each replacement is atomic and durable subject to filesystem guarantees; deletion synchronizes the directory. A complete operation may update more than one record and is not a transaction. Stop the service before making a consistent backup. Unknown layouts or invalid records fail closed.

The protocol loop serializes operations. A bounded worker handles TPM and filesystem requests; the loop continues to send keepalives and process cancellation. A canceled TPM result is discarded, while an in-progress durable write finishes before cancellation is honored. Unexpected storage or TPM failures stop the process; there is no software signing fallback. Restart clears transient grants and preserves state.

The service runs as a dedicated unprivileged account with access to the TPM and UHID devices. The desktop user is granted access only to the generated authenticator device through `fidophir-client`. The systemd unit restricts filesystem, device and network access. These controls do not isolate Fidophir from root or the kernel. Physical device permissions and SELinux behavior still require the checks in [validation](VALIDATION.md).
