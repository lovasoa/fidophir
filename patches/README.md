# OpenSK integration diff

Upstream: https://github.com/google/OpenSK at
`8c81bc299886deb221beed35e2fe01a822649d67`, directory `libraries/opensk`.
The pinned `vendor/OpenSK` submodule stays untouched. `make prepare` copies the
standalone library and its unmodified CBOR sibling into ignored build outputs,
then applies `opensk.patch` with Git. The engine-test lockfile lives separately
in `locks/opensk.Cargo.lock`. Release archives contain the exact prepared sources.

Only three upstream files change; `FILES` is the complete inventory:

| File | Injection points |
| --- | --- |
| `src/env/mod.rs` | Default methods for PIN verification/revocation and credential creation/signing. Software defaults preserve the existing TestEnv. |
| `src/ctap/client_pin.rs` | Delegate candidate verification after durable retry decrement; revoke platform grants with token reset/expiry/errors; require existing presence loop before first PIN setup. |
| `src/ctap/mod.rs` | Three credential calls: generation, self-attestation, assertion. |

Linux policy and RP prompt context use the **existing**
`Env::process_vendor_command` pre-dispatch hook. The adapter calls OpenSK's
`Command::deserialize`, sets request context, and normally returns `None` for core
processing; nonresident creation returns the standard unsupported-option response.
The core parses again normally. Both passes use upstream's parser; there is no
custom wire-format logic or protocol dispatcher in the adapter.

Existing `Persist::set_pin` provisions/changes TPM authorization. `pin_hash`
returns an opaque all-zero configured-PIN marker, never a verifier. Only the
candidate-verification hook checks PINs, in TPM. Existing `KeyStore` PIN methods
pass a new candidate directly to `set_pin` or expose the currently verified cache
for the forced-change equality check; no verifier file is written.

The generic crypto API, presence API, storage logic, manifest, fingerprint paths,
CTAP1, private-key helpers and TestEnv are unchanged. The host uses upstream's
`CtapState` and `MainHid` directly, polling token expiry regardless of Wink state.
Unexpected TPM/storage faults log and exit; systemd handles restart.

Core tests: 346 with std/no defaults, 393 with upstream defaults/std. Independent
simulator and private-D-Bus tests cover native overrides, including rejection of
the public marker, forced-PIN-change behavior and denied initial setup.
