# OpenSK integration diff

Upstream: https://github.com/google/OpenSK

Commit: `8c81bc299886deb221beed35e2fe01a822649d67`

Base directory: `libraries/opensk`. `vendor/cbor` is the unmodified sibling crate
from the same commit. Apache-2.0 licenses are retained. No embedded kernel is included.

`opensk.patch` is the complete integration diff, including test adaptations.
`FILES` lists affected files. Apply with `patch -p1` inside a fresh copy of the
upstream standalone library; compare the result with `vendor/opensk`.
Generated Cargo lockfiles are separate build inputs, not part of that diff.

The planned three interface changes are combined into one patch because their
call sites overlap. Review them by interface:

1. `api/pin.rs`, `env`, `client_pin.rs`, `storage.rs`: remove production dependence
   on a stored software PIN verifier. Delegate install/verify/change/clear to
   `PinAuthority`. Persist a retry before hardware verification. Revoke cached
   authorization on token reset/expiry and all ClientPIN command errors. TestEnv
   keeps its upstream software verifier strictly for library tests.
2. `api/user_presence.rs`, `ctap/mod.rs`, `client_pin.rs`: pass operation and RP
   context through the existing presence loop, including fresh approval before
   first PIN installation. Existing keepalive and cancellation behavior stays in
   the core. No second CTAP parser or custom prompt machinery is added.
3. `api/crypto/ec_signing.rs`, `api/private_key.rs`, `env`: make ECDSA generation
   and signing return `CtapResult`, with an explicit context from Env. Propagate
   failures through registration, assertion and self-attestation. Software crypto
   uses unit context; the host uses the TPM backend. Optional upstream CTAP1 call
   sites are adapted too, although the host does not enable CTAP1.

The `resident_only` feature adds an early rejection of nonresident registration
without changing library defaults. The host selects it explicitly. Its counter
zero behavior is a host `Persist` override, not another engine patch.

Tests are run with `--no-default-features --features std --lib` (346) and with
upstream defaults plus `std` (393). The extra timeout assertion verifies that
expiry calls `PinAuthority::clear`; a changed failure assertion verifies that
failed forced-PIN changes no longer retain authorization. Hardware paths are
tested separately by the independent Python FIDO client against swtpm.
