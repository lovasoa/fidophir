# OpenSK integration diff

Upstream: https://github.com/google/OpenSK

Commit: `8c81bc299886deb221beed35e2fe01a822649d67`

Base directory: `libraries/opensk`. `vendor/OpenSK` is a pinned Git submodule; `build/cbor` is its unmodified sibling crate
from the same commit. Apache-2.0 licenses are retained. No embedded kernel is included.

`opensk.patch` is the complete integration diff, including test adaptations.
`FILES` lists affected files. Apply with `patch -p1` inside a fresh copy of the
upstream standalone library; compare the result with `build/opensk` after `make prepare`.
The build creates those ignored outputs from the submodule and never changes the
upstream checkout. No copied third-party implementation is tracked in this repository.
The engine lockfile in `locks/opensk.Cargo.lock` is a separate build input, not part of that diff.

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
3. `env`, `ctap/mod.rs`: add two optional platform hooks for credential creation
   and signing. Linux overrides them to call the TPM. Their defaults preserve
   upstream software behavior. Generic crypto traits, private-key helpers, CTAP1,
   credential management and their fixtures stay unchanged. Unexpected TPM errors
   stop the service; systemd handles restart. Expected PIN refusals and cancellation
   still use the engine's normal error responses.

ClientPIN cleanup wraps an unchanged command dispatcher in a separate method,
so its original match does not need to be reindented in our diff.

The `resident_only` feature adds an early rejection of nonresident registration
without changing library defaults. The host selects it explicitly. Its counter
zero behavior is a host `Persist` override, not another engine patch.

Tests are run with `--no-default-features --features std --lib` (346) and with
upstream defaults plus `std` (393). The extra timeout assertion verifies that
expiry calls `PinAuthority::clear`; a changed failure assertion verifies that
failed forced-PIN changes no longer retain authorization. Hardware paths are
tested separately by the independent Python FIDO client against swtpm.
