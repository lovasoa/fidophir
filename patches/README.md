# OpenSK patch

Fidophir pins [OpenSK](https://github.com/google/OpenSK) at `8c81bc299886deb221beed35e2fe01a822649d67`. `make prepare` copies its standalone library and CBOR sibling into `build/` and applies `opensk.patch`; it does not modify the submodule. Release source bundles include the prepared sources. `FILES` lists the complete patch scope.

| Upstream file | Change |
|---|---|
| `src/env/mod.rs` | Adds hooks for PIN verification, grant cleanup, credential creation and signing, with software defaults for upstream tests. |
| `src/ctap/client_pin.rs` | Calls the PIN hooks, clears grants with the token lifecycle and requests presence for initial PIN setup. |
| `src/ctap/mod.rs` | Routes credential creation and signing through the hooks. |

The Linux host uses the existing pre-dispatch hook to capture operation context and reject non-discoverable credentials. Both it and OpenSK use OpenSK's parser. Existing persistence interfaces configure the TPM PIN; the configured-PIN marker is not a verifier. See [design](../DESIGN.md) for the security boundaries and [validation](../VALIDATION.md) for test evidence.
