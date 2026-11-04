# Fidophir

[![Packages CI](https://github.com/lovasoa/fidophir/actions/workflows/packages.yml/badge.svg?branch=main)](https://github.com/lovasoa/fidophir/actions/workflows/packages.yml)

Fidophir exposes a Linux computer's TPM (a security chip found in most modern computers) as a virtual USB physical security key, allowing passkey authentication in web browsers. A passkey lets you sign in to a website without sending it a password. The TPM protects the private keys; wrapped key material and account information are stored on the computer. Firefox asks for a Fidophir PIN, and the desktop asks for approval when needed.

**Experimental:** Fidophir was built for me, Ophir. I intend to use it and fix bugs and security issues as I find them, but offer no guarantee whatsoever. Do not rely on it as your only way into an account. See [validation](VALIDATION.md).

Fidophir supports up to 64 passkeys on one computer; they cannot be synced or moved to another TPM.

## What does it protect against?

The table compares typical setups. It assumes a unique password, a password manager such as 1Password, a FIDO2 YubiKey and the intended Fidophir setup. A website’s account recovery process can bypass any of these protections.

| Threat | Password | Passkey in a password manager | Passkey on a YubiKey | Fidophir |
|---|---|---|---|---|
| Fake website tries to steal a login (phishing) | Vulnerable if entered | Resists fake-domain phishing | Resists fake-domain phishing | Designed to resist fake-domain phishing |
| Attacker intercepts network traffic | HTTPS normally protects the password | The passkey secret is not sent | The passkey secret is not sent | The passkey secret is not sent |
| Website's login database is stolen | Stored passwords may be cracked | No secret usable to sign in is stored by the website | Same | Same |
| Malware running as your user | Can steal a typed or stored password | May access an unlocked vault or trick you into approving | Cannot normally export the key; may trick you into approving a login | TPM key cannot normally be exported; malware may use the device or trick you into approving |
| Attacker controls the computer, browser or desktop | Vulnerable | Vulnerable when used on that computer | Key stays on the YubiKey, but attacker may misuse an approved operation | **Not protected:** Fidophir trusts these components |
| Someone has the physical device | Can read or use passwords if they can unlock the computer or vault | Depends on device and vault security | Needs the key and may need its PIN; touch is required for normal login | Normal sign-in needs the PIN and desktop approval; physical attacks are untested |
| Stored or synced credentials are copied | Copied passwords can be used | Depends on vault encryption and access | Private keys cannot normally be copied | Wrapped keys work only with the same TPM and PIN; copied old state can still be used there |
| Device is lost or damaged | Password can be used elsewhere if remembered or backed up | Synced or backed-up vault may restore access | A separate registered key or recovery method is needed | The TPM and local state are both needed; use a separate recovery method |

Passkey protection assumes the browser and website implement the protocol correctly. The YubiKey column describes common FIDO2 use, not every model or configuration. Fidophir's protections are design goals supported by simulator tests, not physical-device security claims. Malware can also steal an authenticated browser session after any of these sign-in methods.

Fidophir is useful if you want a hardware-backed passkey on the computer you already use, without a separate security key. A physical security key has a separate device and touch control; Fidophir does not provide the same isolation from a compromised computer.

## Important limits

- Your TPM and Fidophir's local state are both needed. Keep another sign-in or recovery method for every account.
- Changing the Fidophir PIN or deleting a local passkey does **not** revoke a copied older state file on the same TPM. To revoke access, remove the passkey from the website.
- Fidophir trusts the computer's administrator, kernel, browser and desktop approval system. It does not protect against privileged malware or guarantee protection against physical attacks.
- Too many wrong PIN attempts can permanently block the Fidophir PIN, requiring local state removal and re-enrollment. Attempts can also contribute to the TPM's shared lockout, affecting other software. Fidophir cannot clear TPM lockout.
- The desktop approval request describes the operation and website, but its text is supplied by the client and is not proof of the browser's origin. Fingerprint availability depends on your desktop configuration.

See [design](DESIGN.md) for the security boundaries and implementation.

## Install for testing

[Download a package](https://github.com/lovasoa/fidophir/releases/latest). Installation requires administrator access. The package does not start the service or enroll a passkey. Install the downloaded package using the appropriate command, replacing the filename with yours:

```sh
sudo dnf install ./fidophir-PACKAGE.x86_64.rpm  # Fedora 44
# or: sudo apt install ./fidophir-PACKAGE_amd64.deb  # Debian 13
```

For first-time setup, configure the owner. Existing users should keep their configuration. Replace `YOUR_DESKTOP_USER` with your login name. Find its numeric ID with `id -u YOUR_DESKTOP_USER`, and your current seat with `loginctl show-session "$XDG_SESSION_ID" -p Seat --value`. Enter those values as `FIDOPHIR_OWNER_UID` and `FIDOPHIR_OWNER_SEAT` in the editor; verify them before starting the service.

```sh
sudo install -d -m 0755 /etc/fidophir
sudo test -e /etc/fidophir/owner.conf || sudo install -m 0600 /usr/share/doc/fidophir/owner.conf.example /etc/fidophir/owner.conf
sudoedit /etc/fidophir/owner.conf
sudo usermod -aG fidophir-client YOUR_DESKTOP_USER
sudo modprobe uhid
sudo udevadm control --reload
sudo udevadm trigger --subsystem-match=misc --sysname-match=uhid
```

Add the desktop user only to `fidophir-client`, not to `fidophir` or `tss`.

Log out and back in so the group change takes effect, then run:

```sh
sudo systemctl start fidophir.service
```

Complete the [physical acceptance checklist](VALIDATION.md#physical-acceptance-not-yet-run) before relying on Fidophir; use disposable accounts during testing. Open `about:webauthn` in Firefox to set the Fidophir PIN, then use a website's passkey setup. This PIN is separate from your desktop login password; the desktop approval may also ask for your login password or fingerprint. If startup fails, inspect `journalctl -u fidophir.service`. Only enable automatic startup (`sudo systemctl enable fidophir.service`) after acceptance.

Stopping or removing the service preserves `/var/lib/fidophir`. There is no automatic reset or migration tool. If you lose the PIN, an administrator must stop the service and remove its local state before starting over; this removes all local Fidophir passkeys. Use each website's recovery method to enroll new passkeys. Debian package and build details are in [packaging](packaging/README.md).

## Build and test

On Fedora 44, install the build tools:

```sh
sudo dnf install rust cargo gcc make clang-libs clang-devel pkgconf-pkg-config glib2-devel tpm2-tss-devel
```

Rust and Cargo 1.92 or newer are required. From an extracted release source bundle:

```sh
sha256sum --check SHA256SUMS
make build
make test
```

Builds are locked and offline. For a Git checkout, fetch the pinned submodule and dependencies first:

```sh
git submodule update --init
make prepare
cargo fetch --locked
cargo fetch --locked --manifest-path build/opensk/Cargo.toml
make build
make test
```

`make integration` additionally needs `swtpm`, `tpm2-tools`, `python3-fido2`, `python3-gobject` and `dbus-daemon`. It uses disposable simulators and a private D-Bus, not the host TPM or real accounts. Its test-only binary is not for deployment. See [validation](VALIDATION.md) for what the tests cover and what remains untested.
