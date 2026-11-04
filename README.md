# Fidophir

[![Packages CI](https://github.com/lovasoa/fidophir/actions/workflows/packages.yml/badge.svg?branch=main)](https://github.com/lovasoa/fidophir/actions/workflows/packages.yml)

Fidophir exposes a Linux computer's TPM (a security chip found in most modern computers) as a virtual USB physical security key, allowing passkey authentication in web browsers. A passkey lets you sign in to a website without sending it a password. The TPM protects the private keys; wrapped key material and account information are stored on the computer. Firefox asks for a Fidophir PIN, and the desktop asks for approval when needed.

**Experimental:** Fidophir was built for me, Ophir. I intend to use it and fix bugs and security issues as I find them, but offer no guarantee whatsoever. Do not rely on it as your only way into an account. See [validation](VALIDATION.md).

Fidophir supports up to 64 passkeys on one computer; they cannot be synced or moved to another TPM.

## What does it protect against?

The table compares typical setups. It assumes a unique password, a password manager such as 1Password, a FIDO2 YubiKey and the intended Fidophir setup. A stolen credential can be used later from another device; a stolen session or an abused sign-in can give access without exporting the credential. A website’s account recovery process can bypass these protections. Costs are examples in US dollars and may vary by region and over time.

🟢 Protection in the stated scenario · 🟡 Limited, conditional or untested · 🔴 Vulnerable or access lost

| Threat | Password | Passkey in a password manager | Passkey on a YubiKey | Fidophir |
|---|---|---|---|---|
| Fake website tries to steal a login (phishing) | 🔴 Vulnerable if entered | 🟢 Resists fake-domain phishing | 🟢 Resists fake-domain phishing | 🟢 Designed to resist fake-domain phishing |
| Attacker reads unencrypted network traffic | 🔴 A captured password can be reused | 🟢 The passkey secret is not sent and the sign-in proof cannot be reused | 🟢 The passkey secret is not sent and the sign-in proof cannot be reused | 🟢 The passkey secret is not sent and the sign-in proof cannot be reused |
| Website's login database is stolen | 🔴 Stored passwords may be cracked | 🟢 The website stores no secret usable to sign in | 🟢 The website stores no secret usable to sign in | 🟢 The website stores no secret usable to sign in |
| Malicious program runs as your user, without taking over the browser or desktop | 🔴 May steal a typed or stored password and use it elsewhere | 🔴 May access an unlocked vault and copy passkeys, depending on the manager; may also trick you into approving a login | 🟡 Cannot normally copy the key; may trick you into approving a login while the key is connected | 🟢 Cannot normally copy the key for use elsewhere; may request a login and trick you into approving it |
| Attacker controls the browser or desktop, or has administrator (root) access | 🔴 Can steal passwords and use them elsewhere | 🔴 Can abuse an unlocked vault and may copy passkeys for use elsewhere | 🟡 Cannot normally copy the key; can request logins while it is connected and trick you into providing touch or PIN | 🟡 Cannot normally export the TPM key for use elsewhere, but can capture the PIN and use the TPM to sign in on this computer; desktop approval cannot be trusted |
| Attacker has physical access to the device | 🔴 Passwords in use or in an unlocked vault may be read from computer memory and reused elsewhere | 🔴 Passkeys in an unlocked software vault may be read from computer memory and copied for use elsewhere | 🟢 The private key is used inside the YubiKey and is not normally exposed in computer memory; physical attacks may still be possible | 🟢 The private key is used inside the TPM and is not normally exposed in computer memory; physical attacks have not been tested |
| Stored or synced credentials are copied | 🔴 Copied passwords can be used | 🟡 Depends on vault encryption and access | 🟢 Private keys cannot normally be copied | 🟢 Stolen key files cannot be used on another device or without the PIN |
| Device is lost or damaged | 🟡 Password works elsewhere if remembered or backed up | 🟡 Synced or backed-up vault may restore access | 🔴 A separate registered key or recovery method is needed | 🔴 The TPM and local state are both needed; use a separate recovery method |
| Cost | Free to choose and remember | Free options exist; [1Password Individual](https://1password.com/pricing/personal) is $3.99/month, billed annually, at its regular price | One-time purchase: [YubiKey 5 NFC](https://www.yubico.com/us/product/yubikey-5-nfc/) is $58; a backup key costs extra | Free software; requires a compatible computer with a TPM |

Ordinary user-level malware may also take over the browser or desktop; if it does, the second malware row applies. Passkey protection assumes the browser and website implement the protocol correctly. The YubiKey column describes common FIDO2 use, not every model or configuration. Fidophir's protections are design goals supported by simulator tests, not physical-device security claims. Malware can also steal an authenticated browser session after any of these sign-in methods.

Fidophir is useful if you want a hardware-backed passkey on the computer you already use, without a separate security key. A physical security key has a separate device and touch control; Fidophir does not provide the same isolation from a compromised computer.

## Important limits

- Your TPM and Fidophir's local state are both needed. Keep another sign-in or recovery method for every account.
- Changing the Fidophir PIN or deleting a local passkey does **not** revoke a copied older state file on the same TPM. To revoke access, remove the passkey from the website.
- Fidophir trusts the computer's administrator, kernel, browser and desktop approval system. It does not protect against privileged malware or guarantee protection against physical attacks.
- Too many wrong PIN attempts can permanently block the Fidophir PIN, requiring local state removal and re-enrollment. Attempts can also contribute to the TPM's shared lockout, affecting other software. Fidophir cannot clear TPM lockout.
- The desktop approval request describes the operation and website, but its text is supplied by the client and is not proof of the browser's origin. Fingerprint availability depends on your desktop configuration.

See [design](DESIGN.md) for the security boundaries and implementation.

## Install for testing

Installation requires administrator access. The package does not start the service or enroll a passkey. On Fedora 44:

```sh
wget https://github.com/lovasoa/fidophir/releases/latest/download/fidophir.rpm
sudo dnf install ./fidophir.rpm
```

On Debian 13:

```sh
wget https://github.com/lovasoa/fidophir/releases/latest/download/fidophir.deb
sudo apt install ./fidophir.deb
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
