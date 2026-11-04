# Fidophir

[![Packages CI](https://github.com/lovasoa/fidophir/actions/workflows/packages.yml/badge.svg?branch=main)](https://github.com/lovasoa/fidophir/actions/workflows/packages.yml)

Fidophir exposes a Linux computer's TPM (a security chip found in most modern computers) as a virtual USB physical security key, allowing passkey authentication in web browsers. A passkey lets you sign in to a website without sending it a password. The TPM protects the private keys; wrapped key material and account information are stored on the computer. Firefox asks for a Fidophir PIN, and the desktop asks for approval when needed.

**Experimental:** Fidophir was built for me, Ophir. I intend to use it and fix bugs and security issues as I find them, but offer no guarantee whatsoever. Do not rely on it as your only way into an account. See [validation](VALIDATION.md).

Fidophir supports up to 300 passkeys per user on one computer; they cannot be synced or moved to another TPM.

## What does it protect against?

The table compares typical setups. It assumes a unique password, a password manager such as 1Password, a FIDO2 YubiKey and the intended Fidophir setup. A stolen credential can be used later from another device; a stolen session or an abused sign-in can give access without exporting the credential. A website’s account recovery process can bypass these protections. Costs are examples in US dollars and may vary by region and over time.

| Threat | Password | Passkey in a password manager | Passkey on a YubiKey | Fidophir |
|---|---|---|---|---|
| Fake website tries to steal a login (phishing) | 🔴 Vulnerable if entered | 🟢 Resists fake-domain phishing | 🟢 Resists fake-domain phishing | 🟢 Designed to resist fake-domain phishing |
| Attacker reads unencrypted network traffic | 🔴 A captured password can be reused | 🟢 The passkey secret is not sent and the sign-in proof cannot be reused | 🟢 The passkey secret is not sent and the sign-in proof cannot be reused | 🟢 The passkey secret is not sent and the sign-in proof cannot be reused |
| Website's login database is stolen | 🔴 Stored passwords may be cracked | 🟢 The website stores no secret usable to sign in | 🟢 The website stores no secret usable to sign in | 🟢 The website stores no secret usable to sign in |
| Malicious program runs as your user, without taking over the browser or desktop | 🔴 May steal a typed or stored password and use it elsewhere | 🔴 May access an unlocked vault and copy passkeys, depending on the manager; may also trick you into approving a login | 🟢 Cannot normally copy the key; may trick you into approving a login while the key is connected | 🟢 Cannot normally copy the key for use elsewhere; may request a login and trick you into approving it |
| Attacker has administrator (root) access | 🔴 Can steal passwords and use them elsewhere | 🔴 Can abuse an unlocked vault and may copy passkeys for use elsewhere | 🟢 Cannot normally copy the key; has to trick you to touch the key to use it.       | 🟡 Cannot  export the keys for use elsewhere, but can use the TPM silently to sign in to websites      |
| Attacker has physical access to the device | 🔴 Passwords in use or in an unlocked vault may be read from computer memory and reused elsewhere | 🔴 Passkeys in an unlocked software vault may be read from computer memory and copied for use elsewhere | 🟢 The private key is used inside the YubiKey and is not normally exposed in computer memory; physical attacks may still be possible | 🟢 The private key is used inside the TPM and is not normally exposed in computer memory; physical attacks have not been tested |
| Stored or synced credentials are copied | 🔴 Copied passwords can be used | 🟡 Depends on vault encryption and access | 🟢 Private keys cannot normally be copied | 🟢 Stolen key files cannot be used on another device or without the PIN |
| Device is lost or damaged | 🟡 Password works elsewhere if remembered or backed up | 🟡 Synced or backed-up vault may restore access | 🔴 A separate registered key or recovery method is needed | 🔴 The TPM and local state are both needed; use a separate recovery method |
| Cost | Free | a few euros a month   |  dozens of euros, once| Free |

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

You need a computer with a TPM, a local graphical desktop session, and administrator access to install the package. Use a disposable account while testing: browser and website compatibility on physical hardware is still being verified.

On Fedora 44:

```sh
wget https://github.com/lovasoa/fidophir/releases/latest/download/fidophir.rpm
sudo dnf install ./fidophir.rpm
```

On Debian 13:

```sh
wget https://github.com/lovasoa/fidophir/releases/latest/download/fidophir.deb
sudo apt install ./fidophir.deb
```

The package starts Fidophir for each logged-in user. Each user has their own PIN and passkeys; no logout or account configuration is needed.

### Set your PIN

1. In Firefox, open `about:webauthn` and select the **PIN** tab in the sidebar (separate from device information). Approve the desktop prompt if asked.
2. Choose a PIN of at least four characters. It is separate from your desktop login password.

Set the PIN before enrolling with Firefox: Firefox on Linux may not offer to create one during website enrollment. Chrome may offer PIN setup during enrollment, but this flow has not yet been verified with Fidophir. Once set, the same Fidophir PIN works in both browsers.

Firefox 159 on Fedora 44 has a known page-layout issue: the PIN panel can remain hidden after selection. For testing, removing the `hidden` attribute from `#set-change-pin-section` in the page Inspector reveals the form until the page is reloaded. This is a temporary browser workaround, not a verified first-use experience.

### Add a passkey

1. Sign in to a website and start adding a passkey. For example, open [Google's passkey settings](https://myaccount.google.com/signinoptions/passkeys) and choose **Create a passkey**, or follow [GitHub's passkey instructions](https://docs.github.com/en/authentication/authenticating-with-a-passkey/managing-your-passkeys). You can also add one to a [Microsoft account](https://support.microsoft.com/en-us/accounts-billing/security/create-save-passkey).
2. When asked where to save it, choose a **security key**. You may need to select **Use another device** or **Save another way** first. Fidophir appears to the browser as a security key; there is no physical key to plug in.
3. Enter your Fidophir PIN and approve the desktop prompt. The desktop may ask for your login password or fingerprint. Follow the website's remaining prompts to finish.
4. Next time you sign in, choose the passkey or security key option and follow the PIN and approval prompts.

Keep another sign-in or recovery method for each account. Fidophir passkeys stay on this computer and cannot be moved to another one. If you forget the PIN, resetting Fidophir removes its local passkeys, so you will need your recovery methods to enroll again.

### Troubleshooting

- **No security key appears:** Make sure your desktop session is local, active and unlocked. Check the service status with `systemctl status "fidophir@$(id -u).service"`.
- **The service fails to start:** Read its error messages with `journalctl -u "fidophir@$(id -u).service" -b`. Check that the computer has a working TPM and that `/dev/tpmrm0` and `/dev/uhid` exist.
- **No approval prompt appears:** Unlock the screen and make sure your desktop can show authentication prompts, then retry.
- **Enrollment fails or asks for a PIN:** Set the PIN in Firefox's `about:webauthn`, select the security key option, and retry. Browser and website compatibility is still being tested.
- **Forgotten or blocked PIN:** Follow the reset steps below. Avoid repeated guesses, which can also lock the TPM temporarily.

### Reset a forgotten or blocked PIN

Resetting deletes **all your Fidophir passkeys** on this computer. You will need another sign-in or recovery method for each website, then add new passkeys. Other users' Fidophir passkeys are unaffected.

1. Open a terminal in your own desktop account and check where your state is stored:

   ```sh
   systemctl show "fidophir@$(id -u).service" --property=StateDirectory --value
   ```

2. If the output is `fidophir-users/` followed by your user ID, stop the service and delete your state:

   ```sh
   sudo systemctl stop "fidophir@$(id -u).service" && sudo rm -rf -- "/var/lib/fidophir-users/$(id -u)/v1"
   ```

   If the output is `fidophir`, you have a legacy installation. Use this command instead:

   ```sh
   sudo systemctl stop "fidophir@$(id -u).service" && sudo rm -rf -- /var/lib/fidophir/v1
   ```

   If the output is different, do not delete anything: your service has a custom state location. Check its configuration first.

3. Start the service again, then set a new PIN and add passkeys as described above:

   ```sh
   sudo systemctl start "fidophir@$(id -u).service"
   ```

If the TPM itself is locked, resetting Fidophir does not clear that lockout. Check the service journal as described above and wait for the TPM lockout to clear before trying again.

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
