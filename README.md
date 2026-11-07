# Fidophir

[![Packages CI](https://github.com/lovasoa/fidophir/actions/workflows/packages.yml/badge.svg?branch=main)](https://github.com/lovasoa/fidophir/actions/workflows/packages.yml)

Fidophir lets you use your Linux computer's built-in security hardware like a security key for passkeys. A passkey lets you sign in to a website without sending it a password. Fidophir presents a virtual security key to the browser; there is no separate USB key to plug in. Your computer's Trusted Platform Module (TPM) protects the private keys, while wrapped key material and account information are stored on the computer. Firefox asks for a Fidophir PIN, and the desktop asks for approval when needed.

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
- Too many wrong PIN attempts can block the Fidophir PIN. An administrator can reset its software counter if the PIN is known; a forgotten PIN requires local state removal and re-enrollment. Attempts can also contribute to the TPM's shared lockout, affecting other software. Fidophir cannot clear TPM lockout.
- The desktop approval request describes the operation and website, but its text is supplied by the client and is not proof of the browser's origin. Fingerprint availability depends on your desktop configuration.

See [design](DESIGN.md) for the security boundaries and implementation.

## Install for testing

You need a computer with a TPM, a local graphical desktop session, and administrator access to install the package. Use a disposable account while testing: browser and website compatibility on physical hardware is still being verified.

For RPM-based systems (for example, Fedora with DNF):

```sh
wget https://github.com/lovasoa/fidophir/releases/latest/download/fidophir.rpm
sudo dnf install ./fidophir.rpm
```

For DEB-based systems (for example, Debian with APT):

```sh
wget https://github.com/lovasoa/fidophir/releases/latest/download/fidophir.deb
sudo apt install ./fidophir.deb
```

The package starts Fidophir for each logged-in user. Each user has their own PIN and passkeys; no logout or account configuration is needed.

### Set your PIN

1. Install the FIDO tools with your package manager, for example `sudo dnf install fido2-tools` or `sudo apt install fido2-tools`.
2. Run `fido2-token -S /dev/fidophir-$(id -u)`. Choose a PIN of at least four characters and approve the desktop prompt if asked. The PIN is separate from your desktop login password.

Set the PIN before enrolling with Firefox: Firefox on Linux may not offer to create one during website enrollment. Chrome may offer PIN setup during enrollment, but this flow has not yet been verified with Fidophir. Once set, the same Fidophir PIN works in both browsers.

### Add a passkey

1. Sign in to a website and start adding a passkey. For example, open [Google's passkey settings](https://myaccount.google.com/signinoptions/passkeys) and choose **Create a passkey**, or follow [GitHub's passkey instructions](https://docs.github.com/en/authentication/authenticating-with-a-passkey/managing-your-passkeys). You can also add one to a [Microsoft account](https://support.microsoft.com/en-us/accounts-billing/security/create-save-passkey).
2. When asked where to save it, choose a **security key**. You may need to select **Use another device** or **Save another way** first. Fidophir appears to the browser as a security key; there is no physical key to plug in.
3. Enter your Fidophir PIN and approve the desktop prompt. The desktop may ask for your login password or fingerprint. Follow the website's remaining prompts to finish.
4. Next time you sign in, choose the passkey or security key option and follow the PIN and approval prompts.

Keep another sign-in or recovery method for each account. Fidophir passkeys stay on this computer and cannot be moved to another one. If you forget the PIN, resetting Fidophir removes its local passkeys, so you will need your recovery methods to enroll again.

### Troubleshooting

- **View logs:** Run `journalctl -u "fidophir@$(id -u).service" -b` to see logs since boot. Add `-f` to follow new messages as they arrive.
- **Understand key activity:** The journal records passkey creation, signing, PIN operations, passkey management and desktop approvals. Each request has a number (unique within one daemon process), its result, a protocol status code and elapsed time. Failed, successfully decoded creation and signing requests also log selected protocol options and whether certain fields were present; omitted options appear as their protocol defaults. A completed signing request means the key produced a response; it does not confirm that the website accepted a sign-in. Routine discovery and PIN helper queries are silent unless they fail. Website names, account details, credential identifiers, PINs, tokens and key material are excluded. To see full lines, add `--no-pager`; to show warnings and errors, add `-p warning`. Logs reveal when the key was used, so review them before sharing.
- **No security key appears:** Make sure your desktop session is local, active and unlocked. Check the service status with `systemctl status "fidophir@$(id -u).service"`.
- **Device path missing after an upgrade:** Run `sudo systemctl restart "fidophir@$(id -u).service"` to recreate it.
- **The service fails to start:** Read its error messages with `journalctl -u "fidophir@$(id -u).service" -b`. Check that the computer has a working TPM and that `/dev/tpmrm0` and `/dev/uhid` exist.
- **The key briefly disappears:** Hardware signing failures or internal compatibility checks can restart the service. It retries automatically; retry the browser operation after it returns. Inspect the journal if this repeats.
- **No approval prompt appears:** Unlock the screen and make sure your desktop can show authentication prompts, then retry.
- **Enrollment fails or asks for a PIN:** Set the PIN as described above, select the security key option, and retry. Browser and website compatibility is still being tested.
- **Forgotten or blocked PIN:** See the reset and retry-limit instructions below. Avoid repeated guesses, which can also lock the TPM temporarily.

### Manage your PIN and passkeys

Use the FIDO tools installed above. To change your PIN or list the websites with passkeys:

```sh
fido2-token -C /dev/fidophir-$(id -u)      # change PIN
fido2-token -L -r /dev/fidophir-$(id -u)   # list websites
```

To see passkeys for a website, copy its name from the list and run `fido2-token -L -k WEBSITE /dev/fidophir-$(id -u)`. The output includes the ID of each passkey; to remove one, run `fido2-token -D -i ID /dev/fidophir-$(id -u)` with its ID. Enter your PIN and approve desktop prompts when asked.

Deleting a passkey here does not remove it from the website; remove it there too. Keep another way to sign in.

### Saved credentials and maintenance

State lives under `/var/lib/fidophir-users/UID/v2/`. Each credential has a numbered directory with readable `metadata.ini` and separate binary files. `README.txt` inside the store explains editing, deletion, permissions and backup; the [format reference](src/state/README.txt) is also in this repository. Stop the user's service before maintenance. An invalid credential is parked and reported in the journal without disabling healthy credentials; its numbered slot can be reused.

### Reset a forgotten PIN

Resetting deletes **all your Fidophir passkeys** on this computer. You will need another sign-in or recovery method for each website, then add new passkeys. Other users' Fidophir passkeys are unaffected.

1. Open a terminal in your own desktop account, stop the service and delete your state:

   ```sh
   sudo systemctl stop "fidophir@$(id -u).service" && sudo rm -rf -- "/var/lib/fidophir-users/$(id -u)/v2"
   ```

2. Start the service again, then set a new PIN and add passkeys as described above:

   ```sh
   sudo systemctl start "fidophir@$(id -u).service"
   ```

If the TPM itself is locked, resetting Fidophir does not clear that lockout. Check the service journal as described above and wait for the TPM lockout to clear before trying again.
The journal reports the TPM's configured recovery interval when available; this is not the exact time remaining. TPM resets or loss of power can delay recovery. A confirmed TPM lockout does not consume a Fidophir PIN attempt.

### PIN retry limits and administration

Fidophir and the TPM maintain separate retry counters:

- **Fidophir's software counter** is per user. A correct PIN resets it; eight failed attempts block PIN verification until an administrator intervenes. Three consecutive wrong attempts also temporarily block verification until the service is restarted. Restarting does not reset the persistent count. Neither block deletes passkeys.
- **The TPM's counter** is shared with other software and uses settings configured on the computer. Failed protected authorizations increment the counter; reaching the configured maximum temporarily blocks protected TPM authorizations, even with the correct PIN. A successful PIN does not necessarily reset this counter. The TPM normally decreases it by one after each configured recovery interval without a TPM reset; power loss or resets can delay recovery. An interval of zero requires special handling. The configured interval is not the exact time remaining, and a TPM lockout may affect other applications. Restarting Fidophir or clearing its software counter does not clear the TPM lockout.

Use `sudo tpm2_getcap -T device:/dev/tpmrm0 properties-variable` to inspect `TPM2_PT_LOCKOUT_COUNTER`, `TPM2_PT_MAX_AUTH_FAIL`, and `TPM2_PT_LOCKOUT_INTERVAL` (seconds). The command requires `tpm2-tools` and suitable TPM access. Stop retrying while the TPM is locked and allow it to recover.

If the PIN is known and Fidophir's software counter is blocked, an administrator can reset that counter without deleting the PIN or passkeys. This bypasses the software retry limit; it does not make an unknown PIN recoverable or bypass the TPM's protections. Run these commands in the affected user's desktop account:

```sh
sudo systemctl stop "fidophir@$(id -u).service" &&
  sudo rm -f -- "/var/lib/fidophir-users/$(id -u)/v2/authenticator/pin-retries.bin" &&
  sudo systemctl start "fidophir@$(id -u).service"
```

Do not remove `tpm-parent.bin`: it protects all the user's passkeys. If the PIN is forgotten, use the full reset above and re-enroll using another sign-in method.

## Build and test

Install Rust, Cargo, a C compiler, Make, libclang, pkg-config, GLib development files (2.66 or newer), and TPM2-TSS development files. For example, on Fedora:

```sh
sudo dnf install rust cargo gcc make clang-libs clang-devel pkgconf-pkg-config glib2-devel tpm2-tss-devel
```

Rust and Cargo 1.92 or newer are required. From a Git checkout:

```sh
make build
make test
```

See [validation](VALIDATION.md) for simulator tests and hardware acceptance checks.

## Related projects

FIDO key management tools:

- [libfido2](https://github.com/Yubico/libfido2) provides the `fido2-token` command-line tool used above.
- [Keyroost](https://github.com/framefilter/keyroost) and [Token2 Key Manager / fido2-manage](https://github.com/token2/fido2-manage) provide graphical and command-line tools for managing FIDO keys. Their compatibility with Fidophir's virtual device has not been tested.

Other TPM-backed virtual authenticators:

- [tpm-fido](https://github.com/psanford/tpm-fido) is a Go/Linux U2F authenticator that emulates a security key and uses TPM-backed keys. Fidophir uses OpenSK to provide FIDO2 passkeys.
- [TuSK](https://github.com/irtimmer/TuSK) also combines OpenSK, UHID and TPM-backed signing. TuSK documents software PIN protection and a `pinentry` popup; Fidophir uses TPM-backed PIN authorization and desktop approval through polkit.
- [tpm-fido2-thinkpad-linux](https://github.com/mc256/tpm-fido2-thinkpad-linux) provides FIDO2 with TPM-backed keys and fingerprint verification through fprintd, plus a system tray toggle. Fidophir uses a PIN and desktop approval rather than requiring a fingerprint reader.
