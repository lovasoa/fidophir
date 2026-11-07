Fidophir state, layout v2
========================

credentials/00000/ through credentials/00299/ are stable storage slots.
Each directory holds one passkey. Names are in metadata.ini:

  [credential]
  format_version=1
  rp_id=example.com
  creation_order=1
  user_name=alice
  user_display_name=Alice
  cred_protect_policy=3

Strings use GLib key-file escaping. Names, icon and protection policy are optional.
creation_order defaults to zero. Protection policies: 1=optional verification,
2=verification unless listed, 3=required verification. The production profile
also requires PIN verification. Unknown INI keys are ignored.

Binary fields use fixed filenames, with no encoding:
  credential-id.bin       Required, 32 bytes
  user-handle.bin         Required, up to 64 bytes (may be empty)
  tpm-signing-blob.bin    Required, Trusted Platform Module-wrapped ES256 key;
                          NOT a plaintext key
  cred-blob.bin           Optional opaque credential data
  large-blob-key.bin      Optional large-blob key

non-discoverable/00000/ through 00299/ hold credentials used only when the
website supplies their ID. They share metadata.ini, credential-id.bin,
tpm-signing-blob.bin and optional cred-blob.bin with discoverable credentials.
Their metadata has format_version, cred_protect_policy and rp_id_hash (lowercase
hex SHA-256). OpenSK supplies no website or account names for these records.
Compare a known RP ID with: printf %s example.com | sha256sum
CTAP credential management does not list them. Remove a security key at its
website before deleting its local directory. Keep the shared TPM parent.

Administration
--------------
Stop fidophir@UID.service before editing, deleting, copying or backing up state.
Directories must be owned by the fidophir service account, mode 0700; files 0600.
Symlinks and hard-linked files are not accepted. Each file is bounded to 4096
bytes, and the credential's OpenSK encoding is bounded to 4096 bytes.

Edit user_name, user_display_name or user_icon to change account presentation.
Other fields are authentication state; edit only to repair a known problem.
Delete a whole credential directory to remove that passkey locally. This does
not revoke it at the website or invalidate backups. A running operation may already have loaded it.

Invalid credentials are renamed to e.g. credentials/00000.damaged-1/ and the
failing path is reported in the journal. Their numbered slots can be reused.
To restore one, stop the service, repair its files, and rename the directory to
an unused five-digit slot (00000 through 00299). Keep the shared TPM parent.
Filesystem and permission errors are reported without parking the credential.
Unknown filenames are ignored.

Shared state
------------
authenticator/tpm-parent.bin protects ALL credentials and contains PIN-related
Trusted Platform Module state. Never edit it. If missing with credentials present,
or malformed, Fidophir refuses to provision a replacement. Restore a matching
backup. Other
files in authenticator/ are shared OpenSK settings or large-blob shards; their
names describe their purpose. They are binary unless named *.flag (presence is
meaningful). Shared-state errors affect all operations.

Back up the complete state root with the service stopped, including this v2/
directory. Backups work only with the same Trusted Platform Module and hierarchy
state; clearing or losing the Trusted Platform Module can make them unusable. An
old parent backup retains its old PIN.
There is no protection against privileged edits or rollback.

Crash recovery
--------------
Initialization creates missing directories and this reference; retry if interrupted.

Hidden *.pending directories are unpublished writes, cleaned up at startup.
Credential replacements atomically exchange whole directories, so metadata and
binary files stay together across crashes. PIN and shared settings are replaced
as individual durable files. Backups are not transactions.

For an intentional complete reset, stop the service and remove v2/.
