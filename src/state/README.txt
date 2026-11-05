Fidophir state, layout v2
========================

credentials/00000/ through credentials/00299/ are stable storage slots.
Each directory holds one passkey. Website and account names are in metadata.ini:

  [credential]
  format_version=1
  rp_id=example.com
  creation_order=1
  user_name=alice
  user_display_name=Alice
  cred_protect_policy=3

Strings use GLib key-file escaping (\n, \r, \t, \s, \\).
Optional names, icon and protection policy may be absent. creation_order defaults
as in OpenSK if absent. Protection policies: 1=optional verification,
2=verification unless listed, 3=required verification. The production profile
also requires PIN verification. Unknown INI keys are ignored.

Binary fields use fixed filenames, with no encoding:
  credential-id.bin       Required, 32 bytes
  user-handle.bin         Required, up to 64 bytes (may be empty)
  tpm-signing-blob.bin    Required, TPM-wrapped ES256 key; NOT a plaintext key
  cred-blob.bin           Optional opaque credential data
  large-blob-key.bin      Optional large-blob key

Administration
--------------
Stop fidophir@UID.service before editing, deleting, copying or backing up state.
Directories must be owned by the fidophir service account, mode 0700; files 0600.
Symlinks and hard-linked files are not accepted. Each file is bounded to 4096
bytes, and the credential's OpenSK encoding is bounded to 4096 bytes.

Edit user_name, user_display_name or user_icon to change account presentation.
Do not change RP ID, credential ID, user handle, policy or binary data casually:
these are authentication state. A well-formed edit is used on the next read.
Delete a whole credential directory to remove that passkey locally. This does
not revoke it at the website or invalidate backups. A running operation may
already have loaded it, so deletion is not an immediate revocation mechanism.

Damaged credentials are skipped, with the failing path reported in the journal.
Their slots stay reserved: new registrations never overwrite them. Restore the
files with correct ownership/permissions, or remove the whole directory. No
credential cache needs rebuilding. Unrecognized filenames are ignored.

Shared state
------------
authenticator/tpm-parent.bin protects ALL credentials and contains PIN-related
TPM state. Never edit it. If missing with credentials present, or malformed,
Fidophir refuses to provision a replacement. Restore a matching backup. Other
files in authenticator/ are shared OpenSK settings or large-blob shards; their
names describe their purpose. They are binary unless named *.flag (presence is
meaningful). A shared-state error can affect all operations and is reported.

Back up the complete state root with the service stopped, including this v2/
directory. Backups work only with the same TPM and hierarchy state; clearing or
losing the TPM can make them unusable. An old parent backup retains its old PIN.
There is no protection against privileged edits or rollback.

Crash recovery
--------------
Initialization creates missing directories and this format reference. An
interrupted initialization can be retried.

Hidden *.pending directories are unpublished writes, cleaned up at startup.
Credential replacements atomically exchange whole directories, so metadata and
binary files stay together across crashes. PIN and shared settings are replaced
as individual durable files. Whole operations and backups are not transactions.

For an intentional complete reset, stop the service and remove v2/.
