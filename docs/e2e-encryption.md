# SentinelX E2E field encryption

The E2E agent keeps the standard SentinelX WebSocket message structure. Routing metadata (`request`, `response`, `id`, `op`, etc.) remains unchanged; only the command/output text is protected by the E2E layer.

## Local keys

The agent reads keys **locally from the host filesystem**. It does not download keys from GitHub and does not use the repository as a runtime key store.

Expected files:

```text
/etc/sentinelx/keys/command-private.pem
/etc/sentinelx/keys/response-public.pem
```

The command private key decrypts incoming commands. The response public key encrypts textual command results/errors for the Cloud side. The matching Cloud-side private/public keys are outside this repository/runtime.

Recommended key permissions are directory `0700`, private key `0600`, public key `0644`, with explicit read access for the dedicated service account where required.

## Encrypted payload format

The only accepted command transport is:

```text
echo sx1:<ephemeral-x25519-public>:<nonce>:<ciphertext-and-tag>
```

The `<payload>` after `echo ` is therefore an `sx1:` encrypted message. The payload uses URL-safe base64 components. X25519 provides ephemeral key agreement, HKDF-SHA256 derives the AEAD key, and ChaCha20-Poly1305 provides authenticated encryption.

The agent deliberately does **not** accept the old native form `sx1:...` without the `echo ` wrapper. This makes the E2E transport unambiguous and prevents a plaintext SentinelX command from accidentally reaching the normal executor.

## Command processing

For every incoming Hub `request`:

1. The request must be an `exec` request with a dictionary payload.
2. `payload.command` must be a string beginning exactly with `echo sx1:`.
3. If the format is wrong, the command is **not executed** and the agent returns an **unencrypted** format error:

```text
команда не соответствует формату "echo <payload>", где <payload> - зашифрованное сообщение в формате "sx1:<ephemeral-public-key>:<nonce>:<ciphertext+tag>"
```

4. A correctly formatted encrypted command is recorded in the wire audit.
5. The `sx1:` payload is decrypted with the local command private key.
6. The plaintext command is recorded only in the host-local plaintext audit.
7. The plaintext command is passed to the normal executor, where the existing SentinelX allowlist/policy is still applied.
8. A decrypted command that is not allowed by policy does not gain any additional privilege from E2E encryption.
9. Command output is recorded locally in plaintext, encrypted, recorded again in the wire audit, and sent to the Hub using the normal SentinelX response message.

Errors caused by an invalid E2E payload/decryption/execution are returned as protocol response errors. Format errors are deliberately plaintext so the sender can correct the transport. Successful command output and normal command errors are encrypted before leaving the agent.

## Response encryption

Textual response fields (`stdout`, `stderr`, `output`, `message`) are encrypted before being sent to the Hub. `error.message` is encrypted as well when it belongs to the E2E execution path.

Binary transfer frames are outside this field-level encryption mechanism.

## Host-local audit logs

The E2E layer maintains two separate JSONL logs:

```text
/var/log/sentinelx/crypto-wire-audit.jsonl
/var/log/sentinelx/crypto-plaintext-audit.jsonl
```

### Wire audit

`crypto-wire-audit.jsonl` contains encrypted inbound commands and encrypted outbound response fields. It is the audit trail of what crossed the E2E boundary.

### Plaintext audit

`crypto-plaintext-audit.jsonl` contains the decrypted command and plaintext command result. It is strictly host-local and must never be copied into the normal SentinelX Hub audit.

## Append-only protection

The agent must never perform retention, trimming, rotation, replacement, or deletion of these audit files. In particular, the E2E audit code does not implement a maximum line count and does not call `rename`, `replace`, or equivalent operations on an existing audit file. Each record is appended and `fsync()` is called after the write.

The Linux installer additionally protects the files at the filesystem level:

```text
/var/log/sentinelx/crypto-wire-audit.jsonl
/var/log/sentinelx/crypto-plaintext-audit.jsonl
```

are created as:

- owner: `root`
- group: the agent service group
- mode: `0620`
- filesystem attribute: `append-only` (`chattr +a`)

The log directory itself is `root:root` and `0755`. Therefore the service account can append to the existing files, but cannot unlink or rename them. The `append-only` attribute also prevents truncating or overwriting existing contents through ordinary file writes.

The systemd service runs with a dedicated unprivileged account and `NoNewPrivileges=true`, `ProtectSystem=strict`, and `ProtectHome=true`. This provides defense in depth against the agent modifying its own audit history.

### Important limitation

This is protection against the **agent/service account** modifying its audit trail. It is not protection against a fully compromised host `root` account. A host administrator/root can deliberately remove the append-only attribute with `chattr -a` and rotate or delete the files.

If audit integrity against host-root compromise is eventually required, the audit records must also be forwarded to an independent logging system or another trust domain. That is outside the current E2E-agent scope.

### Log rotation

Automatic rotation by the agent is intentionally forbidden because rotation necessarily removes or replaces historical records. If rotation is needed, it must be an explicit privileged administrator operation and must be documented as an audit-chain boundary.

## Installer behavior

`scripts/install-agent.sh` prepares the two audit files and attempts to set `chattr +a`. If `chattr` is unavailable, installation prints a warning because filesystem-level append-only protection could not be established.

The service still uses:

```text
LogsDirectory=sentinelx
ReadWritePaths=/var/log/sentinelx
```

but these systemd settings do not by themselves provide append-only integrity; the ownership/mode and `chattr +a` protection described above are required.
