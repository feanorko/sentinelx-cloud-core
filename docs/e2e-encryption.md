# SentinelX field encryption

The agent keeps the standard SentinelX WebSocket message structure. Encryption is applied only to textual command/output fields.

## Local keys

The agent reads keys **locally from the host filesystem**. It does not download keys from GitHub and does not use the repository as a runtime key store.

Expected files:

```text
/etc/sentinelx/keys/command-private.pem
/etc/sentinelx/keys/response-public.pem
```

For the current test VM these are the X25519 keys generated for SentinelX. The command private key is used to decrypt incoming `exec.payload.command`. The response public key is used to encrypt textual response fields for the Cloud side.

The process running the agent must have read access to `/etc/sentinelx/keys`. Recommended permissions are directory `0700`, private key `0600`, and public key `0644`. If the agent runs as a dedicated service account, grant that account read access explicitly (for example with group ownership/ACL); do not make private keys world-readable.

The matching Cloud-side private key is required to decrypt responses, and the Cloud-side public key is required by the sender to encrypt commands. Those Cloud-side keys are outside this agent repository/runtime.

## Encrypted field format

Encrypted text is represented as:

```text
sx1:<ephemeral-x25519-public>:<nonce>:<ciphertext-and-tag>
```

The payload is URL-safe base64. X25519 performs ephemeral key agreement and ChaCha20-Poly1305 provides authenticated encryption. HKDF-SHA256 derives the AEAD key.

## SentinelX message compatibility

The normal `request`, `response`, `id`, `op`, and other routing fields are unchanged.

For `exec`, the agent supports two encrypted command transports:

1. **Native encrypted field:** `payload.command = sx1:...`
2. **Allowlisted echo transport:** `payload.command = echo sx1:...`

The second form is intentionally carried by the existing `echo` command, which is already present in the agent's normal `allowed_commands` policy. The agent consumes the `echo` wrapper before the `exec` handler runs. It decrypts the `sx1:` payload and replaces `payload.command` with the resulting plaintext command. The ordinary `exec` handler then applies the existing `allowed_commands` prefix policy to that plaintext command.

Therefore the encrypted transport does **not** grant additional command privileges: a decrypted command that is not allowed by the local policy is rejected exactly like an ordinary plaintext command. No new Hub operation and no new allowlist entry are required.

Textual response fields (`stdout`, `stderr`, `output`, `message`) are encrypted before the response is sent. Error messages are encrypted as well. Binary transfer frames are not encrypted by this field layer.

## Host-local audit

The crypto layer writes two independent append-only JSONL audit logs. They are host-local and are never included in SentinelX responses or sent to the Hub:

```text
/var/log/sentinelx/crypto-wire-audit.jsonl
/var/log/sentinelx/crypto-plaintext-audit.jsonl
```

`crypto-wire-audit.jsonl` contains the encrypted `sx1:` command/response fields exactly as seen by the crypto layer. `crypto-plaintext-audit.jsonl` contains the corresponding plaintext after command decryption and before response encryption.

Audit failures are best-effort and never abort command execution or response delivery. The service unit uses systemd `LogsDirectory=sentinelx` so `/var/log/sentinelx` is created with ownership suitable for the dedicated agent account.

The audit files must remain outside the normal SentinelX Hub audit path. In particular, plaintext commands and responses must never be copied into `/var/lib/sentinelx/audit.jsonl` or another Hub-forwarded log.

There is intentionally no attempt to obtain keys from GitHub at runtime.
