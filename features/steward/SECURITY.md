# Steward Command Authentication

Every command received by the steward is authenticated before dispatch. This document describes the authentication contract implemented in Story #919.

## Command Authentication Contract

All commands travel as a `SignedCommand` envelope:

```go
type SignedCommand struct {
    Command   Command                    // inner value type — unchanged
    Signature *signature.ConfigSignature // cryptographic signature over canonical bytes
}
```

### Verification Steps (in order)

The steward handler (`features/steward/commands/handler.go`) applies the following checks before dispatching any command:

1. **Signature verification** — when a `Verifier` is configured, the handler verifies the `Signature` field against the canonical bytes of `Command` using `CommandSigningBytes`. Commands with a missing or invalid signature are rejected with `ErrUnauthenticatedCommand`.

2. **StewardID match** — `Command.StewardID` must equal the handler's own steward identity. Mismatches are rejected with `ErrWrongSteward` to prevent cross-steward command injection.

3. **Timestamp freshness** — `Command.Timestamp` must be within the configured replay window (default: 5 minutes). Stale commands are rejected with `ErrCommandReplay`. The window is configurable via `SignedCommandReplayWindow` in the steward config.

4. **Replay deduplication** — `Command.ID` is recorded in a bounded in-memory TTL cache. A second delivery of the same ID within the replay window is rejected with `ErrCommandReplay`. This catches duplicate delivery even when the timestamp is still fresh.

5. **Params size bound** — `Command.Params` serialised as JSON must not exceed `maxParamsBytes` (default: 64 KiB). Oversized params are rejected with `ErrParamsTooLarge`. The limit is configurable via `SignedCommandMaxParamsBytes` in the steward config.

## Cryptographic Scheme

Command signing uses the same primitives as configuration signing (`features/config/signature`):

- **Algorithm**: RSA-PSS (or ECDSA depending on key type)
- **Digest**: SHA-256
- **Signing input**: `CommandSigningBytes(cmd, rawParams)` — a JSON-encoded canonical payload with UTC timestamp and `map[string]string` params to avoid type mutations across proto round-trips

The controller signs each command in `features/controller/commands/publisher.go` using the same key and certificate used for configuration signing.

## Replay Window Trade-offs

| Window | Trade-off |
|--------|-----------|
| Shorter | Stricter freshness; clock-skew sensitive |
| Longer | More clock-skew tolerance; wider replay window |

The default of 5 minutes balances clock-skew tolerance (NTP-synced hosts rarely drift more than a few seconds) against the risk of accepting replayed commands. Operators in high-latency or poor-NTP environments may increase this via `signed_command_replay_window` in the steward configuration.

## Unsecured / Transitional Mode

When no `Verifier` is configured (e.g. in development or testing), signature verification is skipped. All other checks (StewardID match, timestamp freshness, replay dedup, params size) remain active.

## References

- `features/config/signature` — crypto primitives shared with configuration signing
- `pkg/controlplane/types/messages.go` — `SignedCommand` and `CommandSigningBytes` definitions
- `features/steward/commands/handler.go` — verification implementation
- `features/steward/commands/replay_cache.go` — bounded TTL deduplication cache

---

# Offline Queue Encryption

Implemented in Story #920. The offline event queue file is encrypted at rest with AES-256-GCM.

## Encryption Scheme

- **Algorithm**: AES-256-GCM (AEAD — provides both confidentiality and authenticity)
- **File**: `offline_queue.enc` (replaces legacy `offline_queue.json`)
- **On-disk format**: `[12-byte random nonce][ciphertext + 16-byte GCM authentication tag]`
- **Key source**: `pkg/secrets` slot `steward/offline-queue-key` (32 random bytes)
- **Key generation**: If the slot is absent, 32 random bytes are generated via `crypto/rand` and persisted to the SecretStore on first run
- **Authentication**: GCM's 128-bit authentication tag covers the entire ciphertext — tampering causes load failure with a clear authentication error

## Key Management

The encryption key is stored in the steward's SecretStore (OS-native encryption via the `steward` provider: DPAPI on Windows, AES-256-GCM on Linux/macOS). This provides defence-in-depth: the queue file is encrypted with a key that is itself encrypted by the OS.

When no SecretStore is available (e.g., first boot), a per-session random key is generated. In this case the queue is not persisted across restarts (key is in-memory only).

## Legacy File Handling

On startup, any pre-920 plaintext `offline_queue.json` file found in the queue directory is deleted (cannot be decrypted). An `Info`-level log is emitted and the queue starts fresh.

---

# On-Demand Certificate Loading

Implemented in Story #920. The steward's TLS client certificate is now loaded per-handshake rather than cached in memory at connection time.

## Mechanism

- `TransportConfig.CertManager` accepts a `*cert.Manager` at construction
- When a `CertManager` is provided, `tls.Config.GetClientCertificate` is set to a closure that calls `certManager.GetClientCertificate(ctx)` on every TLS handshake
- `cert.Manager.GetClientCertificate` reads the newest `CertificateTypeClient` entry from the certificate store and returns a `tls.Certificate` with both leaf and private key
- If the renewer has rotated the certificate, the next handshake automatically uses the new cert — no restart required

## Benefits

- Certificate rotation is transparent to running stewards
- The raw private key PEM (`clientKeyPEM`) is no longer cached in `TransportClient` memory — the key lives only in the cert store and in the transient `tls.Certificate` returned per handshake

## References

- `pkg/cert/manager.go` — `GetClientCertificate` implementation
- `features/steward/client/client_transport.go` — `createTLSConfig` closure wiring
- `cmd/steward/main.go` — `buildCertManagerAndSecretStore` initialisation
