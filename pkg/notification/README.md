# pkg/notification

Central, pluggable provider for outbound notifications. Business logic imports
`pkg/notification/interfaces` only; the binary that wires the controller
blank-imports the provider package(s) it wants.

## Interface

- `Message` — `To []string`, `Subject`, plain-text `Body`.
- `DeliveryResult` — one `RecipientResult` per recipient (`Address`, `Accepted`,
  sanitized `Reason`). `Accepted()` / `Failed()` are convenience views.
- `Notifier` — `Send(ctx, Message) (*DeliveryResult, error)` and `Name()`.
  A partial failure returns the result with a nil error. An error with a nil
  result means nothing was delivered (validation failure or transport failure);
  its text never contains recipients or credentials.
- `NotifierProvider` — `CreateNotifier(config map[string]interface{})`.
- Registry: `RegisterNotifierProvider`, `GetNotifierProvider`,
  `CreateNotifierFromConfig`, `GetRegisteredProviderNames`.

## Providers

### `smtp`

TLS is mandatory. `security` is `starttls` (default, port 587) or `implicit_tls`
(port 465). There is no plaintext mode and no way to skip certificate
verification; any config key outside the list below fails provider creation.
`ServerName` is the configured host.

| Key | Meaning |
|-----|---------|
| `host` | required |
| `port` | optional, defaults from `security` |
| `security` | `starttls` \| `implicit_tls` |
| `from` | required sender address |
| `username`, `password` | already-resolved values; the provider never reads files or env |
| `timeout` | duration string bounding dial plus conversation (default `30s`) |
| `root_ca_pem` | extra trusted roots, PEM contents (not a path) |

Bodies are plain text (quoted-printable). Addresses are validated with
`net/mail`; CR or LF in a subject or address is rejected before any network
activity. Every recipient is attempted and reported individually.

## Adding a provider

1. Create `pkg/notification/providers/<name>/` implementing `NotifierProvider`.
2. Call `interfaces.RegisterNotifierProvider` from `init()`.
3. Run `contracttest.Run` from the provider's tests against a real backend.
4. Reject any config key that would weaken transport security.
