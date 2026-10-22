# Tenant Management

Inspect tenants from the `cfg` CLI. `cfg tenant create` is covered in the command's `--help`; this page covers reading tenants and tenant crossings.

Client resolution is the same for every `cfg tenant` verb: an active session or admin bundle, `--url` (or `CFGMS_API_URL`), and `--tls-insecure` for development only.

## List tenants

```bash
cfg tenant list
```

Prints one row per tenant:

```text
ID      PARENT  PATH            STATUS
root    -       root            active
msp-a   root    root/msp-a      active
client  msp-a   root/msp-a/client  active
```

`PATH` is the tenant's ancestry from the top-level tenant, built from the parent links of the tenants returned. When no tenants are visible the command prints `no tenants` and exits 0.

## Show one tenant

```bash
cfg tenant get <id>
```

The tenant ID is a positional argument. A tenant that does not exist, or that is outside the caller's scope, makes the command exit non-zero with the server's message and print no tenant fields.

## JSON output

Both list/get verbs accept `--json`:

```bash
cfg tenant list --json   # the response array exactly as received
cfg tenant get <id> --json   # the tenant object exactly as received
```

## Scope

The controller scopes results to the caller's tenant exactly as `GET /api/v1/tenants` and `GET /api/v1/tenants/{id}` do: the CLI shows the same tenants the API returns for the caller, no more. A path may start below the top-level tenant when its ancestors are outside the caller's scope.

## Tenant crossings

A root-scoped operator cannot reach an MSP tenant by default. A *crossing* opens that boundary for a limited time, either by the MSP's own consent (a grant) or by a justified, audited emergency elevation (break-glass). Five verbs manage them; each accepts `--json`, which prints the response exactly as received.

| Verb | Who may use it | What it does |
|------|----------------|--------------|
| `cfg tenant break-glass <tenant> --reason <reason> --justification "..."` | Root-scoped callers only | Starts a break-glass session into the tenant; the tenant is notified |
| `cfg tenant approve-break-glass <tenant> <crossing-id>` | A root-scoped operator other than the invoker | Approves a break-glass session that is pending a second approver |
| `cfg tenant grant <tenant> --duration <d>` | MSP administrator of the tenant (root-scoped callers are refused; they use break-glass) | Authorises root-scoped operators to cross into the tenant; a grant names no person |
| `cfg tenant crossings <tenant>` | A caller authorised for the tenant | Lists the active grants and break-glass sessions |
| `cfg tenant end-crossing <tenant> <crossing-id>` | A grant is ended by the tenant's MSP administrator; a break-glass session by the root principal that invoked it or the tenant's administrator | Ends an active crossing early |

```bash
cfg tenant break-glass client-1 --reason account_recovery --justification "MSP admins locked out, ticket INC-1234"
cfg tenant approve-break-glass client-1 <crossing-id>
cfg tenant grant client-1 --duration 90m
cfg tenant crossings client-1
cfg tenant end-crossing client-1 <crossing-id>
```

- **Break-glass window.** The controller fixes the window at 30 minutes; there is no duration flag. `--reason` is required and takes one of `account_recovery`, `security_incident`, `legal_request` or `billing_dispute`; a missing or unknown reason, or a justification outside 10-1000 characters, is refused before any request is sent. Both travel in the JSON body. A successful call prints the crossing id and `expires_at`. When the controller requires a second approver the response is `pending` and the command says so: another root-scoped operator must run `cfg tenant approve-break-glass`, which restarts the window at approval time. Break-glass is also the account-recovery path when the console is unusable; the loud notifications are sent by the controller for every caller, so the CLI is no bypass.
- **Grant duration.** `--duration` is a Go duration of whole minutes from `1m` to `24h` (`30m`, `90m`, `2h`). Values such as `30s`, `90m30s` or `25h` are refused before any request is sent.
- **Step-up.** `break-glass`, `approve-break-glass`, `grant` and `end-crossing` require step-up verification (ADR-021). When the controller answers `401` with `WWW-Authenticate: CFGMS-StepUp`, the CLI runs its presence relay and replays the request, including the request body.
- **Confirmation.** `break-glass`, `approve-break-glass`, `grant` and `end-crossing` print what they will do and prompt `Proceed? [y/N]`. `--yes` (`-y`) skips the prompt. With no terminal and no `--yes` they refuse, send no request and exit non-zero. `crossings` is read-only and never prompts.
- **Listing.** `crossings` prints active and pending records with their id, kind, reason category, status and expiry, or `no active crossings` and exits 0 when there are none. `--json` prints every record the server returned, including expired and ended ones.
- **Errors.** The server's message is printed and the command exits non-zero: `401` (session expired, or step-up not completed), `403` (for example `NOT_ROOT_SCOPED`, `ROOT_SCOPED_CANNOT_GRANT`), `404` (tenant or crossing not found), `400` (`INVALID_REASON_CATEGORY`, `INVALID_DURATION`, `JUSTIFICATION_REQUIRED`), `SAME_APPROVER` and `NOT_PENDING` when approving. When access to a tenant is refused because no crossing is active, the message suggests `cfg tenant break-glass`.

## Git config source credential

A tenant's git config source authenticates with a token that is bound to one repository URL. Store the credential with `cfg tenant config-source set-credential`, then point the tenant at it. The order matters:

1. Store the credential: `printf '%s\n' "$TOKEN" | cfg tenant config-source set-credential <tenant-id> --url https://git.example.com/org/configs.git`. The command prints the `credential_ref` (`<tenant-id>/config-source-git`).
2. Set the tenant metadata `config_source_credential` to that `credential_ref` and `config_source_url` to the same repository URL (together with `config_source_type: git`).

| Command | What it does |
|---------|--------------|
| `cfg tenant config-source set-credential <tenant-id> --url <repository URL> [--json]` | Stores the token with its repository binding; a second call replaces both |

- **Token.** No flag or argument accepts the token. It is read as one line from standard input, or typed at a no-echo prompt when standard input is a terminal. It never appears in process arguments, and the command never prints it.
- **Binding.** The secret records the normalized repository URL (scheme and host lowercased, default port, trailing `/` and `.git` removed). The URL must pass the same checks as `config_source_url`: HTTPS, no embedded credentials, no private or loopback address.

**Address checks at admission.** When a config-source or mount-point URL is admitted, a host name is resolved once and every returned address is checked; one blocked address rejects the URL even if others are public. A resolver error, timeout, cancelled request or empty answer also rejects it. Parsing stored tenant metadata performs no lookups. Hosts written as non-canonical numeric IPs (`2130706433`, `0177.0.0.1`, `0x7f.1`, `127.000.000.001`) are rejected without resolution. Blocked ranges: loopback, link-local (including the cloud metadata address), RFC 1918 and IPv6 unique-local, unspecified and `0.0.0.0/8`, shared address space (`100.64.0.0/10`, which also refuses overlay-network git hosts), `192.0.0.0/24`, `198.18.0.0/15`, multicast and reserved (`224.0.0.0/4`, `240.0.0.0/4`, including broadcast), IPv6 multicast (`ff00::/8`), site-local `fec0::/10`, and IPv6 forms that carry an IPv4 address (IPv4-mapped, NAT64 `64:ff9b::/96`, 6to4 `2002::/16`, IPv4-compatible `::/96`), which are checked as the embedded IPv4 address.

**Address checks at connect time.** Admission cannot stop a DNS answer that changes afterwards, an HTTP redirect, or a proxy hop, so every git connection made over HTTPS is re-checked as it is opened: the host is resolved again, every address is checked against the same blocked ranges, and the connection is made to the checked address rather than the host name. The check covers the connection test, repository clones, and each redirect hop; environment proxy settings are ignored. It fails closed: a resolver error, an empty answer or any blocked address refuses the connection, and the error names the host but never an address. The HTTPS transport is process-wide, so gitsync bindings are checked the same way. A gitsync binding to a git server on a private, loopback or shared (`100.64.0.0/10`) address is therefore refused; no operator allowance exists for this today.
- **Permissions.** Needs `tenant:manage`. A root-scoped operator needs an active crossing into the tenant. An unknown or out-of-scope tenant is reported as not found.
- **Audit.** Each call emits `config_source.credential.set` naming the tenant, the actor and the bound URL, never the token.

## M365 connection

A client tenant is connected to Microsoft 365 with `cfg tenant m365`. **A connection exists only on an existing client tenant**, a tenant whose parent is an MSP tenant (a direct child of the root tenant). The root tenant, an MSP tenant, a tenant that does not exist, a tenant below a client tenant and a client tenant that is not a child of the MSP named in the request are all refused before anything is written. No command creates a tenant, an account or a consent record. Setup is described in the [M365 Integration Guide](../M365_INTEGRATION_GUIDE.md#part-2-connecting-client-tenants).

| Command | What it does |
|---------|--------------|
| `cfg tenant m365 set <client-tenant> --app-id <id> --m365-tenant <directory-id> --client-secret-stdin [--replace] [--yes]` | Stores a direct-mode connection on one client tenant |
| `cfg tenant m365 get <client-tenant>` | Shows the mode, app ID, M365 tenant, partner tenant, GDAP roles and `client secret: set`; never the secret |
| `cfg tenant m365 delete <client-tenant> [--yes]` | Removes the stored connection and token |
| `cfg tenant m365 gdap-customers <msp-tenant> --partner-tenant <id> --app-id <id> --client-secret-stdin` | Lists the MSP's active GDAP customers with `CUSTOMER TENANT`, `NAME`, `STATUS`, `EXPIRES` and `LINKED TO` |
| `cfg tenant m365 gdap-link <msp-tenant> --partner-tenant <id> --app-id <id> --client-secret-stdin --link <customer>=<client-tenant> [--link ...] [--gdap-role <role> ...] [--replace] [--yes]` | Links many GDAP customers to existing client tenants in one all-or-nothing request |

- **Secrets.** No flag accepts a secret value. `--client-secret-stdin` reads the secret as one line from standard input. The secret is never echoed, logged or written to an audit entry.
- **Confirmation.** `delete`, `set --replace` and `gdap-link` print what they will change and prompt `Proceed? [y/N]`. `--yes` (`-y`) skips the prompt. With no terminal and no `--yes` they refuse, send no request and exit non-zero. A secret piped on stdin leaves no terminal, so a confirm-gated command that reads the secret from stdin needs `--yes`.
- **Output.** `--json` prints the response data as received.
- **Permissions.** `set`, `delete`, `gdap-customers` and `gdap-link` need `tenant:manage`; `get` needs `tenant:read`. A root-scoped operator needs an active crossing into the MSP.
- **Audit.** Each write emits one event per affected client tenant: `m365.connection.set`, `m365.connection.delete` or `m365.gdap.link`.
