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
