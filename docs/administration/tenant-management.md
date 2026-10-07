# Tenant Management

Inspect tenants from the `cfg` CLI. `cfg tenant create` is covered in the command's `--help`; this page covers reading tenants.

Client resolution is the same for every `cfg tenant` verb: an active session or admin bundle, `--api-url` (or `CFGMS_API_URL`), and `--tls-insecure` for development only.

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

Both verbs accept `--json`:

```bash
cfg tenant list --json   # the response array exactly as received
cfg tenant get <id> --json   # the tenant object exactly as received
```

## Scope

The controller scopes results to the caller's tenant exactly as `GET /api/v1/tenants` and `GET /api/v1/tenants/{id}` do: the CLI shows the same tenants the API returns for the caller, no more. A path may start below the top-level tenant when its ancestors are outside the caller's scope.
