# Billing Visibility

What the root operator and an MSP can see about billing, and the `cfg` commands that read it.

## What each role sees

| Role | Report | Client identity |
|------|--------|-----------------|
| Root operator | Every MSP: tech and endpoint counts, endpoint metrics, and each client's sizes | Opaque label only. No client name, no client tenant ID |
| MSP | Its own subtree | Client names and IDs |

Counts exclude stewards in a terminal state (deregistered, archived, dormant, revoked) and disabled accounts. Both reports come from the same aggregation, so their numbers cannot disagree.

**Standing disclosure.** Root sees these figures about each MSP at all times. A read of the root report is not individually audited, and it needs no grant or break-glass crossing. It does not reveal who an MSP's clients are.

## `cfg billing report`

Root cross-MSP report from `GET /api/v1/billing/report`.

```bash
cfg billing report
cfg billing report --json
```

Text output is one block per MSP (techs, endpoints, clients, online/offline/pending, platforms, versions, the MSP's own counts), followed by its clients as `LABEL  ENDPOINTS  TECHS`. With no MSPs it prints `no tenants` and exits 0. A caller that is not the root operator gets the server's `403` message, a non-zero exit and no report lines. The command takes no label argument.

## `cfg tenant billing <tenant-id>`

MSP report from `GET /api/v1/tenants/{id}/billing-report`, with named clients.

```bash
cfg tenant billing msp-a
cfg tenant billing msp-a --json
```

A tenant outside the caller's scope, or an unknown one, gives the server's `404` message and a non-zero exit with no report lines.

`--json` on both commands prints the response body exactly as received; the CLI does no redaction because the server already redacts.

## Boundary rows in `cfg tenant list`

A root-scoped caller sees an MSP it holds no crossing for as a boundary row, marked `[not accessible: N techs, N devices, N clients]`. The row names no client and grants nothing: it exists so break-glass has a target.

## REST endpoints

- `GET /api/v1/billing/report` (`tenant:billing-read`, root operator only)
- `GET /api/v1/tenants/{id}/billing-report` (`tenant:billing-read`)
- `GET /api/v1/tenants` (boundary rows)

See [REST API](../api/rest-api.md) for the response schemas.
