<!-- SPDX-License-Identifier: AGPL-3.0-only -->
<!-- Copyright 2026 Jordan Ritz -->

# CFGMS Web UI

React + TypeScript + Vite application for the controller-served web UI
(Epic #2344): toolchain scaffold (#2488), login screen (#2495), app shell
(#2496), and the fleet overview (#2497).

The JS/TS toolchain is fully contained in `web/` and does not participate in
any Go build or test gate. CI runs the same scripts (`lint`, `typecheck`,
`test`, `build`, and `npm audit --audit-level=high`) via the dedicated
[`frontend-ci.yml`](../.github/workflows/frontend-ci.yml) lane, which gates
merges to `develop` for PRs that touch `web/**`.

## How the SPA is embedded in the controller binary

The `web/embed.go` file uses `//go:embed all:dist` to embed the entire `dist/`
directory into the controller binary at build time. Go reads `dist/` from the
filesystem at `go build` time — it does not care about git status.

- **Go-only build (no Node):** the committed placeholder `dist/index.html` is
  embedded. The binary serves "Web UI not built" at `/`. This is intentional:
  `go build ./...` must always succeed on a clean checkout without Node.
- **Release build:** run `npm run build` inside `web/` first, then `go build`.
  Vite writes the full SPA into `dist/`, which `go:embed` picks up. The real SPA
  replaces the placeholder — same binary format, no extra tooling at runtime.

`dist/*` is git-ignored except for the committed placeholder (`dist/index.html`).
Real Vite output is never committed — committed compiled JS bypasses source review
(security A6.3) and risks stale-SPA patch-lag bugs. If `dist/` is out of date when
`go build` runs, the binary silently embeds whatever is on disk; a stale `dist/`
with an old SPA version is a deployment error, not a build error. Releases should
validate the `dist/` mtime as part of their packaging pipeline.

## Prerequisites

- Node 26 — pinned in [`.nvmrc`](.nvmrc) and enforced via `package.json`
  `engines`. With nvm: `nvm use` in this directory.
- npm (bundled with Node). Dependencies are pinned by `package-lock.json`;
  always install with `npm ci` for reproducible trees.

## Commands

All commands run from `web/`:

| Command             | What it does                                                        |
|---------------------|---------------------------------------------------------------------|
| `npm ci`            | Clean, reproducible install from `package-lock.json`                |
| `npm run dev`       | Vite dev server with `/api` proxy to a local controller             |
| `npm run build`     | Typecheck (`tsc -b`) + production build to `web/dist/`              |
| `npm run lint`      | ESLint (flat config) — security rules at error severity             |
| `npm run typecheck` | TypeScript strict-mode check, no emit                               |
| `npm run test`      | Vitest run (jsdom + Testing Library)                                |
| `npm run audit`     | `npm audit --audit-level=high` — fails on high/critical advisories  |
| `npm run preview`   | Serve the production build locally                                  |

## Design tokens — single source, never fork

All design tokens come from
[`docs/design/web-ui-design-tokens.css`](../docs/design/web-ui-design-tokens.css)
(founder-owned, consumed **read-only**). The binding is a Vite filesystem
alias, `@design-tokens`, defined in [`vite.config.ts`](vite.config.ts) and
imported exactly once, in
[`src/styles/global.css`](src/styles/global.css):

```css
@import '@design-tokens';
```

Rules:

- **Never copy token values into `web/`.** No hex colours, font stacks, type
  scales, spacing, radii, or shadows that duplicate the token file — they
  would silently drift from the source of truth. Reference tokens with
  `var(--token-name)` only.
- **Never edit the token file from this app.** `docs/design/` is
  founder-owned.
- The token file owns the theme model: light is the default,
  `@media (prefers-color-scheme: dark)` supplies dark, and
  `:root[data-theme="light"|"dark"]` overrides the media query in both
  directions (the app's future theme control stamps `data-theme` on `:root`).
  Nothing in `web/` may redeclare these tokens or interfere with that
  cascade.
- Fonts use the progressive fallback stacks from the token file. Do **not**
  add external font CDN references — the app's CSP (#2494) is self-only.

The dev server explicitly allows serving the token file from outside the app
root (`server.fs.allow` in `vite.config.ts`).

## Security lint gate

`npm run lint` is a frontend SAST gate. The flat config
([`eslint.config.js`](eslint.config.js)) enforces **at error severity**:

- `react/no-danger` and `react/no-danger-with-children`
- A ban on HTML-injection sinks: `dangerouslySetInnerHTML`, `innerHTML`,
  `outerHTML`, `insertAdjacentHTML`, `document.write`/`writeln`
  (`no-restricted-properties` / `no-restricted-syntax`)
- `no-eval`, `no-implied-eval`, `no-new-func` (no runtime code composition)
- The full `eslint-plugin-security` recommended ruleset, elevated from warn
  to error

Lint failures block; do not downgrade these rules or suppress them inline
without review.

## Dev proxy (dev-only)

`npm run dev` proxies `/api` to a locally running controller REST API at
`https://localhost:9080` (the controller's default HTTP API listen address).
The proxy sets `secure: false` because a dev controller boots with an
auto-generated, self-signed CA. **This is a dev-only setting**: it exists
solely inside the Vite dev server and is not part of any production artifact.
In production the controller serves the built app itself, same-origin — no
proxy and no TLS-verification bypass exist there.

## Auth and session architecture (Story #2495, ADR-018)

The app authenticates against the controller's web session endpoints
(#2493) using **cookie transport** — no token ever passes through JS.

- **Session cookie (HttpOnly).** Set by `POST /api/v1/web/login`, attached
  automatically by the browser on every same-origin request
  (`credentials: 'same-origin'`). App code never reads, names, or stores
  it; a source-scan test fails if any non-test source references it.
- **CSRF (double-submit).** [`src/api/client.ts`](src/api/client.ts) is the
  single fetch wrapper for cookie-authenticated calls. On every unsafe
  method (POST/PUT/PATCH/DELETE) it echoes the JS-readable `cfgms_csrf`
  cookie as the `X-CSRF-Token` header. GET/HEAD carry no CSRF header.
- **Login pre-flight.** The login POST itself is gated by a **pre-session**
  token: the client first calls `GET /api/v1/web/csrf` (which sets the
  single-use `cfgms_csrf_pre` cookie) and echoes that value as
  `X-CSRF-Token` on `POST /api/v1/web/login`. Credentials travel only in
  the JSON body.
- **401 handling (ADR-018 §4).** Any 401 on a normal API call means the
  session is gone (idle/absolute expiry or revocation): a central listener
  in [`src/auth/AuthContext.tsx`](src/auth/AuthContext.tsx) drops the app
  to the login screen in its **"session expired"** state. Login and logout
  requests are exempt — a 401 there is invalid credentials / an
  already-dead session, not expiry.
- **Logout.** `POST /api/v1/web/logout` (CSRF-checked) revokes the session
  server-side; the client returns to the fresh signin state.
- **In-memory state only (security A7.2).** The signed-in principal lives
  in React context. Nothing auth-related is ever written to web storage —
  enforced by both a runtime test and a source-scan test. A page reload
  starts signed out; the first authenticated data call re-establishes or
  expires the session naturally.
- **Route guard.** `RequireAuth` renders the login screen
  ([`src/pages/Login.tsx`](src/pages/Login.tsx), canonical design:
  [`docs/design/mockups/login.html`](../docs/design/mockups/login.html))
  for any unauthenticated visit; the authenticated screen it protects is
  the app shell (#2496).

## App shell architecture (Story #2496)

Every authenticated screen mounts inside [`src/shell/AppShell.tsx`](src/shell/AppShell.tsx)
— the persistent chrome fixed by
[`docs/design/mockups/fleet-overview.html`](../docs/design/mockups/fleet-overview.html)
(lines ~102-266): sidebar navigation, a top app bar (tenant-scope switcher,
global search, alert center, user menu), and the responsive drawer/scrim
behavior below 1024px. `App.tsx` renders `AppShell` as the sole child of
`RequireAuth`; later epics mount their views into `AppShell`'s `.content`
area (fleet overview, #2497, is the first occupant; the shell's global
search box doubles as its live filter).

- **Tenant-scope context — a display convenience, not a security boundary
  (security A8.1).** [`src/shell/TenantScopeContext.tsx`](src/shell/TenantScopeContext.tsx)
  holds the currently selected scope and the set of paths observed so far
  (seeded with the principal's own root path; later views call
  `registerObservedPath` as they see more of the tenant tree — there is no
  list-tenants API). `isScopeMatch` mirrors the server's path-separator-aware
  ancestor check in `handlers_stewards.go` (`tenant-a` must never match
  `tenant-abc`). **Server-side tenant scoping on every API call is the only
  real enforcement** — this context only decides what a technician sees in
  the switcher and gives views a shared scope to filter by.
- **Global search / alert center are chrome only.** No search or alerting
  backend exists yet; `GlobalSearch` is a controlled input a later view can
  wire up, and `AlertCenter` renders its designed empty state rather than
  fabricated sample data.
- **User menu.** Shows the signed-in principal from `AuthContext` and hosts
  logout via the #2495 auth actions, plus the design-system theme toggle
  (auto/light/dark via `:root[data-theme]`). Theme choice persists in
  `localStorage` under `cfgms.theme` — a display preference, not auth data,
  so it's explicitly allowlisted in the A7.2 source scan
  ([`src/pages/Login.test.tsx`](src/pages/Login.test.tsx)
  `STORAGE_ALLOWLIST`) rather than exempt from it: any new storage key
  anywhere in `web/` must be added to that allowlist by exact `(file, key)`
  match or the scan fails, and a non-literal key always fails closed.
- **Responsive drawer.** Below 1024px the sidebar becomes an off-canvas
  drawer opened by the hamburger button; a scrim covers the content and
  Escape or a scrim click closes it, matching the mockup harness.

## Registration console (Stories #2934, #2935)

[`src/registration/RegistrationConsolePage.tsx`](src/registration/RegistrationConsolePage.tsx)
renders the steward enrollment console at `/registration`. The page opens on the
**Pending** tab by default. The tab strip follows the same roving-tabindex +
ArrowLeft/Right pattern as `StewardAssetPage.tsx`.

Canonical design:
[`docs/design/mockups/registration-console.html`](../docs/design/mockups/registration-console.html).

No approve, approve-all, approve-by-CIDR, mint, rotate, revoke, or delete control
is present — those are Section 2's follow-on epic.

### Pending tab (Story #2934)

[`src/registration/PendingQueueTab.tsx`](src/registration/PendingQueueTab.tsx)
lists every pending registration in the caller's tenant scope and provides a
functional **Deny** button per row.

- **List endpoint:** `GET /api/v1/registration/pending` — bare-array response (no
  `{data:...}` envelope). Shape-validated by `parsePendingRegistrations` before
  any value reaches the DOM.
- **Deny endpoint:** `POST /api/v1/registration/{id}/deny` — removes the row from
  the list on success; surfaces a row-level error without crashing on failure.
- All steward-supplied values (`pending_id`, `steward_id`, `source_ip`,
  `registered_at`) render as JSX text nodes only (security A9.1).

### Tokens tab (Story #2935)

[`src/registration/TokensTab.tsx`](src/registration/TokensTab.tsx)
is a read-only view of registration tokens for the caller's tenant scope.
`token_prefix` (never the full secret) is the only token identifier rendered.
The list endpoint contract (`handlers_registration_tokens.go`) omits the `token`
field from list responses; `parseToken` enforces this client-side by not reading
that field.

- **List endpoint:** `GET /api/v1/registration/tokens` — `{tokens:[...], total:N}`
  shape (no `{data:...}` envelope). Shape-validated by `parseTokenList`.
- **Fields rendered:** `token_prefix`, `tenant_id`, `group`, `created_at`,
  `expires_at`, computed status (Active / Expired / Revoked).
- `expires_at` / `revoked_at` are optional (`omitempty` in Go) — renders `—`
  when absent, matching the `columns.ts` em-dash convention.
- No mint, rotate, revoke, or delete affordance of any kind.

### IP Trust tab (Story #2936)

Renders a "soon" placeholder — the IP-trust list tab is added by Story #2936.

## Fleet overview (Story #2497)

[`src/fleet/FleetOverview.tsx`](src/fleet/FleetOverview.tsx) renders the
steward table inside the app shell. Canonical design:
[`docs/design/mockups/fleet-overview.html`](../docs/design/mockups/fleet-overview.html).
Story #2498 adds saved views and the row drill-in asset-DNA drawer (both
below).

### Checkbox selection + bulk actions (Story #2939)

Canonical design:
[`docs/design/mockups/fleet-bulk.html`](../docs/design/mockups/fleet-bulk.html)
(founder-approved 2026-07-24).

[`src/fleet/FleetTable.tsx`](src/fleet/FleetTable.tsx) renders a checkbox
column (leftmost) when `selectedIds` is provided. The header checkbox
implements select-all-on-page; it is indeterminate when some but not all
rows on the current page are selected.

[`src/fleet/BulkActionBar.tsx`](src/fleet/BulkActionBar.tsx) is mounted by
`FleetOverview` above the table panel when ≥1 row is selected; it disappears
at zero selection. The bar shows the selected count and an **Edit tags**
action.

**Bulk tag edit** opens an inline tag editor in the bar. Clicking **Add to
selected** or **Remove from selected** issues one `POST` or `DELETE
/api/v1/stewards/{id}/tags` call per selected steward — no server-side batch
endpoint is used, so the per-steward tenant authorization check in
`resolveStewardForTags` runs for every steward individually. Results are
surfaced per-item (e.g. "8 of 10 succeeded, 2 failed: id1, id2"); partial
success is never swallowed into a single pass/fail toast.

**Selection reset**: selection clears when the page, filter, or sort
changes. Stale selections across a different displayed row set would allow
bulk operations on rows the operator is no longer looking at, which is a
correctness hazard. No selection state is preserved across page navigation.

No decommission affordance of any kind exists in these components — that is
Section 2's follow-on epic.

### Data flow

- **Endpoint:** `GET /api/v1/stewards?limit=<n>&offset=<n>` through the
  #2495 client (`apiFetch` — cookie session, central 401 handling). The
  response is the `{ data: { stewards, total, limit, offset } }` envelope
  from Issue #2489: `total` is the post-filter, pre-slice fleet count and
  page order is deterministic (steward-ID sort).
- **Scale posture (48k+ stewards):** only the current server page is ever
  held in memory; the full fleet is never fetched. The pager and the
  toolbar count render the server `total`.
- **Client-side semantics (fixed by the epic):** the live filter (the
  shell's global search box) and column sort operate on the **displayed
  page's rows** — the filter is not a fleet-wide query bar, and the server
  provides only pagination + count (no sort/filter params). The pager's
  "Showing X–Y of Z" always describes the server page window; the toolbar
  count switches to "N of Z match" while a filter or narrowed scope is
  active. The filter haystack covers every mapped DNA value (visible or
  hidden columns) plus the derived health and check-in text.
- **Tenant scope:** rows are narrowed by the #2496 scope context via
  `isScopeMatch` when a scope below the principal's root is selected, and
  tenant paths observed in page data are reported back through
  `registerObservedPath`. Display convenience only — server-side tenant
  scoping on the API call is the only enforcement (security A8.1).
- **Untrusted data:** the response body is shape-validated
  (`parseStewardPage`) before rendering, and every steward-supplied value
  reaches the DOM as a text node only — never markup (security A9.1;
  regression-tested with hostile DNA values).

### DNA-attribute → column mapping

Defined in [`src/fleet/columns.ts`](src/fleet/columns.ts). Default columns:
Name, Company, Last user, IP, Health, Last check-in; opt-in: OS, Agent,
Ring, Model, Serial, MAC. Missing values render an em-dash placeholder.

| Column        | Source (payload field / `dna.attributes` key)                                           |
|---------------|-----------------------------------------------------------------------------------------|
| Name          | `dna.hostname`, fallback `id`                                                           |
| Company       | `tenant` (tenant path; **not emitted by the controller yet** — renders `—` until it is) |
| Last user     | `current_user`                                                                          |
| IP            | `primary_ip`                                                                            |
| Health        | derived from `status` + `last_seen` (see below)                                         |
| Last check-in | `last_seen`, relative (`12s ago` … `3d ago`; `—` = never)                               |
| OS            | `dna.os`, fallback `os_pretty_name`                                                     |
| Agent         | `version`, fallback `steward.version`                                                   |
| Ring          | `deployment_ring`                                                                       |
| Model         | `system_model`, fallback `hardware_model`                                               |
| Serial        | `system_serial_number`, fallback `motherboard_serial`                                   |
| MAC           | `primary_mac`                                                                           |

Column selection persists in `localStorage` under `cfgms.fleet.columns`
(allowlisted in the A7.2 source scan; values read back are validated as
untrusted input).

### Saved views (Story #2498)

[`src/fleet/SavedViews.tsx`](src/fleet/SavedViews.tsx) — the toolbar's
"View:" panel (mockup `pop-views`). A saved view captures the current
**filter text, sort (column + direction), visible column set, and page
size** under a technician-chosen name; applying one restores exactly those
four fields. Tenant scope is session chrome (per the mockup) and is never
captured or restored. Save, apply, rename, and delete all happen in the
panel; the built-in **All stewards** entry restores the defaults.

**Storage format.** Views persist in `localStorage` under the literal key
`cfgms.fleet.views` (allowlisted in the A7.2 source scan), keyed per
principal *inside* the stored record so the storage key itself stays
literal:

```json
{
  "<username>": [
    {
      "name": "acme servers",
      "config": {
        "filter": "acme",
        "sort": { "key": "name", "direction": -1 },
        "columns": ["name", "company", "os", "health", "seen"],
        "pageSize": 100
      }
    }
  ]
}
```

Everything read back is **untrusted input** (security A10.2): the record,
each view, and every config field are shape- and type-validated
(`sort.key` and `columns` against the column registry, `pageSize` against
the fixed page-size set, length caps on names and filter text). A view
that fails validation is dropped; valid siblings survive. At most 50 views
per principal. There is no server-side persistence endpoint in this epic —
sharing/roaming views across browsers is future work.

### Asset-DNA drawer (Story #2498)

[`src/fleet/DnaDrawer.tsx`](src/fleet/DnaDrawer.tsx) — clicking (or
Enter/Space on) a fleet row opens the right-hand drawer (mockup `.det`)
for that steward. Escape or a scrim click closes it, matching the shell
overlay conventions.

**Data flow.** The drawer fetches `GET /api/v1/stewards/{id}/dna` through
the #2495 client and validates the `{ data: DNAInfo }` envelope
(`parseDNAInfo`) as untrusted wire data. A **fixed client-side allowlist**
maps known attribute keys into the mockup's designed groups (Identity,
Network, System, Session & agent); every attribute the steward reports
beyond the allowlist renders under **Other attributes**, so new steward
DNA appears without UI changes. Group headings and row labels come only
from that allowlist, never from data, and steward-supplied keys and values
reach the DOM as text nodes only (security A10.1). A raw-JSON `<details>`
view shows the full parsed payload.

**Redaction tolerance.** The endpoint may 404 (cross-tenant requests 404
rather than 403, no DNA reported yet) and the controller denylists
sensitive attribute keys — the drawer renders its error state with a retry
affordance for failed fetches and simply renders whatever attribute set
comes back, never a blank panel.

Deep-linking the drawer (steward ID in the route) is deferred until the
app has a router; the seam is marked in `FleetOverview.tsx`.

### Health mapping

[`src/fleet/health.ts`](src/fleet/health.ts) folds lifecycle `status` and
`last_seen` staleness into one cell, colored only by semantic state tokens:
active/online + heartbeat ≤ 5 min → **Healthy** (ok); active/online but
older (or never) → **Unreachable** (crit); `degraded` → **Degraded**
(warn); `lost`/`offline` → **Unreachable** (crit); `revoked` → **Revoked**
(crit); `registered`/`dormant`/`archived` → neutral; unknown statuses
render neutral with the raw label as inert text. The 5-minute threshold is
a display heuristic (the payload pins no heartbeat contract), anchored at
fetch time; Go's zero time (`0001-01-01T00:00:00Z`) is treated as "never
seen".

## Testing

Vitest with jsdom and Testing Library. Suites:
[`src/App.test.tsx`](src/App.test.tsx) (guard + full login/logout flow),
[`src/api/client.test.ts`](src/api/client.test.ts) (CSRF injection,
pre-session flow, 401 interception),
[`src/auth/AuthContext.test.tsx`](src/auth/AuthContext.test.tsx) (state
transitions, web-storage assertions), and
[`src/pages/Login.test.tsx`](src/pages/Login.test.tsx) (mockup states,
source scans), `src/shell/*.test.tsx` (tenant-scope prefix matching,
drawer/scrim/Escape behavior, user-menu logout dispatch), and
`src/fleet/*.test.*` (pagination contract, live filter, sort, column
picker + persistence, health/staleness mapping, loading/error/empty
states, hostile-DNA text-node rendering, saved-view round-trip +
untrusted-config validation, DNA drawer fetch/grouping/error states +
hostile attribute keys/values). Setup (jest-dom
matchers, RTL cleanup, in-memory Storage for the A7.2 assertions):
[`src/test/setup.ts`](src/test/setup.ts).

## License

All CFGMS code, including everything under `web/`, is licensed under
**AGPL-3.0-only**. Every source file carries an
`SPDX-License-Identifier: AGPL-3.0-only` header. A commercial embedding
license is available via private agreement — see the repository root
[`LICENSE`](../LICENSE).
