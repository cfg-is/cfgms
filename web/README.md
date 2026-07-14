<!-- SPDX-License-Identifier: AGPL-3.0-only -->
<!-- Copyright 2026 Jordan Ritz -->

# CFGMS Web UI

React + TypeScript + Vite application for the controller-served web UI
(Epic #2344). This is the toolchain scaffold (Story #2488): a buildable,
lintable, testable app with a minimal placeholder screen. The login screen
(#2495) and app shell (#2496) land in later stories.

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
  for any unauthenticated visit; the authenticated placeholder it protects
  is replaced by the app shell in #2496.

## Testing

Vitest with jsdom and Testing Library. Suites:
[`src/App.test.tsx`](src/App.test.tsx) (guard + full login/logout flow),
[`src/api/client.test.ts`](src/api/client.test.ts) (CSRF injection,
pre-session flow, 401 interception),
[`src/auth/AuthContext.test.tsx`](src/auth/AuthContext.test.tsx) (state
transitions, web-storage assertions), and
[`src/pages/Login.test.tsx`](src/pages/Login.test.tsx) (mockup states,
source scans). Setup (jest-dom matchers, RTL cleanup, in-memory Storage
for the A7.2 assertions): [`src/test/setup.ts`](src/test/setup.ts).

## License

All CFGMS code, including everything under `web/`, is licensed under
**AGPL-3.0-only**. Every source file carries an
`SPDX-License-Identifier: AGPL-3.0-only` header. A commercial embedding
license is available via private agreement — see the repository root
[`LICENSE`](../LICENSE).
