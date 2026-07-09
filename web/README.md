<!-- SPDX-License-Identifier: AGPL-3.0-only -->
<!-- Copyright 2026 Jordan Ritz -->

# CFGMS Web UI

React + TypeScript + Vite application for the controller-served web UI
(Epic #2344). This is the toolchain scaffold (Story #2488): a buildable,
lintable, testable app with a minimal placeholder screen. The login screen
(#2495) and app shell (#2496) land in later stories.

The JS/TS toolchain is fully contained in `web/` and does not participate in
any Go build or test gate.

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

## Testing

Vitest with jsdom and Testing Library. Smoke test:
[`src/App.test.tsx`](src/App.test.tsx). Setup (jest-dom matchers):
[`src/test/setup.ts`](src/test/setup.ts).

## License

All CFGMS code, including everything under `web/`, is licensed under
**AGPL-3.0-only**. Every source file carries an
`SPDX-License-Identifier: AGPL-3.0-only` header. A commercial embedding
license is available via private agreement — see the repository root
[`LICENSE`](../LICENSE).
