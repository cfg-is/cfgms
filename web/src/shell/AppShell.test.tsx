// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz

import { useEffect, useRef } from 'react'
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'
import { render, screen, fireEvent } from '@testing-library/react'
import { MemoryRouter, Route, Routes } from 'react-router'
import { AuthProvider, useAuth } from '../auth/AuthContext.tsx'
import FleetOverview from '../fleet/FleetOverview.tsx'
import AppShell from './AppShell.tsx'

const fetchMock = vi.fn<typeof fetch>()

beforeEach(() => {
  vi.stubGlobal('fetch', fetchMock)
  fetchMock.mockReset()
  // The fleet view (#2497) fetches its steward page on mount; the health tiles
  // (Issue #2729) also fetch on mount. Use mockImplementation to create a fresh
  // Response per call — a shared Response from mockResolvedValue would have its
  // body consumed by the health fetch, breaking the stewards fetch.
  fetchMock.mockImplementation(() =>
    Promise.resolve(
      new Response(
        JSON.stringify({
          data: { stewards: [], total: 0, limit: 50, offset: 0 },
          timestamp: new Date().toISOString(),
        }),
        { status: 200, headers: { 'Content-Type': 'application/json' } },
      ),
    ),
  )
  document.body.className = ''
})

afterEach(() => {
  vi.unstubAllGlobals()
})

/**
 * Renders AppShell as a layout route with FleetOverview at the index route.
 * AppShell provides search state via Outlet context, which FleetOverview
 * reads via useOutletContext.
 */
function renderShell() {
  return render(
    <MemoryRouter initialEntries={['/']}>
      <AuthProvider>
        <Routes>
          <Route path="/" element={<AppShell />}>
            <Route index element={<FleetOverview />} />
          </Route>
        </Routes>
      </AuthProvider>
    </MemoryRouter>,
  )
}

describe('AppShell', () => {
  it('renders sidebar navigation with Fleet, Modules, Config, Workflows, Scripts, Registration, Reports, Audit, and Accounts as links', () => {
    renderShell()
    expect(screen.getByRole('navigation')).toBeInTheDocument()
    expect(screen.getByRole('link', { name: /fleet/i })).toBeInTheDocument()
    expect(screen.getByRole('link', { name: /modules/i })).toBeInTheDocument()
    expect(screen.getByRole('link', { name: /config/i })).toBeInTheDocument()
    expect(screen.getByRole('link', { name: /workflows/i })).toBeInTheDocument()
    expect(screen.getByRole('link', { name: /scripts/i })).toBeInTheDocument()
    expect(screen.getByRole('link', { name: /registration/i })).toBeInTheDocument()
    expect(screen.getByRole('link', { name: /reports/i })).toBeInTheDocument()
    expect(screen.getByRole('link', { name: /audit/i })).toBeInTheDocument()
    expect(screen.getByRole('link', { name: /accounts/i })).toBeInTheDocument()
  })

  it('all nav items are real links; no soon-tagged placeholders remain (Issue #2732, #2934, #2935)', () => {
    renderShell()
    expect(screen.queryAllByText(/soon/i)).toHaveLength(0)
    expect(screen.getByRole('link', { name: /fleet/i })).toBeInTheDocument()
    expect(screen.getByRole('link', { name: /modules/i })).toBeInTheDocument()
    expect(screen.getByRole('link', { name: /config/i })).toBeInTheDocument()
    expect(screen.getByRole('link', { name: /workflows/i })).toBeInTheDocument()
    expect(screen.getByRole('link', { name: /scripts/i })).toBeInTheDocument()
    expect(screen.getByRole('link', { name: /registration/i })).toBeInTheDocument()
    expect(screen.getByRole('link', { name: /reports/i })).toBeInTheDocument()
    expect(screen.getByRole('link', { name: /audit/i })).toBeInTheDocument()
    expect(screen.getByRole('link', { name: /accounts/i })).toBeInTheDocument()
  })

  it('mounts the fleet overview (#2497) in the content area', async () => {
    renderShell()
    expect(
      screen.getByRole('heading', { name: 'Fleet', level: 1 }),
    ).toBeInTheDocument()
    expect(
      await screen.findByText(/no stewards enrolled yet/i),
    ).toBeInTheDocument()
    expect(screen.getByRole('button', { name: /columns/i })).toBeInTheDocument()
  })

  it('renders the tenant switcher, search, alert center, and user menu', () => {
    renderShell()
    expect(screen.getByRole('button', { name: /root/i })).toBeInTheDocument()
    expect(screen.getByRole('searchbox')).toBeInTheDocument()
    expect(screen.getByRole('button', { name: /notifications/i })).toBeInTheDocument()
    expect(screen.getByRole('button', { name: /account menu/i })).toBeInTheDocument()
  })

  it('opens the mobile drawer via the hamburger button and shows a scrim', () => {
    renderShell()
    const hamburger = screen.getByRole('button', { name: /open navigation/i })
    fireEvent.click(hamburger)
    expect(document.body.classList.contains('drawer')).toBe(true)
  })

  it('closes the drawer on Escape', () => {
    renderShell()
    fireEvent.click(screen.getByRole('button', { name: /open navigation/i }))
    expect(document.body.classList.contains('drawer')).toBe(true)
    fireEvent.keyDown(document, { key: 'Escape' })
    expect(document.body.classList.contains('drawer')).toBe(false)
  })

  it('closes the drawer when the scrim is clicked', () => {
    renderShell()
    fireEvent.click(screen.getByRole('button', { name: /open navigation/i }))
    fireEvent.click(screen.getByTestId('shell-scrim'))
    expect(document.body.classList.contains('drawer')).toBe(false)
  })

  // ── Tenant-scoped rootPath propagation (Issue #2919) ──────────────────────
  // AppShell wires TenantScopeProvider rootPath={principal?.tenantId ?? ''}.
  // For a tenant-scoped account this is the wiring that confines the UI session
  // to its own subtree: a user scoped to 'msp-a' must get rootPath='msp-a' and
  // must NOT be able to browse a sibling like 'msp-b'.
  //
  // Production mounts AppShell only once signed in (RequireAuth), so principal
  // is already populated when TenantScopeProvider initialises its scope from
  // rootPath. This harness mirrors that ordering: it logs in on mount and only
  // mounts AppShell once principal is set.
  const MOCK_PASSKEY_BEGIN_OPTIONS = {
    publicKey: {
      challenge: 'Y2hhbGxlbmdlLWJ5dGVz',
      timeout: 60000,
      rpId: 'localhost',
      allowCredentials: [],
      userVerification: 'required' as const,
    },
  }

  function makePublicKeyCredential(): PublicKeyCredential {
    const toArrayBuffer = (s: string) => new TextEncoder().encode(s).buffer as ArrayBuffer
    return {
      id: 'cred-id',
      type: 'public-key',
      rawId: toArrayBuffer('cred-id'),
      response: {
        clientDataJSON: toArrayBuffer('{"type":"webauthn.get"}'),
        authenticatorData: toArrayBuffer('auth-data'),
        signature: toArrayBuffer('sig'),
        userHandle: null,
      } as AuthenticatorAssertionResponse,
      getClientExtensionResults: () => ({} as AuthenticationExtensionsClientOutputs),
      authenticatorAttachment: null,
      toJSON: () => ({}),
    } as unknown as PublicKeyCredential
  }

  function loginScopeMock(tenantId: string) {
    vi.stubGlobal('navigator', {
      credentials: { get: vi.fn().mockResolvedValue(makePublicKeyCredential()) },
    })
    fetchMock.mockImplementation((input) => {
      const url = String(input)
      if (url.endsWith('/api/v1/web/csrf')) {
        document.cookie = 'cfgms_csrf_pre=pre-tok-shell; path=/'
        return Promise.resolve(new Response(null, { status: 204 }))
      }
      if (url.endsWith('/api/v1/web/passkey/login/begin')) {
        return Promise.resolve(new Response(JSON.stringify(MOCK_PASSKEY_BEGIN_OPTIONS), {
          status: 200, headers: { 'Content-Type': 'application/json' },
        }))
      }
      if (url.endsWith('/api/v1/web/passkey/login/finish')) {
        return Promise.resolve(
          new Response(
            JSON.stringify({
              data: {
                ok: true,
                username: 'admin@msp-a',
                tenant_id: tenantId,
                root_scope: tenantId === '',
              },
            }),
            { status: 200, headers: { 'Content-Type': 'application/json' } },
          ),
        )
      }
      // fleet stewards + health tiles
      return Promise.resolve(
        new Response(
          JSON.stringify({
            data: { stewards: [], total: 0, limit: 50, offset: 0 },
            timestamp: new Date().toISOString(),
          }),
          { status: 200, headers: { 'Content-Type': 'application/json' } },
        ),
      )
    })
  }

  /**
   * Logs the given user in on mount, then mounts AppShell only after the
   * principal is populated — mirroring RequireAuth gating so AppShell's first
   * render already has principal.tenantId (which TenantScopeProvider reads once
   * to seed its scope state).
   */
  function ScopedShellHarness({ username }: { username: string }) {
    const { principal, login } = useAuth()
    const started = useRef(false)
    useEffect(() => {
      if (started.current) return
      started.current = true
      void login(username)
    }, [login, username])
    if (principal === null) return <span>signing in…</span>
    return (
      <Routes>
        <Route path="/" element={<AppShell />}>
          <Route index element={<FleetOverview />} />
        </Route>
      </Routes>
    )
  }

  function renderScopedShell(username: string) {
    return render(
      <MemoryRouter initialEntries={['/']}>
        <AuthProvider>
          <ScopedShellHarness username={username} />
        </AuthProvider>
      </MemoryRouter>,
    )
  }

  it("propagates a signed-in account's tenantId to the tenant scope rootPath", async () => {
    loginScopeMock('msp-a')
    renderScopedShell('admin@msp-a')

    // The scope switcher reflects rootPath: a tenant-scoped account shows its
    // own path ('msp-a'), not the root 'root' label.
    const scopeButton = await screen.findByRole('button', { name: /msp-a/i })
    expect(scopeButton).toBeInTheDocument()
    expect(scopeButton).not.toHaveAccessibleName(/root/i)
  })

  it('confines a tenant-scoped session to its own subtree (cannot browse a sibling tenant)', async () => {
    loginScopeMock('msp-a')
    renderScopedShell('admin@msp-a')

    // Open the scope switcher; the only selectable scope is the account's own
    // rootPath. A sibling tenant ('msp-b') is not reachable from this session.
    const scopeButton = await screen.findByRole('button', { name: /msp-a/i })
    fireEvent.click(scopeButton)
    const menu = screen.getByRole('menu')
    expect(menu).toHaveTextContent('msp-a')
    expect(menu).not.toHaveTextContent('msp-b')
  })

  it('a root-scoped account (empty tenantId) keeps rootPath empty and shows the root scope', async () => {
    loginScopeMock('')
    renderScopedShell('root-admin')

    // Empty tenantId → rootPath '' → the switcher renders the 'root' label.
    const scopeButton = await screen.findByRole('button', { name: /root/i })
    expect(scopeButton).toHaveAccessibleName(/root/i)
  })
})
