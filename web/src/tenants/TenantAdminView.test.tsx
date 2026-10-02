// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz

/*
 * TenantAdminView test suite (Issue #3131).
 * Tests: loading skeleton, error state, empty state, boundary state (ADR-025),
 * tree rendering with parent/child indentation, suspension provenance display
 * (ADR-027 Decision 2), delete pipeline (ADR-027 Decision 3), create/edit forms,
 * and all action buttons.
 *
 * The ADR-025 boundary state and the ADR-027 dual-control lock are security
 * behaviours, so they are exercised through the real AuthProvider and the real
 * passkey login ceremony (WebAuthn's browser API is stubbed the same way
 * AuthContext.test.tsx does — a browser API, not a CFGMS component).
 */
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'
import { act, cleanup, fireEvent, render, screen, waitFor } from '@testing-library/react'
import { MemoryRouter } from 'react-router'
import { AuthProvider, useAuth } from '../auth/AuthContext.tsx'
import TenantAdminView from './TenantAdminView.tsx'

const fetchMock = vi.fn<typeof fetch>()

beforeEach(() => {
  vi.stubGlobal('fetch', fetchMock)
  fetchMock.mockReset()
})

afterEach(() => {
  vi.unstubAllGlobals()
  cleanup()
})

function jsonResponse(status: number, body: unknown) {
  return new Response(JSON.stringify(body), {
    status,
    headers: { 'Content-Type': 'application/json' },
  })
}

// ── Passkey sign-in harness (real AuthProvider, stubbed WebAuthn browser API) ──

const passkeyBeginOptions = {
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
    id: 'cred-id-b64u',
    type: 'public-key',
    rawId: toArrayBuffer('cred-id-b64u'),
    response: {
      clientDataJSON: toArrayBuffer('{"type":"webauthn.get"}'),
      authenticatorData: toArrayBuffer('authenticator-data'),
      signature: toArrayBuffer('signature'),
      userHandle: null,
    } as AuthenticatorAssertionResponse,
    getClientExtensionResults: () => ({}) as AuthenticationExtensionsClientOutputs,
    authenticatorAttachment: null,
    toJSON: () => ({}),
  } as unknown as PublicKeyCredential
}

/** Exposes the real useAuth().login() so a test can establish a session. */
function SignInHarness({ username }: { username: string }) {
  const { login, status } = useAuth()
  return (
    <div>
      <output data-testid="auth-status">{status}</output>
      <button type="button" data-testid="do-login" onClick={() => void login(username)}>
        sign in
      </button>
    </div>
  )
}

/**
 * Routes the passkey ceremony endpoints so login() succeeds with the given
 * session shape; every other URL falls through to `rest`.
 */
function routeWithLogin(
  session: { username: string; tenant_id: string; root_scope: boolean },
  rest: (url: string, init?: RequestInit) => Response,
) {
  vi.stubGlobal('navigator', {
    credentials: { get: vi.fn().mockResolvedValue(makePublicKeyCredential()) },
  })
  fetchMock.mockImplementation((input, init) => {
    const url = String(input)
    if (url.endsWith('/api/v1/web/csrf')) {
      document.cookie = 'cfgms_csrf_pre=pre-tok; path=/'
      return Promise.resolve(new Response(null, { status: 204 }))
    }
    if (url.endsWith('/api/v1/web/passkey/login/begin')) {
      return Promise.resolve(jsonResponse(200, passkeyBeginOptions))
    }
    if (url.endsWith('/api/v1/web/passkey/login/finish')) {
      return Promise.resolve(jsonResponse(200, { data: { ok: true, ...session } }))
    }
    return Promise.resolve(rest(url, init as RequestInit | undefined))
  })
}

async function signIn() {
  act(() => screen.getByTestId('do-login').click())
  await waitFor(() => expect(screen.getByTestId('auth-status')).toHaveTextContent('signedIn'))
}

function makeTenant(overrides: Partial<Record<string, unknown>> = {}) {
  return {
    id: 'msp-a',
    name: 'msp-a',
    description: '',
    parent_id: '',
    status: 'active',
    directly_suspended: false,
    cascade_suspended_from: null,
    created_at: '2026-01-01T00:00:00Z',
    updated_at: '2026-01-01T00:00:00Z',
    ...overrides,
  }
}

function makeTenantsResponse(tenants: object[], status = 200) {
  return new Response(
    JSON.stringify({ data: tenants }),
    { status, headers: { 'Content-Type': 'application/json' } },
  )
}

function renderView() {
  return render(
    <MemoryRouter>
      <AuthProvider>
        <TenantAdminView />
      </AuthProvider>
    </MemoryRouter>,
  )
}

// ── Heading and structure ─────────────────────────────────────────────────────

describe('TenantAdminView — heading and page structure', () => {
  it('shows the Tenants heading', async () => {
    fetchMock.mockReturnValue(new Promise(() => {}))
    renderView()
    expect(screen.getByRole('heading', { name: /tenants/i, level: 1 })).toBeInTheDocument()
  })

  it('shows New tenant button when not loading', async () => {
    fetchMock.mockResolvedValue(makeTenantsResponse([makeTenant()]))
    renderView()
    await waitFor(() => screen.getByTestId('toggle-create-btn'))
    expect(screen.getByTestId('toggle-create-btn')).toHaveTextContent('+ New tenant')
  })
})

// ── Loading state ─────────────────────────────────────────────────────────────

describe('TenantAdminView — loading state', () => {
  it('shows loading skeleton while fetching', () => {
    fetchMock.mockReturnValue(new Promise(() => {}))
    renderView()
    expect(screen.getByTestId('tenants-loading')).toBeInTheDocument()
  })

  it('hides loading skeleton after fetch completes', async () => {
    fetchMock.mockResolvedValue(makeTenantsResponse([makeTenant()]))
    renderView()
    await waitFor(() => expect(screen.queryByTestId('tenants-loading')).not.toBeInTheDocument())
  })
})

// ── Error state ────────────────────────────────────────────────────────────────

describe('TenantAdminView — error state', () => {
  it('shows error notice on fetch failure', async () => {
    fetchMock.mockRejectedValue(new Error('network error'))
    renderView()
    await waitFor(() => screen.getByTestId('tenants-error'))
    expect(screen.getByTestId('tenants-error')).toBeInTheDocument()
  })

  it('shows error notice on non-ok response', async () => {
    fetchMock.mockResolvedValue(makeTenantsResponse([], 500))
    renderView()
    await waitFor(() => screen.getByTestId('tenants-error'))
  })

  it('retry button re-fetches', async () => {
    fetchMock
      .mockResolvedValueOnce(makeTenantsResponse([], 500))
      .mockResolvedValue(makeTenantsResponse([makeTenant()]))
    renderView()
    await waitFor(() => screen.getByTestId('tenants-retry-btn'))
    fireEvent.click(screen.getByTestId('tenants-retry-btn'))
    await waitFor(() => screen.getByTestId('tenants-table'))
  })
})

// ── Empty state ────────────────────────────────────────────────────────────────

describe('TenantAdminView — empty state', () => {
  it('shows empty notice when no tenants returned', async () => {
    fetchMock.mockResolvedValue(makeTenantsResponse([]))
    renderView()
    await waitFor(() => screen.getByTestId('tenants-empty'))
    expect(screen.getByTestId('tenants-empty')).toBeInTheDocument()
  })
})

// ── Boundary state (ADR-025) ──────────────────────────────────────────────────

describe('TenantAdminView — boundary state (ADR-025)', () => {
  function renderWithLogin(
    session: { username: string; tenant_id: string; root_scope: boolean },
    tenants: object[],
  ) {
    routeWithLogin(session, (url) => {
      if (url.endsWith('/api/v1/tenants')) return makeTenantsResponse(tenants)
      return jsonResponse(404, { error: { message: 'no pending deletion' } })
    })
    return render(
      <MemoryRouter initialEntries={['/tenants']}>
        <AuthProvider>
          <SignInHarness username={session.username} />
          <TenantAdminView />
        </AuthProvider>
      </MemoryRouter>,
    )
  }

  it('shows the boundary empty state for a root-scoped session with no accessible tenants', async () => {
    // ADR-025: the API silently omits every tenant the root-scoped caller holds no
    // grant/break-glass crossing for, so a list carrying no child tenants means the
    // boundary is in force. The view must say so explicitly rather than render an
    // empty-looking tree.
    renderWithLogin({ username: 'root-admin', tenant_id: '', root_scope: true }, [
      makeTenant({ id: 'root', name: 'root', parent_id: '' }),
    ])

    // Before sign-in the session is not known to be root-scoped: the tree renders.
    await waitFor(() => screen.getByTestId('tenants-table'))
    expect(screen.queryByTestId('boundary-empty-state')).not.toBeInTheDocument()

    await signIn()

    const boundary = await screen.findByTestId('boundary-empty-state')
    expect(boundary).toHaveTextContent('No default access into MSP tenants')
    expect(boundary).toHaveTextContent('ADR-025')
    // The tree, the tenant count and the create action are all withheld.
    expect(screen.queryByTestId('tenants-table')).not.toBeInTheDocument()
    expect(screen.queryByTestId('tenant-count')).not.toBeInTheDocument()
    expect(screen.queryByTestId('toggle-create-btn')).not.toBeInTheDocument()
  })

  it('shows the boundary empty state for a root-scoped session with an empty tenant list', async () => {
    renderWithLogin({ username: 'root-admin', tenant_id: '', root_scope: true }, [])
    await waitFor(() => screen.getByTestId('tenants-empty'))
    await signIn()
    expect(await screen.findByTestId('boundary-empty-state')).toBeInTheDocument()
    // The generic "no tenants yet" notice must not stand in for the boundary notice.
    expect(screen.queryByTestId('tenants-empty')).not.toBeInTheDocument()
  })

  it('renders the tree, not the boundary state, once a crossing exposes MSP children', async () => {
    renderWithLogin({ username: 'root-admin', tenant_id: '', root_scope: true }, [
      makeTenant({ id: 'root', name: 'root', parent_id: '' }),
      makeTenant({ id: 'msp-a', name: 'msp-a', parent_id: 'root' }),
    ])
    await signIn()
    await waitFor(() => screen.getByTestId('tenants-table'))
    expect(screen.queryByTestId('boundary-empty-state')).not.toBeInTheDocument()
    expect(screen.getAllByTestId('tenant-row')).toHaveLength(2)
  })

  it('does not apply the boundary state to a tenant-scoped session', async () => {
    // The boundary is a root↔MSP control (ADR-025 A2.1). An MSP admin whose own
    // tenant has no children must still get their tree, not a lock notice.
    renderWithLogin({ username: 'msp-a-owner', tenant_id: 'msp-a', root_scope: false }, [
      makeTenant({ id: 'msp-a', name: 'msp-a', parent_id: '' }),
    ])
    await signIn()
    await waitFor(() => screen.getByTestId('tenants-table'))
    expect(screen.queryByTestId('boundary-empty-state')).not.toBeInTheDocument()
  })
})

// ── Tree rendering ─────────────────────────────────────────────────────────────

describe('TenantAdminView — tree rendering', () => {
  it('renders tenant rows for all returned tenants', async () => {
    fetchMock.mockResolvedValue(
      makeTenantsResponse([
        makeTenant({ id: 'root', name: 'root', parent_id: '' }),
        makeTenant({ id: 'msp-a', name: 'msp-a', parent_id: 'root' }),
        makeTenant({ id: 'client-1', name: 'client-1', parent_id: 'msp-a' }),
      ]),
    )
    renderView()
    await waitFor(() => screen.getByTestId('tenants-table'))
    const rows = screen.getAllByTestId('tenant-row')
    expect(rows).toHaveLength(3)
  })

  it('shows tenant names in tree rows', async () => {
    fetchMock.mockResolvedValue(
      makeTenantsResponse([
        makeTenant({ id: 'msp-a', name: 'msp-a', parent_id: '' }),
      ]),
    )
    renderView()
    await waitFor(() => screen.getByTestId('tenants-table'))
    expect(screen.getByTestId('tenant-name')).toHaveTextContent('msp-a')
  })

  it('shows tenant count', async () => {
    fetchMock.mockResolvedValue(
      makeTenantsResponse([
        makeTenant({ id: 'a' }),
        makeTenant({ id: 'b' }),
      ]),
    )
    renderView()
    await waitFor(() => screen.getByTestId('tenant-count'))
    expect(screen.getByTestId('tenant-count')).toHaveTextContent('2 tenants')
  })

  it('shows singular "1 tenant" text', async () => {
    fetchMock.mockResolvedValue(makeTenantsResponse([makeTenant()]))
    renderView()
    await waitFor(() => screen.getByTestId('tenant-count'))
    expect(screen.getByTestId('tenant-count')).toHaveTextContent('1 tenant')
  })
})

// ── Suspension status and provenance (ADR-027 Decision 2) ─────────────────────

describe('TenantAdminView — suspension status', () => {
  it('shows Active badge for active tenants', async () => {
    fetchMock.mockResolvedValue(
      makeTenantsResponse([makeTenant({ status: 'active' })]),
    )
    renderView()
    await waitFor(() => screen.getByTestId('active-badge'))
    expect(screen.getByTestId('active-badge')).toHaveTextContent('Active')
  })

  it('shows Suspended badge for suspended tenants', async () => {
    fetchMock.mockResolvedValue(
      makeTenantsResponse([
        makeTenant({ status: 'suspended', directly_suspended: true }),
      ]),
    )
    renderView()
    await waitFor(() => screen.getByTestId('suspended-badge'))
    expect(screen.getByTestId('suspended-badge')).toHaveTextContent('Suspended')
  })

  it('shows Direct provenance for directly-suspended tenant', async () => {
    fetchMock.mockResolvedValue(
      makeTenantsResponse([
        makeTenant({ status: 'suspended', directly_suspended: true, cascade_suspended_from: null }),
      ]),
    )
    renderView()
    await waitFor(() => screen.getByTestId('suspension-provenance'))
    expect(screen.getByTestId('suspension-provenance')).toHaveTextContent('Direct')
  })

  it('shows cascade provenance for cascade-suspended tenant', async () => {
    fetchMock.mockResolvedValue(
      makeTenantsResponse([
        makeTenant({
          status: 'suspended',
          directly_suspended: false,
          cascade_suspended_from: 'parent-a',
        }),
      ]),
    )
    renderView()
    await waitFor(() => screen.getByTestId('suspension-provenance'))
    expect(screen.getByTestId('suspension-provenance')).toHaveTextContent('Cascade from parent-a')
  })

  it('shows both Direct and Cascade provenance when both apply', async () => {
    fetchMock.mockResolvedValue(
      makeTenantsResponse([
        makeTenant({
          status: 'suspended',
          directly_suspended: true,
          cascade_suspended_from: 'msp-a',
        }),
      ]),
    )
    renderView()
    await waitFor(() => screen.getByTestId('suspension-provenance'))
    const prov = screen.getByTestId('suspension-provenance')
    expect(prov.textContent).toContain('Direct')
    expect(prov.textContent).toContain('Cascade from msp-a')
  })
})

// ── Action buttons ─────────────────────────────────────────────────────────────

describe('TenantAdminView — action buttons', () => {
  it('shows Suspend button for active tenant', async () => {
    fetchMock.mockResolvedValue(
      makeTenantsResponse([makeTenant({ status: 'active' })]),
    )
    renderView()
    await waitFor(() => screen.getByTestId('suspend-btn'))
    expect(screen.getByTestId('suspend-btn')).toHaveTextContent('Suspend')
  })

  it('shows "Suspend subtree" for active tenant with children', async () => {
    fetchMock.mockResolvedValue(
      makeTenantsResponse([
        makeTenant({ id: 'parent', name: 'parent', parent_id: '' }),
        makeTenant({ id: 'child', name: 'child', parent_id: 'parent' }),
      ]),
    )
    renderView()
    await waitFor(() => screen.getAllByTestId('suspend-btn'))
    const suspendBtns = screen.getAllByTestId('suspend-btn')
    // parent has a child so should show "Suspend subtree"
    expect(suspendBtns[0]).toHaveTextContent('Suspend subtree')
  })

  it('shows Restore button for suspended tenant', async () => {
    fetchMock.mockResolvedValue(
      makeTenantsResponse([
        makeTenant({ status: 'suspended', directly_suspended: true }),
      ]),
    )
    renderView()
    await waitFor(() => screen.getByTestId('restore-btn'))
    expect(screen.getByTestId('restore-btn')).toBeInTheDocument()
  })

  it('shows Request delete button for suspended tenant', async () => {
    fetchMock.mockResolvedValue(
      makeTenantsResponse([
        makeTenant({ status: 'suspended', directly_suspended: true }),
      ]),
    )
    renderView()
    await waitFor(() => screen.getByTestId('request-delete-btn'))
    expect(screen.getByTestId('request-delete-btn')).toBeInTheDocument()
  })

  it('shows Edit button for all tenants', async () => {
    fetchMock.mockResolvedValue(
      makeTenantsResponse([makeTenant()]),
    )
    renderView()
    await waitFor(() => screen.getByTestId('edit-btn'))
    expect(screen.getByTestId('edit-btn')).toBeInTheDocument()
  })
})

// ── Suspend action ─────────────────────────────────────────────────────────────

describe('TenantAdminView — suspend action', () => {
  it('calls suspend endpoint and refreshes on success', async () => {
    fetchMock
      .mockResolvedValueOnce(
        makeTenantsResponse([makeTenant({ id: 'client-1', status: 'active' })]),
      )
      .mockResolvedValueOnce(
        jsonResponse(200, { data: { target: 'client-1', newly_cascade_suspended: [], already_suspended: [] } }),
      )
      .mockResolvedValue(
        makeTenantsResponse([makeTenant({ id: 'client-1', status: 'suspended', directly_suspended: true })]),
      )

    renderView()
    await waitFor(() => screen.getByTestId('suspend-btn'))
    fireEvent.click(screen.getByTestId('suspend-btn'))
    await waitFor(() => screen.getByTestId('suspended-badge'))
    expect(fetchMock).toHaveBeenCalledWith(
      expect.stringContaining('/api/v1/tenants/client-1/suspend'),
      expect.objectContaining({ method: 'POST' }),
    )
  })

  it('shows error message when suspend fails', async () => {
    fetchMock
      .mockResolvedValueOnce(makeTenantsResponse([makeTenant({ id: 'default', status: 'active' })]))
      .mockResolvedValue(jsonResponse(400, { error: { message: 'cannot suspend default tenant' } }))

    renderView()
    await waitFor(() => screen.getByTestId('suspend-btn'))
    fireEvent.click(screen.getByTestId('suspend-btn'))
    await waitFor(() => screen.getByTestId('action-error'))
    expect(screen.getByTestId('action-error')).toHaveTextContent('cannot suspend default tenant')
  })
})

// ── Restore action ─────────────────────────────────────────────────────────────

describe('TenantAdminView — restore action', () => {
  it('calls restore endpoint and refreshes on success', async () => {
    fetchMock
      .mockResolvedValueOnce(
        makeTenantsResponse([makeTenant({ id: 'client-2', status: 'suspended', directly_suspended: true })]),
      )
      .mockResolvedValueOnce(jsonResponse(404, {})) // pending deletion check (404 = none)
      .mockResolvedValueOnce(
        jsonResponse(200, { data: { target: 'client-2', restored: ['client-2'], still_suspended: [] } }),
      )
      .mockResolvedValue(makeTenantsResponse([makeTenant({ id: 'client-2', status: 'active' })]))

    renderView()
    await waitFor(() => screen.getByTestId('restore-btn'))
    fireEvent.click(screen.getByTestId('restore-btn'))
    await waitFor(() => screen.getByTestId('active-badge'))
  })

  it('does not restore independently-suspended descendant (server behavior reflected in UI)', async () => {
    // The server ensures independently-suspended descendants stay suspended.
    // The restore result's still_suspended list names them.
    // After restore, the tree re-fetches and shows the descendant still suspended.
    fetchMock
      .mockResolvedValueOnce(
        makeTenantsResponse([
          makeTenant({ id: 'parent', status: 'suspended', directly_suspended: true }),
          makeTenant({ id: 'child', parent_id: 'parent', status: 'suspended', directly_suspended: true }),
        ]),
      )
      .mockResolvedValueOnce(jsonResponse(404, {})) // pending deletion for parent
      .mockResolvedValueOnce(jsonResponse(404, {})) // pending deletion for child
      .mockResolvedValueOnce(
        jsonResponse(200, { data: { target: 'parent', restored: ['parent'], still_suspended: ['child'] } }),
      )
      .mockResolvedValue(
        makeTenantsResponse([
          makeTenant({ id: 'parent', status: 'active', directly_suspended: false }),
          makeTenant({ id: 'child', parent_id: 'parent', status: 'suspended', directly_suspended: true }),
        ]),
      )

    renderView()
    await waitFor(() => screen.getAllByTestId('restore-btn'))
    // Click restore on the parent (first one)
    fireEvent.click(screen.getAllByTestId('restore-btn')[0]!)
    // After refresh: parent is active, child is still suspended
    await waitFor(() => {
      const badges = screen.getAllByTestId(/badge/)
      expect(badges.some((b) => b.textContent?.includes('Active'))).toBe(true)
      expect(badges.some((b) => b.textContent?.includes('Suspended'))).toBe(true)
    })
  })
})

// ── Request delete action (ADR-027 Decision 3) ────────────────────────────────

describe('TenantAdminView — request delete action', () => {
  it('calls request deletion and shows hold state on success', async () => {
    // The server holds the pipeline entry created by POST, so the refetch that
    // follows a successful request returns it — which is what proves the view
    // actually transitions to Hold rather than merely issuing the POST.
    let pending: Record<string, unknown> | null = null
    fetchMock.mockImplementation((input, init) => {
      const url = String(input)
      const method = ((init as RequestInit | undefined)?.method ?? 'GET').toUpperCase()
      if (url.endsWith('/api/v1/tenants')) {
        return Promise.resolve(
          makeTenantsResponse([
            makeTenant({ id: 'client-4', status: 'suspended', directly_suspended: true }),
          ]),
        )
      }
      if (url.endsWith('/api/v1/tenants/client-4/delete')) {
        if (method === 'POST') {
          pending = {
            subtree_root_id: 'client-4',
            requested_by: 'acct-11111111',
            requested_at: '2026-08-01T00:00:00Z',
            eligible_at: '2099-09-01T00:00:00Z',
            state: 'hold',
            pinned_member_ids: ['client-4'],
          }
          return Promise.resolve(jsonResponse(202, { data: pending }))
        }
        return Promise.resolve(
          pending === null
            ? jsonResponse(404, { error: { message: 'no pending deletion found' } })
            : jsonResponse(200, { data: pending }),
        )
      }
      return Promise.resolve(jsonResponse(500, { error: { message: 'unexpected call' } }))
    })

    renderView()
    await waitFor(() => screen.getByTestId('request-delete-btn'))
    fireEvent.click(screen.getByTestId('request-delete-btn'))

    // Success path: the row transitions to the Hold state with its countdown card
    // and the cancel action, and the request-delete action is gone.
    await waitFor(() => screen.getByTestId('delete-hold-badge'))
    expect(screen.getByTestId('delete-hold-badge')).toHaveTextContent('Delete: Hold')
    expect(screen.getByTestId('hold-card')).toHaveTextContent('acct-11111111')
    // A real remaining-time figure against the clock store, e.g. "365d 4h 0m".
    expect(screen.getByTestId('hold-countdown').textContent).toMatch(/\d+[dhm]/)
    expect(screen.getByTestId('cancel-delete-btn')).toBeInTheDocument()
    expect(screen.queryByTestId('request-delete-btn')).not.toBeInTheDocument()
    // Failure path did not run: no error banner.
    expect(screen.queryByTestId('action-error')).not.toBeInTheDocument()
    expect(fetchMock).toHaveBeenCalledWith(
      expect.stringContaining('/api/v1/tenants/client-4/delete'),
      expect.objectContaining({ method: 'POST' }),
    )
  })

  it('shows error message when delete request is rejected (subtree not fully suspended)', async () => {
    fetchMock
      .mockResolvedValueOnce(
        makeTenantsResponse([makeTenant({ id: 'client-3', status: 'suspended', directly_suspended: true })]),
      )
      .mockResolvedValueOnce(jsonResponse(404, {})) // pending deletion check
      .mockResolvedValue(
        jsonResponse(400, {
          error: { message: 'subtree not fully suspended — tenant dev-servers is not suspended' },
        }),
      )

    renderView()
    await waitFor(() => screen.getByTestId('request-delete-btn'))
    fireEvent.click(screen.getByTestId('request-delete-btn'))
    await waitFor(() => screen.getByTestId('action-error'))
    expect(screen.getByTestId('action-error')).toHaveTextContent('subtree not fully suspended')
    expect(screen.getByTestId('action-error')).toHaveTextContent('dev-servers')
  })
})

// ── Delete pipeline state display ─────────────────────────────────────────────

describe('TenantAdminView — delete pipeline display', () => {
  it('shows Hold badge and Cancel delete button for hold-state tenant', async () => {
    fetchMock
      .mockResolvedValueOnce(
        makeTenantsResponse([
          makeTenant({ id: 'client-4', status: 'suspended', directly_suspended: true }),
        ]),
      )
      .mockResolvedValueOnce(
        jsonResponse(200, {
          data: {
            subtree_root_id: 'client-4',
            requested_by: 'ops-admin',
            requested_at: '2026-07-24T00:00:00Z',
            eligible_at: '2099-09-01T00:00:00Z',
            state: 'hold',
            pinned_member_ids: ['client-4'],
          },
        }),
      )

    renderView()
    await waitFor(() => screen.getByTestId('delete-hold-badge'))
    expect(screen.getByTestId('delete-hold-badge')).toHaveTextContent('Delete: Hold')
    expect(screen.getByTestId('cancel-delete-btn')).toBeInTheDocument()
    expect(screen.getByTestId('hold-card')).toBeInTheDocument()
  })

  it('shows Eligible badge and Approve deletion button for eligible-state tenant', async () => {
    fetchMock
      .mockResolvedValueOnce(
        makeTenantsResponse([
          makeTenant({ id: 'client-5', status: 'suspended', directly_suspended: true }),
        ]),
      )
      .mockResolvedValueOnce(
        jsonResponse(200, {
          data: {
            subtree_root_id: 'client-5',
            requested_by: 'msp-a-owner',
            requested_at: '2026-06-28T00:00:00Z',
            eligible_at: '2026-07-28T00:00:00Z',
            state: 'eligible',
            pinned_member_ids: ['client-5'],
          },
        }),
      )

    renderView()
    await waitFor(() => screen.getByTestId('delete-eligible-badge'))
    expect(screen.getByTestId('delete-eligible-badge')).toHaveTextContent('Delete: Eligible')
    expect(screen.getByTestId('approve-delete-btn')).toBeInTheDocument()
    expect(screen.getByTestId('eligible-card')).toBeInTheDocument()
  })

  it('offers an enabled approve action to a session holding no dual-control lock', async () => {
    // The second-approver path: this session neither requested the deletion nor has
    // been refused by the controller, so the terminal action is available and the
    // card carries the dual-control hint rather than the lock notice.
    fetchMock
      .mockResolvedValueOnce(
        makeTenantsResponse([
          makeTenant({ id: 'client-5', status: 'suspended', directly_suspended: true }),
        ]),
      )
      .mockResolvedValueOnce(
        jsonResponse(200, {
          data: {
            subtree_root_id: 'client-5',
            requested_by: 'acct-22222222',
            requested_at: '2026-06-28T00:00:00Z',
            eligible_at: '2026-07-28T00:00:00Z',
            state: 'eligible',
            pinned_member_ids: ['client-5'],
          },
        }),
      )

    renderView()
    await waitFor(() => screen.getByTestId('approve-delete-btn'))
    expect(screen.getByTestId('approve-delete-btn')).not.toBeDisabled()
    expect(screen.getByTestId('dual-control-hint')).toBeInTheDocument()
    expect(screen.queryByTestId('dual-control-lock-notice')).not.toBeInTheDocument()
  })
})

// ── Dual-control lock (ADR-027 Decision 4) ────────────────────────────────────

describe('TenantAdminView — dual-control lock', () => {
  it('locks the approve action when the controller refuses with SAME_APPROVER', async () => {
    // `pending_deletion.requested_by` is a server principal ID that no browser
    // session can match locally, so the controller's 403 SAME_APPROVER is the
    // authoritative signal that this operator is the original requester. Once it
    // arrives the terminal action must lock and the notice must appear.
    fetchMock.mockImplementation((input, init) => {
      const url = String(input)
      const method = ((init as RequestInit | undefined)?.method ?? 'GET').toUpperCase()
      if (url.endsWith('/api/v1/tenants')) {
        return Promise.resolve(
          makeTenantsResponse([
            makeTenant({ id: 'client-5', status: 'suspended', directly_suspended: true }),
          ]),
        )
      }
      if (url.endsWith('/api/v1/tenants/client-5/delete/approve') && method === 'POST') {
        return Promise.resolve(
          jsonResponse(403, {
            error: {
              code: 'SAME_APPROVER',
              message: 'approver must differ from the principal who requested this deletion',
            },
          }),
        )
      }
      if (url.endsWith('/api/v1/tenants/client-5/delete')) {
        return Promise.resolve(
          jsonResponse(200, {
            data: {
              subtree_root_id: 'client-5',
              requested_by: 'acct-33333333',
              requested_at: '2026-06-28T00:00:00Z',
              eligible_at: '2026-07-28T00:00:00Z',
              state: 'eligible',
              pinned_member_ids: ['client-5'],
            },
          }),
        )
      }
      return Promise.resolve(jsonResponse(500, { error: { message: 'unexpected call' } }))
    })

    renderView()
    await waitFor(() => screen.getByTestId('approve-delete-btn'))
    expect(screen.getByTestId('approve-delete-btn')).not.toBeDisabled()

    fireEvent.click(screen.getByTestId('approve-delete-btn'))

    await waitFor(() => expect(screen.getByTestId('approve-delete-btn')).toBeDisabled())
    expect(screen.getByTestId('approve-delete-btn')).toHaveAttribute(
      'title',
      'You requested this deletion — a different principal must approve',
    )
    expect(screen.getByTestId('dual-control-lock-notice')).toHaveTextContent(
      'a different principal must approve',
    )
    expect(screen.queryByTestId('dual-control-hint')).not.toBeInTheDocument()
    expect(screen.getByTestId('action-error')).toHaveTextContent(
      'approver must differ from the principal who requested this deletion',
    )
  })

  it('locks the approve action for the session that requested the deletion', async () => {
    // Same-session requester: the view knows it issued the request, so the lock
    // engages without waiting for the controller to refuse a doomed approval.
    // (Hold period configured to zero here, so the entry is Eligible at once.)
    let pending: Record<string, unknown> | null = null
    fetchMock.mockImplementation((input, init) => {
      const url = String(input)
      const method = ((init as RequestInit | undefined)?.method ?? 'GET').toUpperCase()
      if (url.endsWith('/api/v1/tenants')) {
        return Promise.resolve(
          makeTenantsResponse([
            makeTenant({ id: 'client-6', status: 'suspended', directly_suspended: true }),
          ]),
        )
      }
      if (url.endsWith('/api/v1/tenants/client-6/delete')) {
        if (method === 'POST') {
          pending = {
            subtree_root_id: 'client-6',
            requested_by: 'acct-44444444',
            requested_at: '2026-08-01T00:00:00Z',
            eligible_at: '2026-08-01T00:00:00Z',
            state: 'eligible',
            pinned_member_ids: ['client-6'],
          }
          return Promise.resolve(jsonResponse(202, { data: pending }))
        }
        return Promise.resolve(
          pending === null
            ? jsonResponse(404, { error: { message: 'no pending deletion found' } })
            : jsonResponse(200, { data: pending }),
        )
      }
      return Promise.resolve(jsonResponse(500, { error: { message: 'unexpected call' } }))
    })

    renderView()
    await waitFor(() => screen.getByTestId('request-delete-btn'))
    fireEvent.click(screen.getByTestId('request-delete-btn'))

    await waitFor(() => screen.getByTestId('approve-delete-btn'))
    expect(screen.getByTestId('approve-delete-btn')).toBeDisabled()
    expect(screen.getByTestId('dual-control-lock-notice')).toBeInTheDocument()
    expect(screen.queryByTestId('dual-control-hint')).not.toBeInTheDocument()
  })

  it('releases the lock when the pending deletion is cancelled', async () => {
    // Cancelling discards the pipeline entry this session requested. A later entry
    // raised by a different principal must not inherit the stale lock.
    let pending: Record<string, unknown> | null = null
    fetchMock.mockImplementation((input, init) => {
      const url = String(input)
      const method = ((init as RequestInit | undefined)?.method ?? 'GET').toUpperCase()
      if (url.endsWith('/api/v1/tenants')) {
        return Promise.resolve(
          makeTenantsResponse([
            makeTenant({ id: 'client-7', status: 'suspended', directly_suspended: true }),
          ]),
        )
      }
      if (url.endsWith('/api/v1/tenants/client-7/delete')) {
        if (method === 'POST') {
          pending = {
            subtree_root_id: 'client-7',
            requested_by: 'acct-55555555',
            requested_at: '2026-08-01T00:00:00Z',
            eligible_at: '2026-08-01T00:00:00Z',
            state: 'eligible',
            pinned_member_ids: ['client-7'],
          }
          return Promise.resolve(jsonResponse(202, { data: pending }))
        }
        if (method === 'DELETE') {
          // Cancelled here; a second principal then raises their own request,
          // which the next GET returns.
          pending = {
            subtree_root_id: 'client-7',
            requested_by: 'acct-66666666',
            requested_at: '2026-08-02T00:00:00Z',
            eligible_at: '2026-08-02T00:00:00Z',
            state: 'eligible',
            pinned_member_ids: ['client-7'],
          }
          return Promise.resolve(jsonResponse(200, { data: { cancelled: true } }))
        }
        return Promise.resolve(
          pending === null
            ? jsonResponse(404, { error: { message: 'no pending deletion found' } })
            : jsonResponse(200, { data: pending }),
        )
      }
      return Promise.resolve(jsonResponse(500, { error: { message: 'unexpected call' } }))
    })

    renderView()
    await waitFor(() => screen.getByTestId('request-delete-btn'))
    fireEvent.click(screen.getByTestId('request-delete-btn'))
    await waitFor(() => expect(screen.getByTestId('approve-delete-btn')).toBeDisabled())

    fireEvent.click(screen.getByTestId('deny-delete-btn'))
    await waitFor(() =>
      expect(screen.getByTestId('eligible-card')).toHaveTextContent('acct-66666666'),
    )
    expect(screen.getByTestId('approve-delete-btn')).not.toBeDisabled()
    expect(screen.getByTestId('dual-control-hint')).toBeInTheDocument()
  })
})

// ── Cancel delete action ──────────────────────────────────────────────────────

describe('TenantAdminView — cancel delete action', () => {
  it('calls cancel endpoint and refreshes on success', async () => {
    fetchMock
      .mockResolvedValueOnce(
        makeTenantsResponse([
          makeTenant({ id: 'client-4', status: 'suspended', directly_suspended: true }),
        ]),
      )
      .mockResolvedValueOnce(
        jsonResponse(200, {
          data: {
            subtree_root_id: 'client-4',
            requested_by: 'ops',
            requested_at: '2026-08-01T00:00:00Z',
            eligible_at: '2099-09-01T00:00:00Z',
            state: 'hold',
            pinned_member_ids: ['client-4'],
          },
        }),
      )
      .mockResolvedValueOnce(jsonResponse(200, { data: { cancelled: true } }))
      .mockResolvedValue(
        makeTenantsResponse([
          makeTenant({ id: 'client-4', status: 'suspended', directly_suspended: true }),
        ]),
      )

    renderView()
    await waitFor(() => screen.getByTestId('cancel-delete-btn'))
    fireEvent.click(screen.getByTestId('cancel-delete-btn'))
    expect(fetchMock).toHaveBeenCalledWith(
      expect.stringContaining('/api/v1/tenants/client-4/delete'),
      expect.objectContaining({ method: 'DELETE' }),
    )
  })
})

// ── Create form ────────────────────────────────────────────────────────────────

describe('TenantAdminView — create form', () => {
  it('opens create panel on "+ New tenant" click', async () => {
    fetchMock.mockResolvedValue(makeTenantsResponse([makeTenant()]))
    renderView()
    await waitFor(() => screen.getByTestId('toggle-create-btn'))
    fireEvent.click(screen.getByTestId('toggle-create-btn'))
    expect(screen.getByTestId('create-tenant-panel')).toBeInTheDocument()
  })

  it('closes create panel on Cancel click', async () => {
    fetchMock.mockResolvedValue(makeTenantsResponse([makeTenant()]))
    renderView()
    await waitFor(() => screen.getByTestId('toggle-create-btn'))
    fireEvent.click(screen.getByTestId('toggle-create-btn'))
    fireEvent.click(screen.getByRole('button', { name: /cancel/i }))
    expect(screen.queryByTestId('create-tenant-panel')).not.toBeInTheDocument()
  })

  it('shows error when submitting without name', async () => {
    fetchMock.mockResolvedValue(makeTenantsResponse([]))
    renderView()
    await waitFor(() => screen.getByTestId('toggle-create-btn'))
    fireEvent.click(screen.getByTestId('toggle-create-btn'))
    fireEvent.click(screen.getByTestId('tenant-save-btn'))
    await waitFor(() => screen.getByTestId('tenant-save-error'))
    expect(screen.getByTestId('tenant-save-error')).toHaveTextContent('Tenant name is required')
  })

  it('calls POST /api/v1/tenants and refreshes on success', async () => {
    fetchMock
      .mockResolvedValueOnce(makeTenantsResponse([]))
      .mockResolvedValueOnce(
        jsonResponse(201, {
          data: { id: 'new-client', name: 'new-client', parent_id: 'msp-a', status: 'active' },
        }),
      )
      .mockResolvedValue(
        makeTenantsResponse([makeTenant({ id: 'new-client', name: 'new-client' })]),
      )

    renderView()
    await waitFor(() => screen.getByTestId('toggle-create-btn'))
    fireEvent.click(screen.getByTestId('toggle-create-btn'))
    fireEvent.change(screen.getByTestId('tenant-name-input'), { target: { value: 'new-client' } })
    fireEvent.click(screen.getByTestId('tenant-save-btn'))
    await waitFor(() => expect(screen.queryByTestId('create-tenant-panel')).not.toBeInTheDocument())
    expect(fetchMock).toHaveBeenCalledWith(
      expect.stringContaining('/api/v1/tenants'),
      expect.objectContaining({ method: 'POST' }),
    )
  })

  it('shows error message when create fails', async () => {
    fetchMock
      .mockResolvedValueOnce(makeTenantsResponse([]))
      .mockResolvedValue(jsonResponse(409, { error: { message: 'tenant already exists' } }))

    renderView()
    await waitFor(() => screen.getByTestId('toggle-create-btn'))
    fireEvent.click(screen.getByTestId('toggle-create-btn'))
    fireEvent.change(screen.getByTestId('tenant-name-input'), { target: { value: 'dup' } })
    fireEvent.click(screen.getByTestId('tenant-save-btn'))
    await waitFor(() => screen.getByTestId('tenant-save-error'))
    expect(screen.getByTestId('tenant-save-error')).toHaveTextContent('tenant already exists')
  })
})

// ── Edit form ──────────────────────────────────────────────────────────────────

describe('TenantAdminView — edit form', () => {
  it('opens edit panel on Edit click', async () => {
    fetchMock.mockResolvedValue(makeTenantsResponse([makeTenant({ name: 'client-1' })]))
    renderView()
    await waitFor(() => screen.getByTestId('edit-btn'))
    fireEvent.click(screen.getByTestId('edit-btn'))
    expect(screen.getByTestId('edit-tenant-panel')).toBeInTheDocument()
  })

  it('calls PUT /api/v1/tenants/{id} on save', async () => {
    fetchMock
      .mockResolvedValueOnce(makeTenantsResponse([makeTenant({ id: 'client-1', name: 'client-1' })]))
      .mockResolvedValueOnce(
        jsonResponse(200, { data: { id: 'client-1', name: 'client-1-renamed', status: 'active' } }),
      )
      .mockResolvedValue(
        makeTenantsResponse([makeTenant({ id: 'client-1', name: 'client-1-renamed' })]),
      )

    renderView()
    await waitFor(() => screen.getByTestId('edit-btn'))
    fireEvent.click(screen.getByTestId('edit-btn'))
    fireEvent.change(screen.getByTestId('edit-tenant-name-input'), {
      target: { value: 'client-1-renamed' },
    })
    fireEvent.click(screen.getByTestId('edit-save-btn'))
    await waitFor(() =>
      expect(fetchMock).toHaveBeenCalledWith(
        expect.stringContaining('/api/v1/tenants/client-1'),
        expect.objectContaining({ method: 'PUT' }),
      ),
    )
  })
})
