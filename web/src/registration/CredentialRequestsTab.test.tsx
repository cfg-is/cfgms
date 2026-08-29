// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz

/*
 * CredentialRequestsTab test suite (Issue #3723, Epic #3711).
 *
 * Required ACs covered here:
 *  - Approval sends the fingerprint the administrator saw; a server conflict
 *    (409) is surfaced as a request to re-compare, never silently retried.
 *  - No requester-supplied value is rendered as raw HTML or placed into a link
 *    target; the panel uses no raw HTML rendering at all.
 *  - The panel never sends a root-scope marker in an approve request, for every
 *    reachable combination of the marker controls, and offers no root-scope
 *    control at all.
 *
 * Also covers: loading/empty/error/pending/approved/denied/expired states, deny,
 * and marker-unavailable-with-reason for a non-root-scope session.
 */
import { useEffect, type ReactNode } from 'react'
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'
import { cleanup, fireEvent, render, screen, waitFor, within } from '@testing-library/react'
import { MemoryRouter } from 'react-router'
import { AuthProvider, useAuth } from '../auth/AuthContext.tsx'
import CredentialRequestsTab from './CredentialRequestsTab.tsx'

const fetchMock = vi.fn<typeof fetch>()

beforeEach(() => {
  vi.stubGlobal('fetch', fetchMock)
  fetchMock.mockReset()
})

afterEach(() => {
  vi.unstubAllGlobals()
  cleanup()
})

// ── Factories ─────────────────────────────────────────────────────────────────

function makeEntry(overrides: Partial<Record<string, unknown>> = {}) {
  return {
    id: 'creq-abc123',
    tenant_id: 'msp-a',
    status: 'pending',
    public_key_fingerprint: 'a'.repeat(64),
    public_key_fingerprint_short: 'AAAA-AAAA-AAAA-AAAA',
    source_ip: '10.0.0.1',
    hostname: 'host-1',
    label: '',
    platform: 'linux',
    purpose: 'steward-enrolment',
    created_at: '2026-08-29T00:00:00Z',
    expires_at: '2099-01-01T00:00:00Z',
    ...overrides,
  }
}

function makeListResponse(entries: object[], status = 200) {
  return new Response(JSON.stringify({ data: entries }), {
    status,
    headers: { 'Content-Type': 'application/json' },
  })
}

function jsonResponse(status: number, body: unknown = {}) {
  return new Response(status === 204 ? null : JSON.stringify(body), {
    status,
    headers: { 'Content-Type': 'application/json' },
  })
}

function renderTab() {
  return render(
    <MemoryRouter>
      <AuthProvider>
        <CredentialRequestsTab />
      </AuthProvider>
    </MemoryRouter>,
  )
}

// ── Root-scope admin harness ──────────────────────────────────────────────────
// principal.rootScope is only ever set via the real passkey login ceremony
// (AuthContext.tsx is out of scope for this story), so entitlement-gated tests
// drive that ceremony to completion before rendering the tab.

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
      authenticatorData: toArrayBuffer('authenticator-data'),
      signature: toArrayBuffer('signature'),
      userHandle: null,
    } as AuthenticatorAssertionResponse,
    getClientExtensionResults: () => ({}) as AuthenticationExtensionsClientOutputs,
    authenticatorAttachment: null,
    toJSON: () => ({}),
  } as unknown as PublicKeyCredential
}

function LoginGate({ children }: { children: ReactNode }) {
  const { login, status } = useAuth()
  useEffect(() => {
    void login()
  }, [login])
  if (status !== 'signedIn') return <div data-testid="awaiting-login" />
  return <>{children}</>
}

/** Wires passkey login + credential-request endpoints behind one dispatcher. */
function mockRootScopeSession(opts: {
  listResponse?: () => Response
  approveResponse?: () => Response
  denyResponse?: () => Response
}) {
  vi.stubGlobal('navigator', { credentials: { get: vi.fn().mockResolvedValue(makePublicKeyCredential()) } })
  const listResponse = opts.listResponse ?? (() => makeListResponse([makeEntry()]))
  fetchMock.mockImplementation((input, init) => {
    const url = String(input)
    const method = (init?.method ?? 'GET').toUpperCase()
    if (url.endsWith('/api/v1/web/csrf')) {
      document.cookie = 'cfgms_csrf_pre=pre-tok; path=/'
      return Promise.resolve(jsonResponse(204))
    }
    if (url.endsWith('/api/v1/web/passkey/login/begin')) {
      return Promise.resolve(jsonResponse(200, MOCK_PASSKEY_BEGIN_OPTIONS))
    }
    if (url.endsWith('/api/v1/web/passkey/login/finish')) {
      return Promise.resolve(
        jsonResponse(200, { data: { ok: true, username: 'admin@root', tenant_id: '', root_scope: true } }),
      )
    }
    if (method === 'POST' && url.includes('/approve')) {
      return Promise.resolve((opts.approveResponse ?? (() => jsonResponse(200, { data: { id: 'creq-abc123', status: 'approved', granted_markers: [] } })))())
    }
    if (method === 'POST' && url.includes('/deny')) {
      return Promise.resolve((opts.denyResponse ?? (() => jsonResponse(200, { data: { id: 'creq-abc123', status: 'denied' } })))())
    }
    if (method === 'GET' && url.endsWith('/api/v1/credential-requests')) {
      return Promise.resolve(listResponse())
    }
    return Promise.resolve(jsonResponse(401))
  })
}

function renderAsRootScopeAdmin() {
  return render(
    <MemoryRouter>
      <AuthProvider>
        <LoginGate>
          <CredentialRequestsTab />
        </LoginGate>
      </AuthProvider>
    </MemoryRouter>,
  )
}

// ── Loading / empty / error states ───────────────────────────────────────────

describe('CredentialRequestsTab — data states', () => {
  it('shows loading rows while the fetch is in-flight', () => {
    fetchMock.mockReturnValue(new Promise(() => {}))
    renderTab()
    expect(screen.getByTestId('credential-requests-loading')).toBeInTheDocument()
  })

  it('shows the empty state when no requests are pending', async () => {
    fetchMock.mockResolvedValue(makeListResponse([]))
    renderTab()
    await waitFor(() => expect(screen.getByTestId('credential-requests-empty')).toBeInTheDocument())
  })

  it('shows an error notice on a non-200 list response', async () => {
    fetchMock.mockResolvedValue(makeListResponse([], 500))
    renderTab()
    await waitFor(() => expect(screen.getByRole('alert')).toBeInTheDocument())
    expect(screen.getByRole('alert')).toHaveTextContent('500')
  })

  it('shows an error notice on a network-level failure', async () => {
    fetchMock.mockRejectedValue(new Error('network down'))
    renderTab()
    await waitFor(() => expect(screen.getByRole('alert')).toBeInTheDocument())
  })

  it('retries the fetch when Retry is clicked', async () => {
    fetchMock
      .mockResolvedValueOnce(makeListResponse([], 500))
      .mockResolvedValueOnce(makeListResponse([]))
    renderTab()
    await waitFor(() => expect(screen.getByRole('alert')).toBeInTheDocument())
    fireEvent.click(screen.getByRole('button', { name: /retry/i }))
    await waitFor(() => expect(screen.getByTestId('credential-requests-empty')).toBeInTheDocument())
    expect(fetchMock).toHaveBeenCalledTimes(2)
  })
})

// ── List rendering ────────────────────────────────────────────────────────────

describe('CredentialRequestsTab — list rendering', () => {
  it('renders a row per pending request with fingerprint, source, purpose, and expiry', async () => {
    fetchMock.mockResolvedValue(makeListResponse([makeEntry()]))
    renderTab()
    await waitFor(() => expect(screen.getByTestId('credential-requests-table')).toBeInTheDocument())
    expect(screen.getAllByTestId('credential-request-row')).toHaveLength(1)
    expect(screen.getByText('AAAA-AAAA-AAAA-AAAA')).toBeInTheDocument()
    expect(screen.getByText('10.0.0.1')).toBeInTheDocument()
    expect(screen.getByText('steward-enrolment')).toBeInTheDocument()
    expect(screen.getByText('2099-01-01T00:00:00Z')).toBeInTheDocument()
  })

  it('renders multiple rows', async () => {
    fetchMock.mockResolvedValue(
      makeListResponse([makeEntry(), makeEntry({ id: 'creq-def456', source_ip: '10.0.0.2' })]),
    )
    renderTab()
    await waitFor(() => expect(screen.getAllByTestId('credential-request-row')).toHaveLength(2))
  })

  it('states plainly that the fingerprint must match what the enrolling machine printed', async () => {
    fetchMock.mockResolvedValue(makeListResponse([makeEntry()]))
    renderTab()
    await waitFor(() => expect(screen.getByTestId('credential-requests-table')).toBeInTheDocument())
    expect(screen.getByText(/must match what the enrolling machine printed/i)).toBeInTheDocument()
  })

  it('refreshes the list on demand', async () => {
    fetchMock.mockResolvedValue(makeListResponse([makeEntry()]))
    renderTab()
    await waitFor(() => expect(screen.getByTestId('credential-requests-table')).toBeInTheDocument())
    fireEvent.click(screen.getByTestId('refresh-btn'))
    await waitFor(() => expect(fetchMock).toHaveBeenCalledTimes(2))
  })

  it('shows a pending status badge for a pending row', async () => {
    fetchMock.mockResolvedValue(makeListResponse([makeEntry()]))
    renderTab()
    await waitFor(() => expect(screen.getByTestId('credential-requests-table')).toBeInTheDocument())
    expect(screen.getByTestId('status-creq-abc123')).toHaveTextContent(/pending/i)
  })

  it('shows an expired status badge and hides actions once expires_at has passed', async () => {
    fetchMock.mockResolvedValue(
      makeListResponse([makeEntry({ expires_at: '2000-01-01T00:00:00Z' })]),
    )
    renderTab()
    await waitFor(() => expect(screen.getByTestId('credential-requests-table')).toBeInTheDocument())
    expect(screen.getByTestId('status-creq-abc123')).toHaveTextContent(/expired/i)
    expect(screen.queryByTestId('approve-btn-creq-abc123')).toBeNull()
    expect(screen.queryByTestId('deny-btn-creq-abc123')).toBeNull()
  })
})

// ── Security A9.1: no raw HTML, no link/download smuggling ──────────────────

describe('CredentialRequestsTab — A9.1 security (no raw HTML rendering)', () => {
  it('renders hostname/label/platform/purpose XSS payloads as text nodes only', async () => {
    const payload = '<img src=x onerror="window.__xss_creq=1">'
    fetchMock.mockResolvedValue(
      makeListResponse([
        makeEntry({ hostname: payload, purpose: payload, platform: payload }),
      ]),
    )
    const { container } = renderTab()
    await waitFor(() => expect(screen.getByTestId('credential-requests-table')).toBeInTheDocument())
    expect(screen.getAllByText(payload).length).toBeGreaterThan(0)
    expect(container.querySelector('img')).toBeNull()
    expect((window as unknown as Record<string, unknown>).__xss_creq).toBeUndefined()
  })

  it('never places a requester-supplied value into a link href or a download attribute', async () => {
    const payload = 'javascript:alert(1)//host'
    fetchMock.mockResolvedValue(
      makeListResponse([makeEntry({ hostname: payload, source_ip: payload, purpose: payload })]),
    )
    const { container } = renderTab()
    await waitFor(() => expect(screen.getByTestId('credential-requests-table')).toBeInTheDocument())
    for (const a of Array.from(container.querySelectorAll('a'))) {
      expect(a.getAttribute('href') ?? '').not.toContain(payload)
    }
    for (const el of Array.from(container.querySelectorAll('[download]'))) {
      expect(el.getAttribute('download') ?? '').not.toContain(payload)
    }
  })
})

// ── Deny ──────────────────────────────────────────────────────────────────────

describe('CredentialRequestsTab — deny', () => {
  it('deny marks the row denied and hides its actions, without removing the row', async () => {
    fetchMock
      .mockResolvedValueOnce(makeListResponse([makeEntry()]))
      .mockResolvedValueOnce(jsonResponse(200, { data: { id: 'creq-abc123', status: 'denied' } }))
    renderTab()
    await waitFor(() => expect(screen.getByTestId('credential-requests-table')).toBeInTheDocument())

    fireEvent.click(screen.getByTestId('deny-btn-creq-abc123'))

    await waitFor(() => expect(screen.getByTestId('status-creq-abc123')).toHaveTextContent(/denied/i))
    expect(screen.getAllByTestId('credential-request-row')).toHaveLength(1)
    expect(screen.queryByTestId('deny-btn-creq-abc123')).toBeNull()
    const denyCall = fetchMock.mock.calls[1]!
    expect(String(denyCall[0])).toBe('/api/v1/credential-requests/creq-abc123/deny')
    expect((denyCall[1] as RequestInit | undefined)?.method).toBe('POST')
  })

  it('surfaces a row-level error on a failed deny without crashing', async () => {
    fetchMock
      .mockResolvedValueOnce(makeListResponse([makeEntry()]))
      .mockResolvedValueOnce(jsonResponse(403))
    renderTab()
    await waitFor(() => expect(screen.getByTestId('credential-requests-table')).toBeInTheDocument())

    fireEvent.click(screen.getByTestId('deny-btn-creq-abc123'))

    await waitFor(() => expect(screen.getByTestId('deny-error-creq-abc123')).toBeInTheDocument())
    expect(screen.getByTestId('deny-error-creq-abc123')).toHaveTextContent('403')
    expect(screen.getByTestId('status-creq-abc123')).toHaveTextContent(/pending/i)
  })
})

// ── Approve — marker entitlement (no root-scope session) ────────────────────

describe('CredentialRequestsTab — approve marker entitlement (non-root-scope session)', () => {
  it('opens the approve modal showing the rendered fingerprint', async () => {
    fetchMock.mockResolvedValue(makeListResponse([makeEntry()]))
    renderTab()
    await waitFor(() => expect(screen.getByTestId('credential-requests-table')).toBeInTheDocument())

    fireEvent.click(screen.getByTestId('approve-btn-creq-abc123'))

    expect(screen.getByTestId('approve-modal')).toBeInTheDocument()
    expect(within(screen.getByTestId('approve-modal')).getByText('AAAA-AAAA-AAAA-AAAA')).toBeInTheDocument()
  })

  it('marker checkboxes default unchecked', async () => {
    fetchMock.mockResolvedValue(makeListResponse([makeEntry()]))
    renderTab()
    await waitFor(() => expect(screen.getByTestId('credential-requests-table')).toBeInTheDocument())
    fireEvent.click(screen.getByTestId('approve-btn-creq-abc123'))

    expect(screen.getByTestId('marker-admin')).not.toBeChecked()
    expect(screen.getByTestId('marker-payload-signing')).not.toBeChecked()
  })

  it('admin and payload-signing markers are disabled with a stated reason for a non-root-scope session', async () => {
    fetchMock.mockResolvedValue(makeListResponse([makeEntry()]))
    renderTab()
    await waitFor(() => expect(screen.getByTestId('credential-requests-table')).toBeInTheDocument())
    fireEvent.click(screen.getByTestId('approve-btn-creq-abc123'))

    expect(screen.getByTestId('marker-admin')).toBeDisabled()
    expect(screen.getByTestId('marker-admin-reason')).toBeInTheDocument()
    expect(screen.getByTestId('marker-payload-signing')).toBeDisabled()
    expect(screen.getByTestId('marker-payload-signing-reason')).toBeInTheDocument()
  })

  it('offers no root-scope marker control, and states a certificate-authenticated approval is required', async () => {
    fetchMock.mockResolvedValue(makeListResponse([makeEntry()]))
    renderTab()
    await waitFor(() => expect(screen.getByTestId('credential-requests-table')).toBeInTheDocument())
    fireEvent.click(screen.getByTestId('approve-btn-creq-abc123'))

    expect(screen.queryByTestId('marker-root-scope')).toBeNull()
    expect(screen.queryByRole('checkbox', { name: /root.?scope/i })).toBeNull()
    expect(screen.getByText(/root-scope grant requires a certificate-authenticated approval/i)).toBeInTheDocument()
  })

  it('cancel closes the modal without approving', async () => {
    fetchMock.mockResolvedValue(makeListResponse([makeEntry()]))
    renderTab()
    await waitFor(() => expect(screen.getByTestId('credential-requests-table')).toBeInTheDocument())
    fireEvent.click(screen.getByTestId('approve-btn-creq-abc123'))
    fireEvent.click(screen.getByTestId('approve-cancel-btn'))
    expect(screen.queryByTestId('approve-modal')).toBeNull()
    expect(fetchMock).toHaveBeenCalledTimes(1)
  })
})

// ── Approve — submission, fingerprint, and conflict handling ────────────────

describe('CredentialRequestsTab — approve submission', () => {
  it('[REQUIRED] sends the fingerprint the panel rendered, and marks the row approved on success', async () => {
    fetchMock
      .mockResolvedValueOnce(makeListResponse([makeEntry()]))
      .mockResolvedValueOnce(
        jsonResponse(200, {
          data: { id: 'creq-abc123', status: 'approved', account_id: 'acct-1', granted_markers: [] },
        }),
      )
    renderTab()
    await waitFor(() => expect(screen.getByTestId('credential-requests-table')).toBeInTheDocument())

    fireEvent.click(screen.getByTestId('approve-btn-creq-abc123'))
    fireEvent.change(screen.getByTestId('approve-username'), { target: { value: 'host-1' } })
    fireEvent.click(screen.getByTestId('approve-submit-btn'))

    await waitFor(() => expect(screen.getByTestId('status-creq-abc123')).toHaveTextContent(/approved/i))
    expect(screen.queryByTestId('approve-modal')).toBeNull()

    const approveCall = fetchMock.mock.calls[1]!
    expect(String(approveCall[0])).toBe('/api/v1/credential-requests/creq-abc123/approve')
    const body = JSON.parse(String((approveCall[1] as RequestInit).body)) as Record<string, unknown>
    expect(body.fingerprint).toBe('AAAA-AAAA-AAAA-AAAA')
    expect(body.new_account_username).toBe('host-1')
  })

  it('requires an account username before submitting', async () => {
    fetchMock.mockResolvedValueOnce(makeListResponse([makeEntry()]))
    renderTab()
    await waitFor(() => expect(screen.getByTestId('credential-requests-table')).toBeInTheDocument())

    fireEvent.click(screen.getByTestId('approve-btn-creq-abc123'))
    fireEvent.click(screen.getByTestId('approve-submit-btn'))

    expect(screen.getByTestId('approve-error')).toBeInTheDocument()
    expect(fetchMock).toHaveBeenCalledTimes(1)
  })

  it('[REQUIRED] a 409 conflict is surfaced as a request to re-compare, refreshes the row, and never retries silently', async () => {
    fetchMock
      .mockResolvedValueOnce(makeListResponse([makeEntry()]))
      .mockResolvedValueOnce(jsonResponse(409, { error: { code: 'REQUEST_NOT_PENDING', message: 'x' } }))
      .mockResolvedValueOnce(makeListResponse([makeEntry({ status: 'pending' })]))
    renderTab()
    await waitFor(() => expect(screen.getByTestId('credential-requests-table')).toBeInTheDocument())

    fireEvent.click(screen.getByTestId('approve-btn-creq-abc123'))
    fireEvent.change(screen.getByTestId('approve-username'), { target: { value: 'host-1' } })
    fireEvent.click(screen.getByTestId('approve-submit-btn'))

    await waitFor(() => expect(screen.getByTestId('conflict-creq-abc123')).toBeInTheDocument())
    expect(screen.getByTestId('conflict-creq-abc123')).toHaveTextContent(/compare the fingerprint again/i)
    // Exactly one approve POST was made — the conflict is never silently retried.
    const approvePosts = fetchMock.mock.calls.filter(
      (c) => String(c[0]).includes('/approve') && (c[1] as RequestInit | undefined)?.method === 'POST',
    )
    expect(approvePosts).toHaveLength(1)
    // The row's data was refreshed (a second GET to the list endpoint).
    await waitFor(() => {
      const listGets = fetchMock.mock.calls.filter((c) => String(c[0]) === '/api/v1/credential-requests')
      expect(listGets.length).toBeGreaterThanOrEqual(2)
    })
    // The row is still pending, not silently approved.
    expect(screen.getByTestId('status-creq-abc123')).toHaveTextContent(/pending/i)
  })

  it('surfaces a non-conflict approve failure inline and keeps the modal open for retry', async () => {
    fetchMock
      .mockResolvedValueOnce(makeListResponse([makeEntry()]))
      .mockResolvedValueOnce(jsonResponse(403, { error: { code: 'MARKER_NOT_GRANTABLE', message: 'x' } }))
    renderTab()
    await waitFor(() => expect(screen.getByTestId('credential-requests-table')).toBeInTheDocument())

    fireEvent.click(screen.getByTestId('approve-btn-creq-abc123'))
    fireEvent.change(screen.getByTestId('approve-username'), { target: { value: 'host-1' } })
    fireEvent.click(screen.getByTestId('approve-submit-btn'))

    await waitFor(() => expect(screen.getByTestId('approve-error')).toBeInTheDocument())
    expect(screen.getByTestId('approve-error')).toHaveTextContent('403')
    expect(screen.getByTestId('approve-modal')).toBeInTheDocument()
  })
})

// ── Approve — root-scope-admin session ───────────────────────────────────────

describe('CredentialRequestsTab — approve as a root-scope admin session', () => {
  it('enables the admin and payload-signing markers', async () => {
    mockRootScopeSession({})
    renderAsRootScopeAdmin()
    await waitFor(() => expect(screen.getByTestId('credential-requests-table')).toBeInTheDocument())

    fireEvent.click(screen.getByTestId('approve-btn-creq-abc123'))

    expect(screen.getByTestId('marker-admin')).not.toBeDisabled()
    expect(screen.getByTestId('marker-payload-signing')).not.toBeDisabled()
    expect(screen.queryByTestId('marker-admin-reason')).toBeNull()
  })

  it('still offers no root-scope control even for a root-scope session', async () => {
    mockRootScopeSession({})
    renderAsRootScopeAdmin()
    await waitFor(() => expect(screen.getByTestId('credential-requests-table')).toBeInTheDocument())

    fireEvent.click(screen.getByTestId('approve-btn-creq-abc123'))

    expect(screen.queryByTestId('marker-root-scope')).toBeNull()
    expect(screen.queryByRole('checkbox', { name: /root.?scope/i })).toBeNull()
  })

  it('[REQUIRED] never sends a root-scope marker for every reachable combination of the marker controls', async () => {
    const combinations: Array<[string, boolean, boolean]> = [
      ['creq-1', false, false],
      ['creq-2', true, false],
      ['creq-3', false, true],
      ['creq-4', true, true],
    ]
    mockRootScopeSession({
      listResponse: () =>
        makeListResponse(combinations.map(([id]) => makeEntry({ id, public_key_fingerprint_short: `FP-${id}` }))),
    })
    renderAsRootScopeAdmin()
    await waitFor(() => expect(screen.getByTestId('credential-requests-table')).toBeInTheDocument())

    for (const [id, admin, signing] of combinations) {
      fireEvent.click(screen.getByTestId(`approve-btn-${id}`))
      fireEvent.change(screen.getByTestId('approve-username'), { target: { value: 'host-1' } })
      if (admin) fireEvent.click(screen.getByTestId('marker-admin'))
      if (signing) fireEvent.click(screen.getByTestId('marker-payload-signing'))

      const before = fetchMock.mock.calls.length
      fireEvent.click(screen.getByTestId('approve-submit-btn'))
      await waitFor(() => expect(screen.getByTestId(`status-${id}`)).toHaveTextContent(/approved/i))

      const approveCall = fetchMock.mock.calls
        .slice(before)
        .find((c) => String(c[0]).includes('/approve'))
      if (!approveCall) throw new Error('approve POST was never made')
      const rawBody = String((approveCall[1] as RequestInit).body)
      expect(rawBody).not.toContain('root_scope')
      expect(rawBody).not.toContain('rootScope')
      const parsedBody = JSON.parse(rawBody) as Record<string, unknown>
      expect(Object.keys(parsedBody)).not.toContain('grant_root_scope_marker')
    }
  })
})
