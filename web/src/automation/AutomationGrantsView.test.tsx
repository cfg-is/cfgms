// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz

/*
 * AutomationGrantsView test suite (Issue #5855, Epic #5421). Real AuthProvider,
 * apiFetch and StepUpModal; only global fetch is stubbed at the network edge.
 */
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'
import { cleanup, fireEvent, render, screen, waitFor } from '@testing-library/react'
import { MemoryRouter } from 'react-router'
import { AuthProvider } from '../auth/AuthContext.tsx'
import AutomationGrantsView from './AutomationGrantsView.tsx'

const fetchMock = vi.fn<typeof fetch>()
const grantsUrl = '/api/v1/automation/grants'

beforeEach(() => {
  fetchMock.mockReset()
  vi.stubGlobal('fetch', fetchMock)
})

afterEach(() => {
  vi.unstubAllGlobals()
  cleanup()
  localStorage.clear()
  sessionStorage.clear()
})

function jsonResponse(status: number, body: unknown = {}, headers: Record<string, string> = {}): Response {
  return new Response(status === 204 ? null : JSON.stringify(body), {
    status,
    headers: { 'Content-Type': 'application/json', ...headers },
  })
}

const future = () => new Date(Date.now() + 30 * 86_400_000).toISOString()
const past = () => new Date(Date.now() - 86_400_000).toISOString()

function makeGrant(overrides: Partial<Record<string, unknown>> = {}) {
  return {
    id: 'grant-abc123',
    tenant_id: 'msp-a',
    name: 'nightly-patching',
    created_by: 'admin',
    created_at: '2026-10-01T00:00:00Z',
    expires_at: future(),
    ...overrides,
  }
}

const CREDENTIAL = 'cfgms_grant_SECRETCREDENTIAL123'

function renderView() {
  return render(
    <MemoryRouter>
      <AuthProvider>
        <AutomationGrantsView />
      </AuthProvider>
    </MemoryRouter>,
  )
}

function callsTo(method: string) {
  return fetchMock.mock.calls.filter(([u, init]) => {
    return String(u).startsWith(grantsUrl) && (init?.method ?? 'GET') === method
  })
}

async function createGrant(name = 'nightly-patching', date = '2026-12-01', tenant?: string) {
  fireEvent.change(await screen.findByTestId('grant-name'), { target: { value: name } })
  if (tenant !== undefined) fireEvent.change(screen.getByTestId('grant-tenant'), { target: { value: tenant } })
  fireEvent.change(screen.getByTestId('grant-expiry'), { target: { value: date } })
  fireEvent.click(screen.getByTestId('grant-create-btn'))
}

const created = () => ({ data: { grant: makeGrant(), credential: CREDENTIAL } })

describe('AutomationGrantsView list', () => {
  it('shows each grant with a status from the server fields and never a credential', async () => {
    fetchMock.mockResolvedValue(
      jsonResponse(200, {
        data: {
          grants: [
            makeGrant({ credential: CREDENTIAL }),
            makeGrant({ id: 'grant-old', expires_at: past() }),
            makeGrant({ id: 'grant-rev', revoked_at: '2026-10-02T00:00:00Z', revoked_by: 'admin' }),
          ],
          count: 3,
        },
      }),
    )
    renderView()
    const rows = await screen.findAllByTestId('grant-row')
    expect(rows).toHaveLength(3)
    expect(screen.getAllByTestId('grant-id')[0]).toHaveTextContent('grant-abc123')
    expect(screen.getAllByTestId('grant-name-cell')[0]).toHaveTextContent('nightly-patching')
    expect(screen.getAllByTestId('grant-tenant-cell')[0]).toHaveTextContent('msp-a')
    expect(screen.getAllByTestId('grant-status').map((n) => n.textContent)).toEqual([
      'active',
      'expired',
      'revoked',
    ])
    // Only a grant that is not revoked can be revoked.
    expect(screen.getByTestId('grant-revoke-btn-grant-abc123')).toBeInTheDocument()
    expect(screen.getByTestId('grant-revoke-btn-grant-old')).toBeInTheDocument()
    expect(screen.queryByTestId('grant-revoke-btn-grant-rev')).toBeNull()
    expect(document.body.textContent).not.toContain(CREDENTIAL)
  })

  it('renders markup in wire values as text only', async () => {
    fetchMock.mockResolvedValue(
      jsonResponse(200, { data: { grants: [makeGrant({ name: '<img src=x onerror=alert(1)>' })], count: 1 } }),
    )
    renderView()
    expect(await screen.findByTestId('grant-name-cell')).toHaveTextContent('<img src=x onerror=alert(1)>')
    expect(document.querySelector('img')).toBeNull()
  })

  it('shows the empty state and an error card on failure', async () => {
    fetchMock.mockResolvedValueOnce(jsonResponse(200, { data: { grants: [], count: 0 } }))
    renderView()
    expect(await screen.findByTestId('grants-empty')).toBeInTheDocument()
    cleanup()
    fetchMock.mockResolvedValueOnce(jsonResponse(500))
    renderView()
    expect(await screen.findByText(/couldn't load automation grants/i)).toBeInTheDocument()
  })
})

describe('AutomationGrantsView create', () => {
  it('shows the controller expiry cap on the form', async () => {
    fetchMock.mockResolvedValue(jsonResponse(200, { data: { grants: [], count: 0 } }))
    renderView()
    expect(await screen.findByTestId('grant-expiry-cap')).toHaveTextContent('90 days')
    expect(screen.getByTestId('grant-expiry')).toHaveAttribute('max')
  })

  it('create shows the credential once and clears it from the DOM and state on close', async () => {
    const writeText = vi.fn().mockResolvedValue(undefined)
    vi.stubGlobal('navigator', { clipboard: { writeText } })
    let made = false
    fetchMock.mockImplementation((_url, init) => {
      if (init?.method === 'POST') {
        made = true
        return Promise.resolve(jsonResponse(201, created()))
      }
      return Promise.resolve(jsonResponse(200, { data: { grants: made ? [makeGrant()] : [], count: 0 } }))
    })
    renderView()
    await createGrant()

    const field = (await screen.findByTestId('grant-credential-value')) as HTMLInputElement
    expect(field.value).toBe(CREDENTIAL)
    expect(field.readOnly).toBe(true)

    const init = callsTo('POST')[0]?.[1]
    expect(JSON.parse(String(init?.body))).toEqual({ name: 'nightly-patching', expires_at: '2026-12-01T00:00:00.000Z' })

    fireEvent.click(screen.getByTestId('grant-copy-btn'))
    await waitFor(() => expect(writeText).toHaveBeenCalledWith(CREDENTIAL))

    // The refreshed list never carries the credential.
    await screen.findByTestId('grant-row')
    expect(screen.getAllByDisplayValue(CREDENTIAL)).toHaveLength(1)

    fireEvent.click(screen.getByTestId('grant-credential-close-btn'))
    expect(screen.queryByTestId('grant-credential-panel')).toBeNull()
    expect(document.body.textContent).not.toContain(CREDENTIAL)
    expect(screen.queryByDisplayValue(CREDENTIAL)).toBeNull()
    expect(JSON.stringify({ ...localStorage })).not.toContain(CREDENTIAL)
    expect(JSON.stringify({ ...sessionStorage })).not.toContain(CREDENTIAL)
    expect(window.location.href).not.toContain(CREDENTIAL)
  })

  it('sends the tenant the admin entered', async () => {
    fetchMock.mockImplementation((_url, init) =>
      Promise.resolve(
        init?.method === 'POST' ? jsonResponse(201, created()) : jsonResponse(200, { data: { grants: [] } }),
      ),
    )
    renderView()
    await createGrant('g', '2026-12-01', ' client-1 ')
    await screen.findByTestId('grant-credential-value')
    expect(JSON.parse(String(callsTo('POST')[0]?.[1]?.body)).tenant_id).toBe('client-1')
  })

  it('shows the server error verbatim and no credential panel', async () => {
    fetchMock.mockImplementation((_url, init) =>
      Promise.resolve(
        init?.method === 'POST'
          ? jsonResponse(400, { error: { message: 'expiry exceeds the maximum lifetime of 2160h0m0s' } })
          : jsonResponse(200, { data: { grants: [] } }),
      ),
    )
    renderView()
    await createGrant()
    expect(await screen.findByTestId('grant-create-error')).toHaveTextContent(/exceeds the maximum lifetime/)
    expect(screen.queryByTestId('grant-credential-panel')).toBeNull()
  })

  it('requires a name and an expiry date before sending', async () => {
    fetchMock.mockResolvedValue(jsonResponse(200, { data: { grants: [] } }))
    renderView()
    await createGrant('  ')
    expect(await screen.findByTestId('grant-create-error')).toHaveTextContent(/name is required/i)
    fireEvent.change(screen.getByTestId('grant-name'), { target: { value: 'g' } })
    fireEvent.change(screen.getByTestId('grant-expiry'), { target: { value: '' } })
    fireEvent.click(screen.getByTestId('grant-create-btn'))
    expect(await screen.findByText(/expiry date is required/i)).toBeInTheDocument()
    expect(callsTo('POST')).toHaveLength(0)
  })

  it('a 401 step_up_required runs the presence modal and retries with the tap token', async () => {
    const cred = {
      id: 'cred-id-b64u',
      type: 'public-key',
      rawId: new TextEncoder().encode('cred-id-b64u').buffer,
      response: {
        clientDataJSON: new TextEncoder().encode('{"type":"webauthn.get"}').buffer,
        authenticatorData: new TextEncoder().encode('ad').buffer,
        signature: new TextEncoder().encode('sig').buffer,
        userHandle: null,
      },
      getClientExtensionResults: () => ({}),
      authenticatorAttachment: null,
      toJSON: () => ({}),
    }
    vi.stubGlobal('navigator', { credentials: { get: vi.fn().mockResolvedValue(cred) } })
    const envelope = (data: unknown) => ({ data, timestamp: new Date().toISOString() })
    fetchMock.mockImplementation((url, init) => {
      const u = String(url)
      if (u.includes('presence/begin')) {
        return Promise.resolve(
          jsonResponse(
            200,
            envelope({
              publicKey: {
                challenge: 'Y2hhbGxlbmdl',
                timeout: 60000,
                rpId: 'localhost',
                allowCredentials: [{ type: 'public-key', id: 'Y3JlZA', transports: ['internal'] }],
                userVerification: 'required',
              },
            }),
          ),
        )
      }
      if (u.includes('presence/finish')) {
        return Promise.resolve(jsonResponse(200, envelope({ presence_token: 'tap-token-1', expires_in: 30 })))
      }
      if (init?.method === 'POST') {
        if (new Headers(init.headers).get('X-Presence-Token') !== 'tap-token-1') {
          return Promise.resolve(
            jsonResponse(
              401,
              { error: 'step_up_required', required_assurance: 'strong', presence_required: true },
              {
                'WWW-Authenticate':
                  'CFGMS-StepUp realm="cfgms", required="strong", presence="required", permission="automation-grant:create"',
              },
            ),
          )
        }
        return Promise.resolve(jsonResponse(201, created()))
      }
      return Promise.resolve(jsonResponse(200, { data: { grants: [] } }))
    })

    renderView()
    await createGrant()
    await waitFor(() => expect(screen.getByTestId('step-up-overlay')).toBeInTheDocument())
    expect(callsTo('POST')).toHaveLength(1)
    // Nothing is created until the admin taps.
    expect(screen.queryByTestId('grant-credential-panel')).toBeNull()
    fireEvent.click(await screen.findByTestId('step-up-verify-btn'))

    expect(await screen.findByTestId('grant-credential-value')).toHaveProperty('value', CREDENTIAL)
    const posts = callsTo('POST')
    expect(posts).toHaveLength(2)
    expect(new Headers(posts[1]?.[1]?.headers).get('X-Presence-Token')).toBe('tap-token-1')
  })

  it('a cancelled presence tap creates nothing and shows no credential', async () => {
    fetchMock.mockImplementation((_url, init) =>
      Promise.resolve(
        init?.method === 'POST'
          ? jsonResponse(
              401,
              { error: 'step_up_required', required_assurance: 'strong', presence_required: true },
              { 'WWW-Authenticate': 'CFGMS-StepUp realm="cfgms", required="strong", presence="required"' },
            )
          : jsonResponse(200, { data: { grants: [] } }),
      ),
    )
    renderView()
    await createGrant()
    await waitFor(() => expect(screen.getByTestId('step-up-overlay')).toBeInTheDocument())
    fireEvent.click(await screen.findByTestId('step-up-cancel-btn'))
    expect(await screen.findByTestId('grant-create-error')).toBeInTheDocument()
    expect(callsTo('POST')).toHaveLength(1)
    expect(screen.queryByTestId('grant-credential-panel')).toBeNull()
  })
})

describe('AutomationGrantsView revoke', () => {
  it('requires the inline confirm before sending and updates the row afterwards', async () => {
    let revoked = false
    fetchMock.mockImplementation((_url, init) => {
      if (init?.method === 'DELETE') {
        revoked = true
        return Promise.resolve(jsonResponse(200, { data: { grant: makeGrant(), runs_ended: 0 } }))
      }
      return Promise.resolve(
        jsonResponse(200, {
          data: { grants: [makeGrant(revoked ? { revoked_at: '2026-11-09T00:00:00Z' } : {})], count: 1 },
        }),
      )
    })
    renderView()
    fireEvent.click(await screen.findByTestId('grant-revoke-btn-grant-abc123'))
    expect(screen.getByTestId('grant-confirm-row')).toBeInTheDocument()
    expect(callsTo('DELETE')).toHaveLength(0)

    // Cancel sends nothing and restores the button.
    fireEvent.click(screen.getByTestId('grant-cancel-btn'))
    expect(screen.queryByTestId('grant-confirm-row')).toBeNull()
    expect(callsTo('DELETE')).toHaveLength(0)

    fireEvent.click(screen.getByTestId('grant-revoke-btn-grant-abc123'))
    fireEvent.click(screen.getByTestId('grant-confirm-btn'))
    await waitFor(() => expect(callsTo('DELETE')).toHaveLength(1))
    expect(String(callsTo('DELETE')[0]?.[0])).toBe('/api/v1/automation/grants/grant-abc123')
    await waitFor(() => expect(screen.getByTestId('grant-status')).toHaveTextContent('revoked'))
    expect(screen.queryByTestId('grant-revoke-btn-grant-abc123')).toBeNull()
    expect(screen.queryByTestId('grant-confirm-row')).toBeNull()
  })

  it('shows the server error when revoke fails and keeps the row active', async () => {
    fetchMock.mockImplementation((_url, init) =>
      Promise.resolve(
        init?.method === 'DELETE'
          ? jsonResponse(503, { error: { message: 'Audit trail unavailable; grant not revoked' } })
          : jsonResponse(200, { data: { grants: [makeGrant()], count: 1 } }),
      ),
    )
    renderView()
    fireEvent.click(await screen.findByTestId('grant-revoke-btn-grant-abc123'))
    fireEvent.click(screen.getByTestId('grant-confirm-btn'))
    expect(await screen.findByTestId('grant-revoke-error')).toHaveTextContent('grant not revoked')
    expect(screen.getByTestId('grant-status')).toHaveTextContent('active')
  })
})
