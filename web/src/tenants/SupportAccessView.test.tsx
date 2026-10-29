// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz

/*
 * SupportAccessView test suite (Issue #4724). The real AuthProvider and the real
 * passkey login ceremony establish the session (WebAuthn's browser API is stubbed
 * the same way TenantAdminView.test.tsx does); the controller is a fetch stub at
 * the network boundary.
 */
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'
import { act, cleanup, fireEvent, render, screen, waitFor, within } from '@testing-library/react'
import { MemoryRouter } from 'react-router'
import { AuthProvider, useAuth } from '../auth/AuthContext.tsx'
import { onStepUpRequired } from '../api/client.ts'
import SupportAccessView from './SupportAccessView.tsx'

const fetchMock = vi.fn<typeof fetch>()

beforeEach(() => {
  vi.stubGlobal('fetch', fetchMock)
  fetchMock.mockReset()
})

afterEach(() => {
  onStepUpRequired(null)
  vi.unstubAllGlobals()
  cleanup()
})

function jsonResponse(status: number, body: unknown, headers: Record<string, string> = {}) {
  return new Response(JSON.stringify(body), { status, headers: { 'Content-Type': 'application/json', ...headers } })
}

/**
 * The step-up challenge. Tests using it clear the ceremony listener first, so
 * apiFetch hands back the original 401, which is what a cancelled ceremony yields.
 */
const stepUpChallenge = () =>
  jsonResponse(401, { error: { code: 'STEP_UP', message: 'step-up required' } }, { 'WWW-Authenticate': 'CFGMS-StepUp presence="required"' })

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

function SignInHarness() {
  const { login, status } = useAuth()
  return (
    <div>
      <output data-testid="auth-status">{status}</output>
      <button type="button" data-testid="do-login" onClick={() => void login('admin')}>
        sign in
      </button>
    </div>
  )
}

type Handler = (url: string, init?: RequestInit) => Response | undefined

function renderSession(session: { tenant_id: string; root_scope: boolean }, handler: Handler) {
  vi.stubGlobal('navigator', { credentials: { get: vi.fn().mockResolvedValue(makePublicKeyCredential()) } })
  fetchMock.mockImplementation((input, init) => {
    const url = String(input)
    if (url.endsWith('/api/v1/web/csrf')) {
      document.cookie = '__Host-cfgms_csrf_pre=pre-tok; path=/; Secure'
      return Promise.resolve(new Response(null, { status: 204 }))
    }
    if (url.endsWith('/api/v1/web/passkey/login/begin')) {
      return Promise.resolve(
        jsonResponse(200, {
          publicKey: { challenge: 'Y2hhbGxlbmdlLWJ5dGVz', timeout: 60000, rpId: 'localhost', allowCredentials: [], userVerification: 'required' },
        }),
      )
    }
    if (url.endsWith('/api/v1/web/passkey/login/finish')) {
      return Promise.resolve(jsonResponse(200, { data: { ok: true, username: 'admin', ...session } }))
    }
    return Promise.resolve(handler(url, init as RequestInit | undefined) ?? jsonResponse(404, {}))
  })
  render(
    <MemoryRouter>
      <AuthProvider>
        <SignInHarness />
        <SupportAccessView />
      </AuthProvider>
    </MemoryRouter>,
  )
}

async function signIn() {
  act(() => screen.getByTestId('do-login').click())
  await waitFor(() => expect(screen.getByTestId('auth-status')).toHaveTextContent('signedIn'))
}

const mspSession = { tenant_id: 'msp-a', root_scope: false }
const grantsUrl = '/api/v1/tenants/msp-a/access-grants'
const contactsUrl = '/api/v1/tenants/msp-a/admin-contacts'
const future = () => new Date(Date.now() + 3 * 3_600_000).toISOString()
const past = () => new Date(Date.now() - 3_600_000).toISOString()

function crossing(over: Record<string, unknown> = {}) {
  return {
    id: 'g-1',
    tenant_id: 'msp-a',
    principal_id: '',
    principal_name: '',
    kind: 'grant',
    granted_by: 'msp-owner',
    justification: '',
    reason_category: '',
    approval_state: 'approved',
    created_at: past(),
    expires_at: future(),
    revoked_at: null,
    status: 'active',
    ...over,
  }
}

const breakGlass = (over: Record<string, unknown> = {}) =>
  crossing({
    id: 'bg-1',
    kind: 'break_glass',
    principal_id: 'p-root',
    principal_name: 'root-ops',
    granted_by: 'p-root',
    justification: 'Locked out <b>badly</b>',
    reason_category: 'account_recovery',
    ...over,
  })

describe('SupportAccessView — root session', () => {
  it('shows the explanation and makes no grants or contacts request', async () => {
    renderSession({ tenant_id: '', root_scope: true }, () => undefined)
    await signIn()
    expect(screen.getByTestId('root-state')).toBeInTheDocument()
    expect(screen.queryByTestId('give-access-btn')).not.toBeInTheDocument()
    expect(screen.queryByTestId('contacts-panel')).not.toBeInTheDocument()
    const urls = fetchMock.mock.calls.map((c) => String(c[0]))
    expect(urls.some((u) => u.includes('access-grants') || u.includes('admin-contacts'))).toBe(false)
  })
})

describe('SupportAccessView — issue a grant', () => {
  it('posts duration_minutes only, refreshes the list, and defaults to 4 hours', async () => {
    let list = [] as ReturnType<typeof crossing>[]
    let body: unknown = null
    renderSession(mspSession, (url, init) => {
      if (url === grantsUrl && init?.method === 'POST') {
        body = JSON.parse(String(init.body))
        list = [crossing()]
        return jsonResponse(201, { data: crossing() })
      }
      if (url === grantsUrl) return jsonResponse(200, { data: list })
      if (url === contactsUrl) return jsonResponse(200, { data: { contacts: [] } })
      return undefined
    })
    await signIn()
    await screen.findByTestId('crossing-empty')
    fireEvent.click(screen.getByTestId('give-access-btn'))
    expect(await screen.findByTestId('crossing-row')).toHaveTextContent('All root support')
    expect(body).toEqual({ duration_minutes: 240 })
    expect(screen.getByTestId('issue-done')).toHaveTextContent('4 h')
  })

  it('sends the chosen duration', async () => {
    let body: unknown = null
    renderSession(mspSession, (url, init) => {
      if (url === grantsUrl && init?.method === 'POST') {
        body = JSON.parse(String(init.body))
        return jsonResponse(201, { data: crossing() })
      }
      if (url === grantsUrl) return jsonResponse(200, { data: [] })
      if (url === contactsUrl) return jsonResponse(200, { data: { contacts: [] } })
      return undefined
    })
    await signIn()
    await screen.findByTestId('crossing-empty')
    fireEvent.click(screen.getByTestId('duration-24'))
    fireEvent.click(screen.getByTestId('give-access-btn'))
    await waitFor(() => expect(body).toEqual({ duration_minutes: 1440 }))
  })

  it('shows a server rejection inline', async () => {
    renderSession(mspSession, (url, init) => {
      if (url === grantsUrl && init?.method === 'POST') {
        return jsonResponse(400, { error: { code: 'INVALID_DURATION', message: 'duration_minutes must be 60, 240, 480 or 1440' } })
      }
      if (url === grantsUrl) return jsonResponse(200, { data: [] })
      if (url === contactsUrl) return jsonResponse(200, { data: { contacts: [] } })
      return undefined
    })
    await signIn()
    await screen.findByTestId('crossing-empty')
    fireEvent.click(screen.getByTestId('give-access-btn'))
    expect(await screen.findByTestId('issue-error')).toHaveTextContent('duration_minutes must be')
  })

  it('words a cancelled step-up (original 401) as a cancelled passkey check', async () => {
    renderSession(mspSession, (url, init) => {
      if (url === grantsUrl && init?.method === 'POST') return stepUpChallenge()
      if (url === grantsUrl) return jsonResponse(200, { data: [] })
      if (url === contactsUrl) return jsonResponse(200, { data: { contacts: [] } })
      return undefined
    })
    await signIn()
    await screen.findByTestId('crossing-empty')
    onStepUpRequired(null)
    fireEvent.click(screen.getByTestId('give-access-btn'))
    expect(await screen.findByTestId('issue-error')).toHaveTextContent('passkey check was cancelled')
  })
})

describe('SupportAccessView — list and revoke', () => {
  it('renders grant and break-glass rows with text nodes only', async () => {
    renderSession(mspSession, (url) => {
      if (url === grantsUrl) return jsonResponse(200, { data: [breakGlass(), crossing(), crossing({ id: 'g-2', status: 'expired' })] })
      if (url === contactsUrl) return jsonResponse(200, { data: { contacts: [] } })
      return undefined
    })
    await signIn()
    await screen.findAllByTestId('crossing-row')
    // Default filter shows active and pending only.
    expect(screen.getAllByTestId('crossing-row')).toHaveLength(2)
    expect(screen.getByTestId('crossing-count')).toHaveTextContent('2 open · 3 total')
    const bg = screen.getAllByTestId('crossing-row').find((r) => r.getAttribute('data-crossing-id') === 'bg-1')!
    expect(bg).toHaveTextContent('Break-glass')
    expect(bg).toHaveTextContent('Active')
    expect(bg).toHaveTextContent('root-ops')
    expect(bg).toHaveTextContent('Account recovery')
    expect(bg).toHaveTextContent('Locked out <b>badly</b>')
    expect(bg.querySelector('b')).toBeNull()
    const grant = screen.getAllByTestId('crossing-row').find((r) => r.getAttribute('data-crossing-id') === 'g-1')!
    expect(grant).toHaveTextContent('All root support')
    expect(grant).toHaveTextContent('given by msp-owner')
    fireEvent.click(screen.getByTestId('filter-all'))
    expect(screen.getAllByTestId('crossing-row')).toHaveLength(3)
  })

  it('revokes a grant after confirmation and shows it revoked', async () => {
    let revoked = false
    let deleteUrl = ''
    renderSession(mspSession, (url, init) => {
      if (url === `${grantsUrl}/g-1` && init?.method === 'DELETE') {
        revoked = true
        deleteUrl = url
        return jsonResponse(200, { data: crossing({ status: 'revoked' }) })
      }
      if (url === grantsUrl) return jsonResponse(200, { data: [crossing({ status: revoked ? 'revoked' : 'active', revoked_at: revoked ? past() : null })] })
      if (url === contactsUrl) return jsonResponse(200, { data: { contacts: [] } })
      return undefined
    })
    await signIn()
    await screen.findByTestId('crossing-row')
    fireEvent.click(screen.getByTestId('revoke-btn'))
    const confirm = screen.getByTestId('confirm-row')
    expect(confirm).toHaveTextContent('Revoke support access?')
    expect(revoked).toBe(false)
    fireEvent.click(within(confirm).getByTestId('confirm-revoke-btn'))
    await waitFor(() => expect(screen.queryByTestId('confirm-row')).not.toBeInTheDocument())
    expect(deleteUrl).toBe(`${grantsUrl}/g-1`)
    fireEvent.click(await screen.findByTestId('filter-all'))
    expect(await screen.findByTestId('crossing-row')).toHaveTextContent('Revoked')
    expect(screen.queryByTestId('revoke-btn')).not.toBeInTheDocument()
  })

  it('Keep dismisses the confirmation without a request', async () => {
    renderSession(mspSession, (url) => {
      if (url === grantsUrl) return jsonResponse(200, { data: [crossing()] })
      if (url === contactsUrl) return jsonResponse(200, { data: { contacts: [] } })
      return undefined
    })
    await signIn()
    await screen.findByTestId('crossing-row')
    fireEvent.click(screen.getByTestId('revoke-btn'))
    fireEvent.click(screen.getByTestId('confirm-keep-btn'))
    expect(screen.queryByTestId('confirm-row')).not.toBeInTheDocument()
    expect(fetchMock.mock.calls.some((c) => (c[1] as RequestInit | undefined)?.method === 'DELETE')).toBe(false)
  })

  it('uses the emergency-elevation confirmation for break-glass and Deny for a pending one', async () => {
    renderSession(mspSession, (url) => {
      if (url === grantsUrl) {
        return jsonResponse(200, {
          data: [breakGlass(), breakGlass({ id: 'bg-2', status: 'pending', approval_state: 'pending', principal_name: 'root-dana' })],
        })
      }
      if (url === contactsUrl) return jsonResponse(200, { data: { contacts: [] } })
      return undefined
    })
    await signIn()
    const buttons = await screen.findAllByTestId('revoke-btn')
    expect(buttons.map((b) => b.textContent)).toEqual(['End now', 'Deny'])
    fireEvent.click(buttons[0]!)
    expect(screen.getByTestId('confirm-row')).toHaveTextContent('ends an emergency elevation immediately')
    expect(screen.getByTestId('confirm-revoke-btn')).toHaveTextContent('End elevation')
    fireEvent.click(screen.getByTestId('confirm-keep-btn'))
    fireEvent.click(screen.getAllByTestId('revoke-btn')[1]!)
    expect(screen.getByTestId('confirm-row')).toHaveTextContent('Deny this emergency elevation?')
  })

  it('shows a revoke failure inline and keeps the row', async () => {
    renderSession(mspSession, (url, init) => {
      if (init?.method === 'DELETE') return stepUpChallenge()
      if (url === grantsUrl) return jsonResponse(200, { data: [crossing()] })
      if (url === contactsUrl) return jsonResponse(200, { data: { contacts: [] } })
      return undefined
    })
    await signIn()
    await screen.findByTestId('crossing-row')
    onStepUpRequired(null)
    fireEvent.click(screen.getByTestId('revoke-btn'))
    fireEvent.click(screen.getByTestId('confirm-revoke-btn'))
    expect(await screen.findByTestId('revoke-error')).toHaveTextContent('passkey check was cancelled')
    expect(screen.getByTestId('crossing-row')).toBeInTheDocument()
  })

  it('shows loading, then an error with retry, for the list', async () => {
    let fail = true
    renderSession(mspSession, (url) => {
      if (url === grantsUrl) return fail ? jsonResponse(500, {}) : jsonResponse(200, { data: [crossing()] })
      if (url === contactsUrl) return jsonResponse(200, { data: { contacts: [] } })
      return undefined
    })
    await signIn()
    expect(await screen.findByTestId('crossing-error')).toBeInTheDocument()
    fail = false
    fireEvent.click(screen.getByTestId('crossing-retry-btn'))
    expect(await screen.findByTestId('crossing-row')).toBeInTheDocument()
  })

  it('shows the empty state when there are no crossings', async () => {
    renderSession(mspSession, (url) => {
      if (url === grantsUrl) return jsonResponse(200, { data: [] })
      if (url === contactsUrl) return jsonResponse(200, { data: { contacts: [] } })
      return undefined
    })
    await signIn()
    expect(await screen.findByTestId('crossing-empty')).toBeInTheDocument()
  })
})

describe('SupportAccessView — contacts', () => {
  const contactsHandler = (state: { contacts: string[] }, onPut?: (init: RequestInit) => Response | undefined): Handler =>
    (url, init) => {
      if (url === grantsUrl) return jsonResponse(200, { data: [] })
      if (url === contactsUrl && init?.method === 'PUT') {
        const custom = onPut?.(init)
        if (custom) return custom
        state.contacts = (JSON.parse(String(init.body)) as { contacts: string[] }).contacts
        return jsonResponse(200, { data: { contacts: state.contacts } })
      }
      if (url === contactsUrl) return jsonResponse(200, { data: { contacts: state.contacts } })
      return undefined
    }

  it('add, remove and save send the full list', async () => {
    const state = { contacts: ['a@acme-corp.example', 'b@acme-corp.example'] }
    renderSession(mspSession, contactsHandler(state))
    await signIn()
    await screen.findByTestId('contacts-list')
    expect(screen.getByTestId('contacts-save-btn')).toBeDisabled()
    fireEvent.change(screen.getByTestId('contact-input'), { target: { value: ' c@acme-corp.example ' } })
    fireEvent.click(screen.getByTestId('contact-add-btn'))
    fireEvent.click(screen.getByRole('button', { name: 'Remove a@acme-corp.example' }))
    expect(screen.getAllByTestId('contact-item')).toHaveLength(2)
    expect(screen.getByText('Unsaved changes')).toBeInTheDocument()
    fireEvent.click(screen.getByTestId('contacts-save-btn'))
    expect(await screen.findByTestId('contacts-saved')).toBeInTheDocument()
    const put = fetchMock.mock.calls.find((c) => (c[1] as RequestInit | undefined)?.method === 'PUT')!
    expect(JSON.parse(String((put[1] as RequestInit).body))).toEqual({
      contacts: ['b@acme-corp.example', 'c@acme-corp.example'],
    })
    expect(screen.getByTestId('contacts-save-btn')).toBeDisabled()
    expect(screen.getAllByTestId('contact-item')).toHaveLength(2)
  })

  it('shows a server validation error inline and keeps the draft', async () => {
    const state = { contacts: [] as string[] }
    renderSession(
      mspSession,
      contactsHandler(state, () =>
        jsonResponse(400, { error: { code: 'INVALID_CONTACTS', message: 'invalid administrator contacts: ops@acme-corp is not a valid email address' } }),
      ),
    )
    await signIn()
    await screen.findByTestId('contacts-empty')
    fireEvent.change(screen.getByTestId('contact-input'), { target: { value: 'ops@acme-corp' } })
    fireEvent.click(screen.getByTestId('contact-add-btn'))
    fireEvent.click(screen.getByTestId('contacts-save-btn'))
    expect(await screen.findByTestId('contacts-save-error')).toHaveTextContent('ops@acme-corp is not a valid email address')
    expect(screen.getByTestId('contact-item')).toHaveTextContent('ops@acme-corp')
    expect(screen.getByTestId('contacts-save-btn')).not.toBeDisabled()
  })

  it('shows the email note, the empty state, and an error with retry', async () => {
    let fail = true
    renderSession(mspSession, (url) => {
      if (url === grantsUrl) return jsonResponse(200, { data: [] })
      if (url === contactsUrl) return fail ? jsonResponse(500, {}) : jsonResponse(200, { data: { contacts: [] } })
      return undefined
    })
    await signIn()
    expect(await screen.findByTestId('contacts-error')).toBeInTheDocument()
    fail = false
    fireEvent.click(screen.getByTestId('contacts-retry-btn'))
    expect(await screen.findByTestId('contacts-empty')).toBeInTheDocument()
    expect(screen.getByTestId('contacts-panel')).toHaveTextContent('emailed to these addresses when the controller has email configured')
  })

  it('renders a contact containing markup as literal text', async () => {
    const state = { contacts: ['<i>x</i>@acme-corp.example'] }
    renderSession(mspSession, contactsHandler(state))
    await signIn()
    const item = await screen.findByTestId('contact-item')
    expect(item).toHaveTextContent('<i>x</i>@acme-corp.example')
    expect(item.querySelector('i')).toBeNull()
  })
})

describe('SupportAccessView — break-glass second approval', () => {
  const rootSession = { tenant_id: 'msp-a', root_scope: true }
  const approveUrl = '/api/v1/tenants/msp-a/break-glass/bg-2/approve'
  const pendingRow = (over: Record<string, unknown> = {}) =>
    breakGlass({ id: 'bg-2', status: 'pending', approval_state: 'pending', principal_name: 'root-dana', ...over })
  const envelope = (data: unknown) => ({ data, timestamp: new Date().toISOString() })
  const presenceChallenge = () =>
    jsonResponse(
      401,
      { error: 'step_up_required', required_assurance: 'strong', presence_required: true },
      {
        'WWW-Authenticate':
          'CFGMS-StepUp realm="cfgms", required="strong", presence="required", permission="tenant:crossing-approve-break-glass"',
      },
    )
  const presenceEndpoints = (url: string) => {
    if (url.includes('presence/begin')) {
      return jsonResponse(
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
      )
    }
    if (url.includes('presence/finish')) return jsonResponse(200, envelope({ presence_token: 'tap-token-1', expires_in: 30 }))
    return undefined
  }
  const approvePosts = () =>
    fetchMock.mock.calls.filter((c) => String(c[0]) === approveUrl && (c[1] as RequestInit | undefined)?.method === 'POST')

  it('approve sends X-Presence-Token after the tap', async () => {
    let state = 'pending'
    renderSession(rootSession, (url, init) => {
      const p = presenceEndpoints(url)
      if (p) return p
      if (url === approveUrl) {
        if (new Headers(init?.headers).get('X-Presence-Token') !== 'tap-token-1') return presenceChallenge()
        state = 'active'
        return jsonResponse(200, { data: { ok: true } })
      }
      if (url === grantsUrl) {
        return jsonResponse(200, {
          data: [state === 'pending' ? pendingRow() : pendingRow({ status: 'active', approval_state: 'approved' })],
        })
      }
      return undefined
    })
    await signIn()
    fireEvent.click(await screen.findByTestId('approve-btn'))
    await waitFor(() => expect(screen.getByTestId('step-up-overlay')).toBeInTheDocument())
    expect(approvePosts()).toHaveLength(1)
    fireEvent.click(await screen.findByTestId('step-up-verify-btn'))
    await waitFor(() => expect(approvePosts()).toHaveLength(2))
    expect(new Headers((approvePosts()[1]![1] as RequestInit).headers).get('X-Presence-Token')).toBe('tap-token-1')
    await waitFor(() => expect(screen.getByTestId('crossing-row')).toHaveTextContent('Active'))
    expect(screen.queryByTestId('approve-btn')).not.toBeInTheDocument()
  })

  it('approve cancelled tap shows a message and sends no second request', async () => {
    renderSession(rootSession, (url) => {
      const p = presenceEndpoints(url)
      if (p) return p
      if (url === approveUrl) return presenceChallenge()
      if (url === grantsUrl) return jsonResponse(200, { data: [pendingRow()] })
      return undefined
    })
    await signIn()
    fireEvent.click(await screen.findByTestId('approve-btn'))
    await waitFor(() => expect(screen.getByTestId('step-up-overlay')).toBeInTheDocument())
    fireEvent.click(await screen.findByTestId('step-up-cancel-btn'))
    expect(await screen.findByTestId('approve-error')).toHaveTextContent('passkey check was cancelled')
    expect(approvePosts()).toHaveLength(1)
  })

  it('approve is disabled for the requester', async () => {
    renderSession(rootSession, (url) => {
      if (url === grantsUrl) return jsonResponse(200, { data: [pendingRow({ principal_name: 'admin' })] })
      return undefined
    })
    await signIn()
    const btn = await screen.findByTestId('approve-btn')
    expect(btn).toBeDisabled()
    expect(screen.getByTestId('approve-requester-note')).toHaveTextContent('different root admin')
    fireEvent.click(btn)
    expect(approvePosts()).toHaveLength(0)
  })

  it('approve hidden for a non-root-scope principal', async () => {
    renderSession(mspSession, (url) => {
      if (url === grantsUrl) return jsonResponse(200, { data: [pendingRow()] })
      if (url === contactsUrl) return jsonResponse(200, { data: { contacts: [] } })
      return undefined
    })
    await signIn()
    await screen.findByTestId('crossing-row')
    expect(screen.queryByTestId('approve-btn')).not.toBeInTheDocument()
  })

  it('approve is not offered on a non-pending row', async () => {
    renderSession(rootSession, (url) => {
      if (url === grantsUrl) return jsonResponse(200, { data: [breakGlass()] })
      return undefined
    })
    await signIn()
    await screen.findByTestId('crossing-row')
    expect(screen.queryByTestId('approve-btn')).not.toBeInTheDocument()
  })

  it('renders server SAME_APPROVER 403 even when the client check passed', async () => {
    renderSession(rootSession, (url, init) => {
      if (url === approveUrl && init?.method === 'POST') {
        return jsonResponse(403, { error: { code: 'SAME_APPROVER', message: 'The requester cannot approve their own break-glass.' } })
      }
      if (url === grantsUrl) return jsonResponse(200, { data: [pendingRow()] })
      return undefined
    })
    await signIn()
    fireEvent.click(await screen.findByTestId('approve-btn'))
    expect(await screen.findByTestId('approve-error')).toHaveTextContent('The requester cannot approve their own break-glass.')
  })

  it('renders a 409 NOT_PENDING message', async () => {
    renderSession(rootSession, (url, init) => {
      if (url === approveUrl && init?.method === 'POST') {
        return jsonResponse(409, { error: { code: 'NOT_PENDING', message: 'This break-glass is no longer pending.' } })
      }
      if (url === grantsUrl) return jsonResponse(200, { data: [pendingRow()] })
      return undefined
    })
    await signIn()
    fireEvent.click(await screen.findByTestId('approve-btn'))
    expect(await screen.findByTestId('approve-error')).toHaveTextContent('no longer pending')
  })
})
