// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz

/*
 * EmailDeliveryView test suite (Issue #6247). The real AuthProvider and the real
 * passkey login ceremony establish the session (WebAuthn's browser API is stubbed
 * the same way SupportAccessView.test.tsx does); the controller is a fetch stub at
 * the network boundary.
 */
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'
import { act, cleanup, fireEvent, render, screen, waitFor, within } from '@testing-library/react'
import { MemoryRouter } from 'react-router'
import { AuthProvider, useAuth } from '../auth/AuthContext.tsx'
import { onStepUpRequired, onTenantCrossingRequired } from '../api/client.ts'
import { TenantScopeProvider } from '../shell/TenantScopeContext.tsx'
import EmailDeliveryView from './EmailDeliveryView.tsx'

const fetchMock = vi.fn<typeof fetch>()

beforeEach(() => {
  vi.stubGlobal('fetch', fetchMock)
  fetchMock.mockReset()
})

afterEach(() => {
  onStepUpRequired(null)
  onTenantCrossingRequired(null)
  vi.unstubAllGlobals()
  localStorage.clear()
  sessionStorage.clear()
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

/** The tenant-crossing challenge a root read of an MSP gets. */
const crossingChallenge = () =>
  jsonResponse(
    401,
    { error: 'tenant_crossing_required', break_glass_endpoint: '/api/v1/tenants/msp-a/break-glass', reason_categories: ['account_recovery'] },
    { 'WWW-Authenticate': 'CFGMS-StepUp required="tenant-crossing"' },
  )

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

type Handler = (url: string, init?: RequestInit) => Response | Promise<Response> | undefined

function renderSession(session: { tenant_id: string; root_scope: boolean }, handler: Handler, scopePath = session.tenant_id) {
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
        <TenantScopeProvider rootPath={scopePath}>
          <EmailDeliveryView />
        </TenantScopeProvider>
      </AuthProvider>
    </MemoryRouter>,
  )
}

async function signIn() {
  act(() => screen.getByTestId('do-login').click())
  await waitFor(() => expect(screen.getByTestId('auth-status')).toHaveTextContent('signedIn'))
}

const mspSession = { tenant_id: 'msp-a', root_scope: false }
const rootSession = { tenant_id: '', root_scope: true }
const senderUrl = '/api/v1/tenants/msp-a/email-sender'
const testUrl = `${senderUrl}/test`

const stored = {
  configured: true,
  password_present: true,
  host: 'smtp.vendor-a.example',
  port: 587,
  tls_mode: 'starttls',
  from: 'ops@acme-corp.example',
  username: 'mailer',
}
const none = { configured: false, password_present: false, host: '', port: 0, tls_mode: '', from: '', username: '' }

const sentinel = 'zzz-sentinel-value-zzz'

function typeInto(testId: string, value: string) {
  fireEvent.change(screen.getByTestId(testId), { target: { value } })
}

function fillForm() {
  typeInto('host-input', 'smtp.vendor-a.example')
  typeInto('from-input', 'ops@acme-corp.example')
  typeInto('username-input', 'mailer')
}

describe('EmailDeliveryView — load', () => {
  it('shows the signed-in MSP admin their own sender with a saved-password chip and no password value', async () => {
    renderSession(mspSession, (url) => (url === senderUrl ? jsonResponse(200, { data: stored }) : undefined))
    expect(screen.getByTestId('no-tenant')).toBeInTheDocument()
    await signIn()
    const panel = await screen.findByTestId('sender-in-use')
    expect(panel).toHaveTextContent("msp-a's own sender")
    expect(panel).toHaveTextContent('In use')
    const details = screen.getByTestId('sender-details')
    expect(details).toHaveTextContent('smtp.vendor-a.example')
    expect(details).toHaveTextContent('587 · STARTTLS')
    expect(details).toHaveTextContent('ops@acme-corp.example')
    expect(details).toHaveTextContent('mailer')
    expect(within(details).getByTestId('password-saved')).toHaveTextContent('Password saved')
    expect(screen.getByTestId('uses-panel')).toHaveTextContent('Platform, always')
    expect(fetchMock.mock.calls.some((c) => String(c[0]) === senderUrl)).toBe(true)
  })

  it('shows "No sender: using the platform sender" with a Set sender action and a disabled test', async () => {
    renderSession(mspSession, (url) => (url === senderUrl ? jsonResponse(200, { data: none }) : undefined))
    await signIn()
    const status = await screen.findByTestId('sender-none')
    expect(status).toHaveTextContent('No sender: using the platform sender')
    expect(screen.getByTestId('set-btn')).toBeInTheDocument()
    expect(screen.queryByTestId('remove-btn')).not.toBeInTheDocument()
    expect(screen.getByTestId('test-btn')).toBeDisabled()
    expect(screen.getByTestId('test-panel')).toHaveTextContent('never falls back to the platform sender')
  })

  it('treats a stored record without a password as no sender', async () => {
    renderSession(mspSession, (url) =>
      url === senderUrl ? jsonResponse(200, { data: { ...stored, password_present: false } }) : undefined,
    )
    await signIn()
    expect(await screen.findByTestId('sender-none')).toBeInTheDocument()
    fireEvent.click(screen.getByTestId('set-btn'))
    expect(screen.getByTestId('host-input')).toHaveValue('smtp.vendor-a.example')
  })

  it('shows a loading state, then an error with Try again that reloads', async () => {
    let calls = 0
    renderSession(mspSession, (url) => {
      if (url !== senderUrl) return undefined
      calls++
      return calls === 1 ? jsonResponse(500, {}) : jsonResponse(200, { data: stored })
    })
    expect(screen.queryByTestId('sender-loading')).not.toBeInTheDocument()
    await signIn()
    const err = await screen.findByTestId('sender-error')
    expect(err).toHaveTextContent('Could not load the email sender.')
    expect(err).toHaveTextContent('Your sender settings have not changed.')
    fireEvent.click(screen.getByTestId('sender-retry-btn'))
    expect(await screen.findByTestId('sender-in-use')).toBeInTheDocument()
  })

  it('shows the loading skeleton while the sender is in flight', async () => {
    renderSession(mspSession, (url) => (url === senderUrl ? new Promise<Response>(() => undefined) : undefined))
    await signIn()
    expect(await screen.findByTestId('sender-loading')).toHaveAttribute('aria-busy', 'true')
  })

  it('shows the forbidden state on a 403', async () => {
    renderSession(mspSession, (url) =>
      url === senderUrl ? jsonResponse(403, { error: { code: 'FORBIDDEN', message: 'permission denied' } }) : undefined,
    )
    await signIn()
    const forbidden = await screen.findByTestId('sender-forbidden')
    expect(forbidden).toHaveTextContent('You cannot view or change this sender')
    expect(forbidden).toHaveTextContent('notification:configure-msp')
    expect(screen.queryByTestId('test-panel')).not.toBeInTheDocument()
  })

  it('words a cancelled passkey check on load as a retryable error', async () => {
    renderSession(mspSession, (url) => {
      if (url !== senderUrl) return undefined
      onStepUpRequired(null)
      return stepUpChallenge()
    })
    await signIn()
    expect(await screen.findByTestId('sender-error')).toHaveTextContent('The passkey check was cancelled.')
  })
})

describe('EmailDeliveryView — root session', () => {
  it('shows the crossing-required state when the crossing prompt is cancelled (401)', async () => {
    renderSession(
      rootSession,
      (url) => {
        if (url !== senderUrl) return undefined
        // No crossing listener: apiFetch returns the original 401, as a cancelled prompt does.
        onTenantCrossingRequired(null)
        return crossingChallenge()
      },
      'msp-a',
    )
    await signIn()
    const state = await screen.findByTestId('sender-crossing')
    expect(state).toHaveTextContent('Access to this tenant is required.')
    expect(state).toHaveTextContent('root can only read this sender')
    expect(screen.queryByTestId('sender-form')).not.toBeInTheDocument()
  })

  it('opens the standard crossing prompt over the page on a crossing challenge', async () => {
    renderSession(rootSession, (url) => (url === senderUrl ? crossingChallenge() : undefined), 'msp-a')
    await signIn()
    const dialog = await screen.findByRole('dialog')
    expect(dialog).toHaveTextContent(/access/i)
  })

  it('with a crossing, shows the read-only view: no Replace or Remove, Send test disabled, no write request', async () => {
    renderSession(rootSession, (url) => (url === senderUrl ? jsonResponse(200, { data: stored }) : undefined), 'msp-a')
    await signIn()
    expect(await screen.findByTestId('root-readonly')).toHaveTextContent('Read-only.')
    expect(screen.getByTestId('sender-details')).toHaveTextContent('smtp.vendor-a.example')
    expect(screen.getByTestId('password-saved')).toBeInTheDocument()
    expect(screen.queryByTestId('replace-btn')).not.toBeInTheDocument()
    expect(screen.queryByTestId('remove-btn')).not.toBeInTheDocument()
    expect(screen.queryByTestId('set-btn')).not.toBeInTheDocument()
    expect(screen.getByTestId('test-btn')).toBeDisabled()
    expect(screen.getByTestId('test-panel')).toHaveTextContent('Only an msp-a administrator can send a test.')
    const writes = fetchMock.mock.calls.filter((c) => ['PUT', 'DELETE', 'POST'].includes((c[1] as RequestInit | undefined)?.method ?? ''))
    // The only POSTs are the sign-in ceremony.
    expect(writes.every((c) => String(c[0]).includes('/web/'))).toBe(true)
  })

  it('shows root without a sender read-only, with no Set sender action', async () => {
    renderSession(rootSession, (url) => (url === senderUrl ? jsonResponse(200, { data: none }) : undefined), 'msp-a')
    await signIn()
    expect(await screen.findByTestId('sender-none')).toBeInTheDocument()
    expect(screen.queryByTestId('set-btn')).not.toBeInTheDocument()
  })
})

describe('EmailDeliveryView — set, replace and save', () => {
  it('first set requires a password and fields, clears the password and shows the marked errors', async () => {
    renderSession(mspSession, (url) => (url === senderUrl ? jsonResponse(200, { data: none }) : undefined))
    await signIn()
    fireEvent.click(await screen.findByTestId('set-btn'))
    expect(screen.getByRole('heading', { name: 'Set sender' })).toBeInTheDocument()
    typeInto('host-input', 'smtp.vendor-a.example/x')
    typeInto('from-input', 'Ops <ops@acme-corp.example>')
    typeInto('password-input', sentinel)
    fireEvent.click(screen.getByTestId('save-btn'))
    expect(screen.getByTestId('host-error')).toHaveTextContent('no spaces, no "/"')
    expect(screen.getByTestId('from-error')).toHaveTextContent('bare address')
    expect(screen.getByTestId('form-invalid')).toHaveTextContent('password field has been cleared')
    expect(screen.getByTestId('password-input')).toHaveValue('')
    expect(fetchMock.mock.calls.some((c) => (c[1] as RequestInit | undefined)?.method === 'PUT')).toBe(false)

    fillForm()
    fireEvent.click(screen.getByTestId('save-btn'))
    expect(screen.getByTestId('password-error')).toHaveTextContent('A password is required: no password is saved for msp-a yet.')
    expect(fetchMock.mock.calls.some((c) => (c[1] as RequestInit | undefined)?.method === 'PUT')).toBe(false)
  })

  it('ties the port to the TLS mode and offers only 587 and 465', async () => {
    renderSession(mspSession, (url) => (url === senderUrl ? jsonResponse(200, { data: none }) : undefined))
    await signIn()
    fireEvent.click(await screen.findByTestId('set-btn'))
    const port = screen.getByTestId('port-select') as HTMLSelectElement
    expect(Array.from(port.options).map((o) => o.value)).toEqual(['587', '465'])
    expect(port.value).toBe('587')
    fireEvent.change(screen.getByTestId('tls-select'), { target: { value: 'implicit_tls' } })
    expect(port.value).toBe('465')
    fireEvent.change(screen.getByTestId('tls-select'), { target: { value: 'starttls' } })
    expect(port.value).toBe('587')
  })

  it('sends the password in the PUT body only, then shows Password saved with no password anywhere', async () => {
    let putInit: RequestInit | undefined
    let putUrl = ''
    let sender: unknown = none
    renderSession(mspSession, (url, init) => {
      if (url === senderUrl && init?.method === 'PUT') {
        putInit = init
        putUrl = url
        sender = { ...stored, host: 'smtp.new.example', port: 465, tls_mode: 'implicit_tls' }
        return jsonResponse(200, { data: sender })
      }
      if (url === senderUrl) return jsonResponse(200, { data: sender })
      return undefined
    })
    await signIn()
    fireEvent.click(await screen.findByTestId('set-btn'))
    fillForm()
    typeInto('host-input', 'smtp.new.example')
    fireEvent.change(screen.getByTestId('tls-select'), { target: { value: 'implicit_tls' } })
    const pw = screen.getByTestId('password-input') as HTMLInputElement
    expect(pw).toHaveAttribute('type', 'password')
    expect(pw).toHaveAttribute('autocomplete', 'new-password')
    typeInto('password-input', sentinel)
    fireEvent.click(screen.getByTestId('save-btn'))

    expect(await screen.findByTestId('sender-saved')).toHaveTextContent('Password saved')
    expect(JSON.parse(String(putInit?.body))).toEqual({
      host: 'smtp.new.example',
      port: 465,
      tls_mode: 'implicit_tls',
      from: 'ops@acme-corp.example',
      username: 'mailer',
      password: sentinel,
    })
    expect(putUrl).toBe(senderUrl)
    // The password is in the PUT body and nowhere else.
    const others = fetchMock.mock.calls.filter((c) => c[1] !== putInit)
    expect(others.some((c) => String(c[0]).includes(sentinel) || String((c[1] as RequestInit | undefined)?.body ?? '').includes(sentinel))).toBe(false)
    expect(document.body.textContent).not.toContain(sentinel)
    expect(Array.from(document.querySelectorAll('input')).every((i) => !i.value.includes(sentinel))).toBe(true)
    expect(JSON.stringify({ ...localStorage })).not.toContain(sentinel)
    expect(JSON.stringify({ ...sessionStorage })).not.toContain(sentinel)
    expect(document.cookie).not.toContain(sentinel)

    // Replace opens with an empty password field, and says the stored one is kept.
    fireEvent.click(screen.getByTestId('replace-btn'))
    expect(screen.getByTestId('password-input')).toHaveValue('')
    expect(screen.getByTestId('password-keep-hint')).toHaveTextContent('Leave empty to keep the saved password')
    expect(screen.getByRole('heading', { name: 'Replace sender' })).toBeInTheDocument()
  })

  it('a settings-only edit omits the password so the stored one is kept', async () => {
    let body: Record<string, unknown> = {}
    renderSession(mspSession, (url, init) => {
      if (url === senderUrl && init?.method === 'PUT') {
        body = JSON.parse(String(init.body)) as Record<string, unknown>
        return jsonResponse(200, { data: { ...stored, username: 'other' } })
      }
      if (url === senderUrl) return jsonResponse(200, { data: stored })
      return undefined
    })
    await signIn()
    fireEvent.click(await screen.findByTestId('replace-btn'))
    expect(screen.getByTestId('host-input')).toHaveValue('smtp.vendor-a.example')
    expect(screen.getByTestId('port-select')).toHaveValue('587')
    typeInto('username-input', 'other')
    fireEvent.click(screen.getByTestId('save-btn'))
    await screen.findByTestId('sender-saved')
    expect('password' in body).toBe(false)
    expect(body.username).toBe('other')
    expect(screen.getByTestId('sender-details')).toHaveTextContent('other')
  })

  it('clears the password after a server rejection and shows the server message as text', async () => {
    renderSession(mspSession, (url, init) => {
      if (url === senderUrl && init?.method === 'PUT') {
        return jsonResponse(400, { error: { code: 'INVALID_EMAIL_SENDER', message: 'port must be <b>465</b> or 587' } })
      }
      if (url === senderUrl) return jsonResponse(200, { data: none })
      return undefined
    })
    await signIn()
    fireEvent.click(await screen.findByTestId('set-btn'))
    fillForm()
    typeInto('password-input', sentinel)
    fireEvent.click(screen.getByTestId('save-btn'))
    const err = await screen.findByTestId('save-error')
    expect(err).toHaveTextContent('port must be <b>465</b> or 587')
    expect(err.querySelector('b')?.textContent).toBe('Not saved.')
    expect(screen.getByTestId('password-input')).toHaveValue('')
    expect(document.body.textContent).not.toContain(sentinel)
  })

  it('words a cancelled passkey check, keeps the sender unchanged and clears the password', async () => {
    renderSession(mspSession, (url, init) => {
      if (url === senderUrl && init?.method === 'PUT') return stepUpChallenge()
      if (url === senderUrl) return jsonResponse(200, { data: stored })
      return undefined
    })
    await signIn()
    fireEvent.click(await screen.findByTestId('replace-btn'))
    onStepUpRequired(null)
    typeInto('password-input', sentinel)
    fireEvent.click(screen.getByTestId('save-btn'))
    const msg = await screen.findByTestId('save-cancelled')
    expect(msg).toHaveTextContent('The passkey check was cancelled.')
    expect(msg).toHaveTextContent('Your sender has not changed.')
    expect(screen.getByTestId('password-input')).toHaveValue('')
    expect(document.body.textContent).not.toContain(sentinel)
    expect(screen.getByTestId('sender-details')).toHaveTextContent('smtp.vendor-a.example')
  })

  it('Cancel closes the form and discards a typed password', async () => {
    renderSession(mspSession, (url) => (url === senderUrl ? jsonResponse(200, { data: stored }) : undefined))
    await signIn()
    fireEvent.click(await screen.findByTestId('replace-btn'))
    typeInto('password-input', sentinel)
    fireEvent.click(screen.getByTestId('form-cancel-btn'))
    expect(screen.queryByTestId('sender-form')).not.toBeInTheDocument()
    expect(document.body.textContent).not.toContain(sentinel)
    fireEvent.click(screen.getByTestId('replace-btn'))
    expect(screen.getByTestId('password-input')).toHaveValue('')
  })
})

describe('EmailDeliveryView — remove', () => {
  it('asks for confirmation, then DELETEs and shows the platform sender state', async () => {
    let removed = false
    renderSession(mspSession, (url, init) => {
      if (url === senderUrl && init?.method === 'DELETE') {
        removed = true
        return jsonResponse(200, { data: none })
      }
      if (url === senderUrl) return jsonResponse(200, { data: stored })
      return undefined
    })
    await signIn()
    fireEvent.click(await screen.findByTestId('remove-btn'))
    const confirm = screen.getByTestId('remove-confirm')
    expect(confirm).toHaveTextContent("Remove msp-a's sender?")
    expect(confirm).toHaveTextContent('platform sender')
    expect(removed).toBe(false)
    fireEvent.click(within(confirm).getByTestId('remove-confirm-btn'))
    expect(await screen.findByTestId('sender-none')).toHaveTextContent('No sender: using the platform sender')
    expect(removed).toBe(true)
    expect(screen.queryByTestId('remove-confirm')).not.toBeInTheDocument()
    expect(screen.queryByTestId('sender-details')).not.toBeInTheDocument()
  })

  it('Keep dismisses the confirmation without a request', async () => {
    renderSession(mspSession, (url) => (url === senderUrl ? jsonResponse(200, { data: stored }) : undefined))
    await signIn()
    fireEvent.click(await screen.findByTestId('remove-btn'))
    fireEvent.click(screen.getByTestId('remove-keep-btn'))
    expect(screen.queryByTestId('remove-confirm')).not.toBeInTheDocument()
    expect(screen.getByTestId('sender-in-use')).toBeInTheDocument()
    expect(fetchMock.mock.calls.some((c) => (c[1] as RequestInit | undefined)?.method === 'DELETE')).toBe(false)
  })

  it('keeps the sender and shows the failure when the delete is refused', async () => {
    renderSession(mspSession, (url, init) => {
      if (url === senderUrl && init?.method === 'DELETE') return stepUpChallenge()
      if (url === senderUrl) return jsonResponse(200, { data: stored })
      return undefined
    })
    await signIn()
    fireEvent.click(await screen.findByTestId('remove-btn'))
    onStepUpRequired(null)
    fireEvent.click(screen.getByTestId('remove-confirm-btn'))
    expect(await screen.findByTestId('remove-error')).toHaveTextContent('Not removed. The passkey check was cancelled.')
    expect(screen.getByTestId('sender-in-use')).toBeInTheDocument()
  })
})

describe('EmailDeliveryView — test send', () => {
  it('shows a delivered result with the accepted recipient', async () => {
    renderSession(mspSession, (url, init) => {
      if (url === testUrl) {
        expect(init?.method).toBe('POST')
        expect(init?.body).toBeUndefined()
        return jsonResponse(200, { data: { delivered: true, recipients: [{ address: 'ops@acme-corp.example', accepted: true }] } })
      }
      if (url === senderUrl) return jsonResponse(200, { data: stored })
      return undefined
    })
    await signIn()
    expect(await screen.findByTestId('test-panel')).toHaveTextContent('ops@acme-corp.example')
    fireEvent.click(screen.getByTestId('test-btn'))
    const result = await screen.findByTestId('test-delivered')
    expect(result).toHaveTextContent('Delivered. The mail server accepted every recipient.')
    const row = within(result).getByTestId('test-recipient')
    expect(row).toHaveTextContent('ops@acme-corp.example')
    expect(row).toHaveTextContent('Accepted')
  })

  it('shows a running state while the test is in flight', async () => {
    let finish: (r: Response) => void = () => undefined
    renderSession(mspSession, (url) => {
      if (url === testUrl) return new Promise<Response>((resolve) => (finish = resolve))
      if (url === senderUrl) return jsonResponse(200, { data: stored })
      return undefined
    })
    await signIn()
    fireEvent.click(await screen.findByTestId('test-btn'))
    expect(await screen.findByTestId('test-running')).toHaveTextContent('smtp.vendor-a.example')
    expect(screen.getByTestId('test-btn')).toBeDisabled()
    expect(screen.getByTestId('test-btn')).toHaveTextContent('Sending…')
    await act(async () => {
      finish(jsonResponse(200, { data: { delivered: true, recipients: [{ address: 'ops@acme-corp.example', accepted: true }] } }))
    })
    await screen.findByTestId('test-delivered')
    expect(screen.queryByTestId('test-running')).not.toBeInTheDocument()
  })

  it('renders each recipient as accepted or rejected with the failure reason as literal text', async () => {
    const reason = '550 <script>window.__pwned = 1</script> rejected'
    renderSession(mspSession, (url) => {
      if (url === testUrl) {
        return jsonResponse(200, {
          data: {
            delivered: false,
            recipients: [
              { address: 'ops@acme-corp.example', accepted: false, reason },
              { address: 'second@acme-corp.example', accepted: true },
            ],
            failure_reason: 'recipient <script>alert(1)</script> not accepted',
          },
        })
      }
      if (url === senderUrl) return jsonResponse(200, { data: stored })
      return undefined
    })
    await signIn()
    fireEvent.click(await screen.findByTestId('test-btn'))
    const result = await screen.findByTestId('test-failed')
    expect(result).toHaveTextContent('Not delivered.')
    expect(screen.getByTestId('test-failure-reason')).toHaveTextContent('recipient <script>alert(1)</script> not accepted')
    const rows = within(result).getAllByTestId('test-recipient')
    expect(rows).toHaveLength(2)
    expect(rows[0]).toHaveTextContent('Not sent')
    expect(rows[0]).toHaveTextContent(reason)
    expect(rows[1]).toHaveTextContent('Accepted')
    // Literal text: no element was created from the server strings.
    expect(document.querySelector('script')).toBeNull()
    expect((window as unknown as Record<string, unknown>).__pwned).toBeUndefined()
    expect(result.querySelector('script')).toBeNull()
  })

  it('shows a refused test (409) as an error, not as a result', async () => {
    renderSession(mspSession, (url) => {
      if (url === testUrl) return jsonResponse(409, { error: { code: 'EMAIL_NOT_CONFIGURED', message: 'the MSP email sender is not configured' } })
      if (url === senderUrl) return jsonResponse(200, { data: stored })
      return undefined
    })
    await signIn()
    fireEvent.click(await screen.findByTestId('test-btn'))
    expect(await screen.findByTestId('test-error')).toHaveTextContent('the MSP email sender is not configured')
    expect(screen.queryByTestId('test-delivered')).not.toBeInTheDocument()
    expect(screen.getByTestId('test-btn')).not.toBeDisabled()
  })

  it('words a cancelled passkey check on a test', async () => {
    renderSession(mspSession, (url) => {
      if (url === testUrl) return stepUpChallenge()
      if (url === senderUrl) return jsonResponse(200, { data: stored })
      return undefined
    })
    await signIn()
    const button = await screen.findByTestId('test-btn')
    onStepUpRequired(null)
    fireEvent.click(button)
    expect(await screen.findByTestId('test-error')).toHaveTextContent('Test not sent. The passkey check was cancelled.')
  })
})
