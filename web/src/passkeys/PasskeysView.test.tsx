// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz
//
// Issue #2992: PasskeysView self-service passkey management UI tests.
//
// Scope:
//   - Renders credential list from the API
//   - Shows loading skeleton, empty state, and load error
//   - Revoke happy path removes the row (204)
//   - Revoke returns 409 LAST_CREDENTIAL → shows anti-lockout alert, row stays
//   - Revoke server error → shows error banner
//   - Add passkey: cancel (NotAllowedError) is silently swallowed
//   - Add passkey: server begin error shows error banner
//
// Real components only: the principal comes from the real <AuthProvider>, driven
// through its real passkey login ceremony (begin → credentials.get → finish) via
// the SignedInHarness below — the same mechanism App.tsx's Login screen uses, and
// the same pattern as UserMenu.test.tsx / SavedViews.test.tsx. Nothing inside
// web/src is mocked.
//
// Only the two browser boundaries are stubbed: the fetch global (answered by a
// URL router so login traffic and passkey-management traffic cannot interleave
// into an ordering dependency) and navigator.credentials (jsdom provisions no
// authenticator). Full WebAuthn ceremony validation lives in the handler tests
// (handlers_webauthn_test.go).
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'
import { useEffect } from 'react'
import { cleanup, fireEvent, render, screen, waitFor } from '@testing-library/react'
import { MemoryRouter } from 'react-router'
import { AuthProvider, useAuth } from '../auth/AuthContext.tsx'
import PasskeysView from './PasskeysView.tsx'

const USERNAME = 'alice'

// ── response helpers ──────────────────────────────────────────────────────

function jsonResponse(status: number, body: unknown): Response {
  return new Response(status === 204 ? null : JSON.stringify(body), {
    status,
    headers: { 'Content-Type': 'application/json' },
  })
}

function makeListResp(credentials: object[]): Response {
  return jsonResponse(200, { data: { username: USERNAME, credentials } })
}

function makeErrorResp(status: number, code: string, message: string): Response {
  return jsonResponse(status, { error: { code, message } })
}

// A per-endpoint FIFO of response factories. Responses are built lazily because a
// Response body can only be consumed once. An exhausted queue answers 500 so an
// unexpected extra call fails its test loudly instead of silently reusing a body.
function makeQueue(name: string) {
  const items: Array<() => Response> = []
  return {
    push(factory: () => Response) {
      items.push(factory)
    },
    reset() {
      items.length = 0
    },
    next(): Response {
      const factory = items.shift()
      if (factory === undefined) {
        return jsonResponse(500, { error: { message: `unexpected extra ${name} request` } })
      }
      return factory()
    },
  }
}

const listQueue = makeQueue('credential-list')
const revokeQueue = makeQueue('revoke')
const registerBeginQueue = makeQueue('register-begin')
const registerFinishQueue = makeQueue('register-finish')

// ── browser boundary stubs ────────────────────────────────────────────────

const fetchMock = vi.fn<typeof fetch>()
const credentialsGet = vi.fn<(opts?: CredentialRequestOptions) => Promise<Credential | null>>()
const credentialsCreate = vi.fn<(opts?: CredentialCreationOptions) => Promise<Credential | null>>()

const LOGIN_BEGIN_OPTIONS = {
  publicKey: {
    challenge: 'Y2hhbGxlbmdlLWJ5dGVz',
    timeout: 60000,
    rpId: 'localhost',
    allowCredentials: [],
    userVerification: 'required' as const,
  },
}

function makeAssertionCredential(): PublicKeyCredential {
  const toArrayBuffer = (s: string) => new TextEncoder().encode(s).buffer as ArrayBuffer
  return {
    id: 'login-cred-id',
    type: 'public-key',
    rawId: toArrayBuffer('login-cred-id'),
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

function route(input: RequestInfo | URL): Response {
  const url = String(input)
  // Real AuthProvider login ceremony.
  if (url.endsWith('/api/v1/web/csrf')) {
    document.cookie = 'cfgms_csrf_pre=pre-tok; path=/'
    return jsonResponse(204, null)
  }
  if (url.endsWith('/api/v1/web/passkey/login/begin')) {
    return jsonResponse(200, LOGIN_BEGIN_OPTIONS)
  }
  if (url.endsWith('/api/v1/web/passkey/login/finish')) {
    return jsonResponse(200, {
      data: { ok: true, username: USERNAME, tenant_id: '', root_scope: false },
    })
  }
  // PasskeysView management endpoints.
  if (url.endsWith(`/api/v1/accounts/${USERNAME}/webauthn/credentials`)) {
    return listQueue.next()
  }
  if (url.endsWith('/webauthn/register/begin')) {
    return registerBeginQueue.next()
  }
  if (url.endsWith('/webauthn/register/finish')) {
    return registerFinishQueue.next()
  }
  if (url.includes('/webauthn/revoke/')) {
    return revokeQueue.next()
  }
  return jsonResponse(404, { error: { message: `unrouted request: ${url}` } })
}

beforeEach(() => {
  fetchMock.mockReset()
  fetchMock.mockImplementation((input) => Promise.resolve(route(input)))
  credentialsGet.mockReset()
  credentialsGet.mockImplementation(() => Promise.resolve(makeAssertionCredential()))
  credentialsCreate.mockReset()
  credentialsCreate.mockImplementation(() =>
    Promise.reject(new Error('credentials.create not configured by this test')),
  )
  listQueue.reset()
  revokeQueue.reset()
  registerBeginQueue.reset()
  registerFinishQueue.reset()
  vi.stubGlobal('fetch', fetchMock)
  vi.stubGlobal('navigator', { credentials: { get: credentialsGet, create: credentialsCreate } })
})

afterEach(() => {
  vi.unstubAllGlobals()
  cleanup()
})

// ── fixtures ──────────────────────────────────────────────────────────────

const CRED_A = {
  id: 'aGVsbG8',
  label: 'MacBook Touch ID',
  transport: ['internal'],
  registered_at: '2026-01-10T12:00:00Z',
  last_used_at: '2026-08-01T09:00:00Z',
}

const CRED_B = {
  id: 'd29ybGQ',
  label: 'YubiKey 5',
  transport: ['usb', 'nfc'],
  registered_at: '2026-02-15T08:00:00Z',
  last_used_at: null,
}

// ── harness ───────────────────────────────────────────────────────────────

/*
 * Signs in through the real AuthProvider.login() — PasskeysView has no login
 * form of its own, so a principal only exists once something drives the
 * provider's real ceremony. PasskeysView mounts only after the session is
 * established, so its credential-list load fires exactly once per test.
 */
function SignedInHarness() {
  const { status, login } = useAuth()
  useEffect(() => {
    if (status === 'signedOut') void login(USERNAME)
  }, [status, login])
  if (status !== 'signedIn') return null
  return <PasskeysView />
}

async function renderView() {
  const result = render(
    <MemoryRouter>
      <AuthProvider>
        <SignedInHarness />
      </AuthProvider>
    </MemoryRouter>,
  )
  await screen.findByTestId('passkeys-view')
  return result
}

// ── tests ─────────────────────────────────────────────────────────────────

describe('PasskeysView', () => {
  it('renders the credential list', async () => {
    listQueue.push(() => makeListResp([CRED_A, CRED_B]))
    await renderView()

    await waitFor(() => expect(screen.queryByTestId('passkeys-loading')).toBeNull())

    const rows = screen.getAllByTestId('passkey-row')
    expect(rows).toHaveLength(2)
    expect(screen.getByText('MacBook Touch ID')).toBeInTheDocument()
    expect(screen.getByText('YubiKey 5')).toBeInTheDocument()
  })

  it('shows empty state when no credentials', async () => {
    listQueue.push(() => makeListResp([]))
    await renderView()

    await waitFor(() => expect(screen.queryByTestId('passkeys-loading')).toBeNull())
    expect(screen.getByTestId('passkeys-empty')).toBeInTheDocument()
  })

  it('shows load error and retry button on API failure', async () => {
    listQueue.push(() => jsonResponse(503, { error: { message: 'store unavailable' } }))
    await renderView()

    await waitFor(() => expect(screen.queryByTestId('passkeys-loading')).toBeNull())
    expect(screen.getByTestId('load-error')).toBeInTheDocument()
    expect(screen.getByText('Retry')).toBeInTheDocument()
  })

  it('removes a credential row after successful revoke', async () => {
    // Initial load returns two credentials.
    listQueue.push(() => makeListResp([CRED_A, CRED_B]))
    await renderView()
    await waitFor(() => screen.getAllByTestId('passkey-row'))

    // Click "Remove" on the first credential to open the confirm dialog.
    // Use getByRole to avoid noUncheckedIndexedAccess on the result array.
    fireEvent.click(screen.getByRole('button', { name: /MacBook Touch ID/i }))

    // Confirm dialog appears — click "Confirm remove".
    await waitFor(() => expect(screen.getByTestId('confirm-revoke-btn')).toBeInTheDocument())

    // POST revoke → 204; reload list → 1 cred.
    revokeQueue.push(() => new Response(null, { status: 204 }))
    listQueue.push(() => makeListResp([CRED_B]))

    fireEvent.click(screen.getByTestId('confirm-revoke-btn'))

    await waitFor(() => {
      expect(screen.getAllByTestId('passkey-row')).toHaveLength(1)
    })
    expect(screen.queryByText('MacBook Touch ID')).toBeNull()
  })

  it('shows anti-lockout alert on 409 LAST_CREDENTIAL', async () => {
    listQueue.push(() => makeListResp([CRED_A]))
    await renderView()
    await waitFor(() => screen.getAllByTestId('passkey-row'))

    fireEvent.click(screen.getByTestId('revoke-btn'))
    await waitFor(() => expect(screen.getByTestId('confirm-revoke-btn')).toBeInTheDocument())

    revokeQueue.push(() => makeErrorResp(409, 'LAST_CREDENTIAL', 'Cannot remove the last passkey'))

    fireEvent.click(screen.getByTestId('confirm-revoke-btn'))

    await waitFor(() => expect(screen.getByTestId('last-cred-alert')).toBeInTheDocument())
    // Row must still be present.
    expect(screen.getAllByTestId('passkey-row')).toHaveLength(1)
  })

  it('shows revoke error banner on server error', async () => {
    listQueue.push(() => makeListResp([CRED_A, CRED_B]))
    await renderView()
    await waitFor(() => screen.getAllByTestId('passkey-row'))

    // Use getByRole to avoid noUncheckedIndexedAccess issue with getAllByTestId()[0].
    fireEvent.click(screen.getByRole('button', { name: /MacBook Touch ID/i }))
    await waitFor(() => expect(screen.getByTestId('confirm-revoke-btn')).toBeInTheDocument())

    revokeQueue.push(() => makeErrorResp(500, 'STORE_ERROR', 'store write failed'))

    fireEvent.click(screen.getByTestId('confirm-revoke-btn'))

    await waitFor(() => expect(screen.getByTestId('revoke-error')).toBeInTheDocument())
  })

  it('silently ignores NotAllowedError from credentials.create', async () => {
    listQueue.push(() => makeListResp([CRED_A]))
    // The authenticator rejects with NotAllowedError (user cancelled the prompt).
    const notAllowed = Object.assign(new Error('NotAllowedError'), { name: 'NotAllowedError' })
    credentialsCreate.mockImplementation(() => Promise.reject(notAllowed))

    await renderView()
    await waitFor(() => screen.getAllByTestId('passkey-row'))

    // Begin returns a minimal options object; the authenticator then throws NotAllowedError.
    registerBeginQueue.push(() =>
      jsonResponse(200, {
        data: {
          publicKey: {
            challenge: 'AAAA',
            rp: { name: 'CFGMS', id: 'example.com' },
            user: { id: 'AAAA', name: USERNAME, displayName: USERNAME },
            pubKeyCredParams: [],
            timeout: 60000,
          },
        },
      }),
    )

    fireEvent.click(screen.getByTestId('add-passkey-btn'))

    await waitFor(() => {
      expect(screen.getByTestId('add-passkey-btn')).not.toBeDisabled()
    })
    // No error banner should appear for a user cancel.
    expect(screen.queryByTestId('add-error')).toBeNull()
  })

  it('shows add error banner when begin returns an error', async () => {
    listQueue.push(() => makeListResp([CRED_A]))
    await renderView()
    await waitFor(() => screen.getAllByTestId('passkey-row'))

    registerBeginQueue.push(() =>
      makeErrorResp(503, 'WEBAUTHN_NOT_CONFIGURED', 'WebAuthn not configured'),
    )

    fireEvent.click(screen.getByTestId('add-passkey-btn'))

    await waitFor(() => expect(screen.getByTestId('add-error')).toBeInTheDocument())
  })
})
