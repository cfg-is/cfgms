// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz

/*
 * RevealDialog and CredentialsPage tests (Issue #5566). Real AuthProvider, apiFetch and
 * StepUpModal; only global fetch is stubbed at the network edge.
 */
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'
import { cleanup, fireEvent, render, screen, waitFor } from '@testing-library/react'
import { MemoryRouter } from 'react-router'
import { AuthProvider } from '../auth/AuthContext.tsx'
import CredentialsPage from './CredentialsPage.tsx'
import RevealDialog from './RevealDialog.tsx'
import type { PendingCredential } from './credentialsApi.ts'

const fetchMock = vi.fn<typeof fetch>()
const SECRET = 'S3cret-Initial-Pw!'
const ID = '0123456789abcdef0123456789abcdef'
const listUrl = '/api/v1/directory/credentials'
const revealUrl = `${listUrl}/${ID}/reveal`

const record: PendingCredential = {
  id: ID,
  resource_id: 'user-a',
  created_at: '2026-11-01T00:00:00Z',
  expires_at: '2026-11-15T00:00:00Z',
}

let logged: string[] = []

beforeEach(() => {
  fetchMock.mockReset()
  vi.stubGlobal('fetch', fetchMock)
  logged = []
  for (const method of ['log', 'info', 'warn', 'error', 'debug'] as const) {
    vi.spyOn(console, method).mockImplementation((...args: unknown[]) => {
      logged.push(args.map(String).join(' '))
    })
  }
})

afterEach(() => {
  cleanup()
  vi.unstubAllGlobals()
  vi.restoreAllMocks()
  localStorage.clear()
  sessionStorage.clear()
})

function jsonResponse(status: number, body: unknown = {}, headers: Record<string, string> = {}): Response {
  return new Response(JSON.stringify(body), {
    status,
    headers: { 'Content-Type': 'application/json', ...headers },
  })
}

const envelope = (data: unknown) => ({ data, timestamp: new Date().toISOString() })

function stepUpChallenge(): Response {
  return jsonResponse(
    401,
    { error: 'step_up_required', required_assurance: 'strong', presence_required: true },
    { 'WWW-Authenticate': 'CFGMS-StepUp realm="cfgms", required="strong", presence="required"' },
  )
}

function stubPasskey() {
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
  vi.stubGlobal('navigator', {
    credentials: { get: vi.fn().mockResolvedValue(cred) },
    clipboard: { writeText: vi.fn().mockResolvedValue(undefined) },
  })
}

/** Presence endpoints that complete a tap, plus the given reveal handler. */
function routeFetch(reveal: (init: RequestInit | undefined) => Response, list: unknown = { items: [record] }) {
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
    if (u === revealUrl) return Promise.resolve(reveal(init))
    return Promise.resolve(jsonResponse(200, envelope(list)))
  })
}

const needsTap = (init: RequestInit | undefined) => new Headers(init?.headers).get('X-Presence-Token') !== 'tap-token-1'
const revealCalls = () => fetchMock.mock.calls.filter(([u]) => String(u) === revealUrl)

function renderDialog(onClose = vi.fn(), onRevealed = vi.fn()) {
  const view = render(
    <MemoryRouter>
      <AuthProvider>
        <RevealDialog credential={record} onClose={onClose} onRevealed={onRevealed} />
      </AuthProvider>
    </MemoryRouter>,
  )
  return { ...view, onClose, onRevealed }
}

function renderPage() {
  return render(
    <MemoryRouter>
      <AuthProvider>
        <CredentialsPage />
      </AuthProvider>
    </MemoryRouter>,
  )
}

function storageHolds(value: string): boolean {
  for (const store of [localStorage, sessionStorage]) {
    for (let i = 0; i < store.length; i++) {
      const key = store.key(i) ?? ''
      if (key.includes(value) || (store.getItem(key) ?? '').includes(value)) return true
    }
  }
  return false
}

async function revealWithTap() {
  fireEvent.click(screen.getByTestId('reveal-btn'))
  await waitFor(() => expect(screen.getByTestId('step-up-overlay')).toBeInTheDocument())
  fireEvent.click(await screen.findByTestId('step-up-verify-btn'))
  await screen.findByTestId('reveal-value')
}

describe('RevealDialog', () => {
  it('starts Ready and sends nothing until Reveal is pressed', () => {
    stubPasskey()
    routeFetch(() => jsonResponse(200, envelope({ password: SECRET })))
    renderDialog()
    expect(screen.getByTestId('reveal-warning')).toBeInTheDocument()
    expect(screen.getByTestId('reveal-resource')).toHaveTextContent('user-a')
    expect(revealCalls()).toHaveLength(0)
  })

  it('runs the passkey tap, retries with the token, and masks the value until Show', async () => {
    stubPasskey()
    routeFetch((init) => (needsTap(init) ? stepUpChallenge() : jsonResponse(200, envelope({ password: SECRET }))))
    const { onRevealed } = renderDialog()
    await revealWithTap()

    const calls = revealCalls()
    expect(calls).toHaveLength(2)
    expect(new Headers(calls[1]?.[1]?.headers).get('X-Presence-Token')).toBe('tap-token-1')
    expect(onRevealed).toHaveBeenCalled()

    // Masked: the value is not in the DOM.
    expect(screen.getByTestId('reveal-once-warning')).toBeInTheDocument()
    expect(screen.getByTestId('reveal-value')).not.toHaveTextContent(SECRET)
    expect(document.body.textContent).not.toContain(SECRET)

    fireEvent.click(screen.getByTestId('reveal-toggle-btn'))
    expect(screen.getByTestId('reveal-value')).toHaveTextContent(SECRET)
    fireEvent.click(screen.getByTestId('reveal-toggle-btn'))
    expect(document.body.textContent).not.toContain(SECRET)
  })

  it('shows Loading while the reveal is pending', async () => {
    stubPasskey()
    let release: (r: Response) => void = () => {}
    routeFetch(() => jsonResponse(500))
    fetchMock.mockImplementation((url) =>
      String(url) === revealUrl
        ? new Promise<Response>((resolve) => {
            release = resolve
          })
        : Promise.resolve(jsonResponse(200, envelope({}))),
    )
    renderDialog()
    fireEvent.click(screen.getByTestId('reveal-btn'))
    expect(await screen.findByTestId('reveal-loading')).toBeInTheDocument()
    release(jsonResponse(200, envelope({ password: SECRET })))
    expect(await screen.findByTestId('reveal-value')).toBeInTheDocument()
  })

  it('removes the value from the DOM, storage and console after close', async () => {
    stubPasskey()
    routeFetch((init) => (needsTap(init) ? stepUpChallenge() : jsonResponse(200, envelope({ password: SECRET }))))
    const { rerender, onClose } = renderDialog()
    await revealWithTap()
    fireEvent.click(screen.getByTestId('reveal-toggle-btn'))
    expect(document.body.textContent).toContain(SECRET)

    fireEvent.click(screen.getByTestId('reveal-close-btn'))
    expect(onClose).toHaveBeenCalled()
    // The owner unmounts the dialog on close.
    rerender(
      <MemoryRouter>
        <AuthProvider>
          <div />
        </AuthProvider>
      </MemoryRouter>,
    )
    expect(document.body.textContent).not.toContain(SECRET)
    expect(storageHolds(SECRET)).toBe(false)
    expect(window.location.href).not.toContain(SECRET)
    expect(window.history.state === null || !JSON.stringify(window.history.state).includes(SECRET)).toBe(true)
    expect(logged.join('\n')).not.toContain(SECRET)
  })

  it('keeps the value out of storage while it is on screen', async () => {
    stubPasskey()
    routeFetch((init) => (needsTap(init) ? stepUpChallenge() : jsonResponse(200, envelope({ password: SECRET }))))
    renderDialog()
    await revealWithTap()
    fireEvent.click(screen.getByTestId('reveal-toggle-btn'))
    expect(storageHolds(SECRET)).toBe(false)
  })

  it('shows the already-revealed state on a second reveal of the same record', async () => {
    stubPasskey()
    let served = false
    routeFetch((init) => {
      if (needsTap(init)) return stepUpChallenge()
      if (served) return jsonResponse(410, { error: 'credential is no longer available' })
      served = true
      return jsonResponse(200, envelope({ password: SECRET }))
    })
    const first = renderDialog()
    await revealWithTap()
    first.unmount()
    expect(document.body.textContent).not.toContain(SECRET)

    renderDialog()
    fireEvent.click(screen.getByTestId('reveal-btn'))
    await waitFor(() => expect(screen.getByTestId('step-up-overlay')).toBeInTheDocument())
    fireEvent.click(await screen.findByTestId('step-up-verify-btn'))
    expect(await screen.findByTestId('reveal-already')).toHaveTextContent(/already revealed/i)
    expect(screen.queryByTestId('reveal-value')).toBeNull()
    expect(document.body.textContent).not.toContain(SECRET)
    expect(storageHolds(SECRET)).toBe(false)
  })

  it('a cancelled presence tap sends no reveal with a token and shows no value', async () => {
    routeFetch(() => stepUpChallenge())
    const { onRevealed } = renderDialog()
    fireEvent.click(screen.getByTestId('reveal-btn'))
    await waitFor(() => expect(screen.getByTestId('step-up-overlay')).toBeInTheDocument())
    fireEvent.click(await screen.findByTestId('step-up-cancel-btn'))

    expect(await screen.findByTestId('reveal-error')).toHaveTextContent(/presence confirmation/i)
    const calls = revealCalls()
    expect(calls).toHaveLength(1)
    expect(new Headers(calls[0]?.[1]?.headers).get('X-Presence-Token')).toBeNull()
    expect(screen.queryByTestId('reveal-value')).toBeNull()
    expect(onRevealed).not.toHaveBeenCalled()
  })

  it('a failed passkey assertion does not retry the reveal route', async () => {
    vi.stubGlobal('navigator', { credentials: { get: vi.fn().mockRejectedValue(new Error('NotAllowedError')) } })
    routeFetch(() => stepUpChallenge())
    renderDialog()
    fireEvent.click(screen.getByTestId('reveal-btn'))
    await waitFor(() => expect(screen.getByTestId('step-up-overlay')).toBeInTheDocument())
    fireEvent.click(await screen.findByTestId('step-up-verify-btn'))
    await waitFor(() => expect(screen.getByTestId('step-up-cancel-btn')).toBeInTheDocument())
    fireEvent.click(screen.getByTestId('step-up-cancel-btn'))

    expect(await screen.findByTestId('reveal-error')).toBeInTheDocument()
    expect(
      revealCalls().filter(([, init]) => new Headers(init?.headers).get('X-Presence-Token') !== null),
    ).toHaveLength(0)
    expect(screen.queryByTestId('reveal-value')).toBeNull()
  })

  it('shows an error without the response text, then allows another attempt', async () => {
    stubPasskey()
    routeFetch(() => jsonResponse(500, { error: SECRET }))
    renderDialog()
    fireEvent.click(screen.getByTestId('reveal-btn'))
    const error = await screen.findByTestId('reveal-error')
    expect(error).toHaveTextContent('500')
    expect(document.body.textContent).not.toContain(SECRET)
    expect(screen.getByTestId('reveal-retry-btn')).toBeInTheDocument()
  })

  it('drops a result that arrives after the dialog was closed', async () => {
    stubPasskey()
    let release: (r: Response) => void = () => {}
    fetchMock.mockImplementation(
      () =>
        new Promise<Response>((resolve) => {
          release = resolve
        }),
    )
    const view = renderDialog()
    fireEvent.click(screen.getByTestId('reveal-btn'))
    await screen.findByTestId('reveal-loading')
    view.unmount()
    release(jsonResponse(200, envelope({ password: SECRET })))
    await Promise.resolve()
    expect(view.onRevealed).not.toHaveBeenCalled()
    expect(document.body.textContent).not.toContain(SECRET)
  })

  it('closes on Escape', () => {
    const { onClose } = renderDialog()
    fireEvent.keyDown(document, { key: 'Escape' })
    expect(onClose).toHaveBeenCalled()
  })

  it('copies the value to the clipboard', async () => {
    stubPasskey()
    routeFetch((init) => (needsTap(init) ? stepUpChallenge() : jsonResponse(200, envelope({ password: SECRET }))))
    renderDialog()
    await revealWithTap()
    fireEvent.click(screen.getByTestId('reveal-copy-btn'))
    await waitFor(() => expect(screen.getByTestId('reveal-copy-btn')).toHaveTextContent('Copied!'))
    expect(navigator.clipboard.writeText).toHaveBeenCalledWith(SECRET)
  })
})

describe('CredentialsPage', () => {
  it('lists pending records with resource id, created and expires, and no value', async () => {
    routeFetch(() => jsonResponse(500))
    renderPage()
    expect(await screen.findAllByTestId('credential-row')).toHaveLength(1)
    expect(screen.getByTestId('credential-resource')).toHaveTextContent('user-a')
    expect(screen.getByTestId('credential-created')).toHaveTextContent('2026-11-01T00:00:00Z')
    expect(screen.getByTestId('credential-expires')).toHaveTextContent('2026-11-15T00:00:00Z')
  })

  it('renders markup in wire values as text', async () => {
    routeFetch(() => jsonResponse(500), { items: [{ ...record, resource_id: '<img src=x onerror=alert(1)>' }] })
    renderPage()
    expect(await screen.findByTestId('credential-resource')).toHaveTextContent('<img src=x onerror=alert(1)>')
    expect(document.querySelector('img')).toBeNull()
  })

  it('shows the empty state', async () => {
    routeFetch(() => jsonResponse(500), { items: [] })
    renderPage()
    expect(await screen.findByTestId('credentials-empty')).toBeInTheDocument()
  })

  it('shows an error card and retries the list', async () => {
    fetchMock.mockResolvedValueOnce(jsonResponse(500, {}))
    fetchMock.mockResolvedValueOnce(jsonResponse(200, envelope({ items: [record] })))
    renderPage()
    expect(await screen.findByText(/couldn't load credentials/i)).toBeInTheDocument()
    fireEvent.click(screen.getByRole('button', { name: /retry|try again/i }))
    expect(await screen.findByTestId('credential-row')).toBeInTheDocument()
  })

  it('reveals through the dialog, then refreshes the list; closing clears the value', async () => {
    stubPasskey()
    let revealed = false
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
      if (u === revealUrl) {
        if (needsTap(init)) return Promise.resolve(stepUpChallenge())
        revealed = true
        return Promise.resolve(jsonResponse(200, envelope({ password: SECRET })))
      }
      return Promise.resolve(jsonResponse(200, envelope({ items: revealed ? [] : [record] })))
    })
    renderPage()
    fireEvent.click(await screen.findByTestId(`credential-reveal-btn-${ID}`))
    await revealWithTap()
    // The record leaves the list once revealed; the dialog stays up.
    await waitFor(() => expect(screen.getByTestId('credentials-empty')).toBeInTheDocument())
    expect(screen.getByTestId('reveal-value')).toBeInTheDocument()

    fireEvent.click(screen.getByTestId('reveal-close-btn'))
    expect(screen.queryByTestId('reveal-dialog')).toBeNull()
    expect(document.body.textContent).not.toContain(SECRET)
    expect(storageHolds(SECRET)).toBe(false)
  })

  it('discards the value when the page unmounts', async () => {
    stubPasskey()
    routeFetch((init) => (needsTap(init) ? stepUpChallenge() : jsonResponse(200, envelope({ password: SECRET }))))
    const view = renderPage()
    fireEvent.click(await screen.findByTestId(`credential-reveal-btn-${ID}`))
    await revealWithTap()
    fireEvent.click(screen.getByTestId('reveal-toggle-btn'))
    expect(document.body.textContent).toContain(SECRET)
    view.unmount()
    expect(document.body.textContent).not.toContain(SECRET)
  })
})
