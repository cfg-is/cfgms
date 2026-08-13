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
// Navigator.credentials.create() is stubbed — this test suite exercises
// the request/response wiring only; full WebAuthn ceremony validation lives
// in the handler tests (handlers_webauthn_test.go).
//
// The fetch global is stubbed (not apiFetch directly) to match the
// AccountsView.test.tsx pattern used across this project.
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'
import { cleanup, fireEvent, render, screen, waitFor } from '@testing-library/react'
import { MemoryRouter } from 'react-router'
import PasskeysView from './PasskeysView.tsx'

// ── auth context mock ─────────────────────────────────────────────────────

vi.mock('../auth/AuthContext.tsx', () => ({
  useAuth: () => ({ principal: { username: 'alice', tenantId: '' } }),
}))

// ── fetch stub ────────────────────────────────────────────────────────────

const fetchMock = vi.fn<typeof fetch>()

beforeEach(() => {
  vi.stubGlobal('fetch', fetchMock)
  fetchMock.mockReset()
})

afterEach(() => {
  vi.unstubAllGlobals()
  cleanup()
})

// ── helpers ───────────────────────────────────────────────────────────────

function makeListResp(credentials: object[]): Response {
  return new Response(
    JSON.stringify({ data: { username: 'alice', credentials } }),
    { status: 200, headers: { 'Content-Type': 'application/json' } },
  )
}

function makeErrorResp(status: number, code: string, message: string): Response {
  return new Response(
    JSON.stringify({ error: { code, message } }),
    { status, headers: { 'Content-Type': 'application/json' } },
  )
}

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

function renderView() {
  return render(
    <MemoryRouter>
      <PasskeysView />
    </MemoryRouter>,
  )
}

// ── tests ─────────────────────────────────────────────────────────────────

describe('PasskeysView', () => {
  it('renders the credential list', async () => {
    fetchMock.mockResolvedValueOnce(makeListResp([CRED_A, CRED_B]))
    renderView()

    await waitFor(() => expect(screen.queryByTestId('passkeys-loading')).toBeNull())

    const rows = screen.getAllByTestId('passkey-row')
    expect(rows).toHaveLength(2)
    expect(screen.getByText('MacBook Touch ID')).toBeInTheDocument()
    expect(screen.getByText('YubiKey 5')).toBeInTheDocument()
  })

  it('shows empty state when no credentials', async () => {
    fetchMock.mockResolvedValueOnce(makeListResp([]))
    renderView()

    await waitFor(() => expect(screen.queryByTestId('passkeys-loading')).toBeNull())
    expect(screen.getByTestId('passkeys-empty')).toBeInTheDocument()
  })

  it('shows load error and retry button on API failure', async () => {
    fetchMock.mockResolvedValueOnce(
      new Response(JSON.stringify({ error: { message: 'store unavailable' } }), {
        status: 503,
        headers: { 'Content-Type': 'application/json' },
      }),
    )
    renderView()

    await waitFor(() => expect(screen.queryByTestId('passkeys-loading')).toBeNull())
    expect(screen.getByTestId('load-error')).toBeInTheDocument()
    expect(screen.getByText('Retry')).toBeInTheDocument()
  })

  it('removes a credential row after successful revoke', async () => {
    // Initial load returns two credentials.
    fetchMock.mockResolvedValueOnce(makeListResp([CRED_A, CRED_B]))
    renderView()
    await waitFor(() => screen.getAllByTestId('passkey-row'))

    // Click "Remove" on the first credential to open the confirm dialog.
    // Use getByRole to avoid noUncheckedIndexedAccess on the result array.
    fireEvent.click(screen.getByRole('button', { name: /MacBook Touch ID/i }))

    // Confirm dialog appears — click "Confirm remove".
    await waitFor(() => expect(screen.getByTestId('confirm-revoke-btn')).toBeInTheDocument())

    // POST revoke → 204; reload list → 1 cred.
    fetchMock
      .mockResolvedValueOnce(new Response(null, { status: 204 }))
      .mockResolvedValueOnce(makeListResp([CRED_B]))

    fireEvent.click(screen.getByTestId('confirm-revoke-btn'))

    await waitFor(() => {
      expect(screen.getAllByTestId('passkey-row')).toHaveLength(1)
    })
    expect(screen.queryByText('MacBook Touch ID')).toBeNull()
  })

  it('shows anti-lockout alert on 409 LAST_CREDENTIAL', async () => {
    fetchMock.mockResolvedValueOnce(makeListResp([CRED_A]))
    renderView()
    await waitFor(() => screen.getAllByTestId('passkey-row'))

    fireEvent.click(screen.getByTestId('revoke-btn'))
    await waitFor(() => expect(screen.getByTestId('confirm-revoke-btn')).toBeInTheDocument())

    fetchMock.mockResolvedValueOnce(makeErrorResp(409, 'LAST_CREDENTIAL', 'Cannot remove the last passkey'))

    fireEvent.click(screen.getByTestId('confirm-revoke-btn'))

    await waitFor(() => expect(screen.getByTestId('last-cred-alert')).toBeInTheDocument())
    // Row must still be present.
    expect(screen.getAllByTestId('passkey-row')).toHaveLength(1)
  })

  it('shows revoke error banner on server error', async () => {
    fetchMock.mockResolvedValueOnce(makeListResp([CRED_A, CRED_B]))
    renderView()
    await waitFor(() => screen.getAllByTestId('passkey-row'))

    // Use getByRole to avoid noUncheckedIndexedAccess issue with getAllByTestId()[0].
    fireEvent.click(screen.getByRole('button', { name: /MacBook Touch ID/i }))
    await waitFor(() => expect(screen.getByTestId('confirm-revoke-btn')).toBeInTheDocument())

    fetchMock.mockResolvedValueOnce(makeErrorResp(500, 'STORE_ERROR', 'store write failed'))

    fireEvent.click(screen.getByTestId('confirm-revoke-btn'))

    await waitFor(() => expect(screen.getByTestId('revoke-error')).toBeInTheDocument())
  })

  it('silently ignores NotAllowedError from credentials.create', async () => {
    fetchMock.mockResolvedValueOnce(makeListResp([CRED_A]))
    // Stub navigator.credentials.create to throw NotAllowedError (user cancelled).
    // jsdom does not provision navigator.credentials, so we stub the global.
    const notAllowed = Object.assign(new Error('NotAllowedError'), { name: 'NotAllowedError' })
    vi.stubGlobal('navigator', {
      credentials: { create: vi.fn().mockRejectedValue(notAllowed) },
    })

    renderView()
    await waitFor(() => screen.getAllByTestId('passkey-row'))

    // Begin returns a minimal options object; the authenticator then throws NotAllowedError.
    const beginOpts = {
      data: {
        publicKey: {
          challenge: 'AAAA',
          rp: { name: 'CFGMS', id: 'example.com' },
          user: { id: 'AAAA', name: 'alice', displayName: 'alice' },
          pubKeyCredParams: [],
          timeout: 60000,
        },
      },
    }
    fetchMock.mockResolvedValueOnce(
      new Response(JSON.stringify(beginOpts), {
        status: 200,
        headers: { 'Content-Type': 'application/json' },
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
    fetchMock.mockResolvedValueOnce(makeListResp([CRED_A]))
    renderView()
    await waitFor(() => screen.getAllByTestId('passkey-row'))

    fetchMock.mockResolvedValueOnce(makeErrorResp(503, 'WEBAUTHN_NOT_CONFIGURED', 'WebAuthn not configured'))

    fireEvent.click(screen.getByTestId('add-passkey-btn'))

    await waitFor(() => expect(screen.getByTestId('add-error')).toBeInTheDocument())
  })
})
