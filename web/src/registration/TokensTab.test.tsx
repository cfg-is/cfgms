// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz

/*
 * TokensTab test suite (Story #2935, #2970): list rendering, data states,
 * parse helpers, mint/rotate/revoke/delete actions, SecretOnceModal, and
 * token-prefix security assertions.
 *
 * Required AC (Story #2970):
 *   - mint/rotate/revoke/delete wired behind apiFetch (step-up handled by AuthProvider)
 *   - minted/rotated secret shown exactly once in SecretOnceModal; dismissed by clearing state
 *   - secret never stored in a durable location; absent from DOM after dismiss
 *   - secret never rendered in the token table — only token_prefix appears
 *
 * The GET /api/v1/registration/tokens response is {tokens:[...], total:N}
 * — no {data:...} envelope — per handlers_registration_tokens.go.
 *
 * expires_at / revoked_at are optional (Go omitempty on pointer types)
 * — absent fields render as an em-dash placeholder, matching columns.ts.
 */
import { useState } from 'react'
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'
import { cleanup, fireEvent, render, screen, waitFor, within } from '@testing-library/react'
import { MemoryRouter } from 'react-router'
import { AuthProvider } from '../auth/AuthContext.tsx'
import TokensTab, { SecretOnceModal, parseToken, parseTokenList } from './TokensTab.tsx'

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

function makeToken(overrides: Partial<Record<string, unknown>> = {}) {
  return {
    token_id: 'aaaaaaaa-0000-4000-8000-000000000001',
    token_prefix: 'reg_a1b2c3',
    tenant_id: 'root/msp-a/prod',
    group: 'prod bulk enroll',
    created_at: '2026-07-10T00:00:00Z',
    expires_at: '2026-08-10T00:00:00Z',
    revoked: false,
    ...overrides,
  }
}

function makeTokensResponse(tokens: object[], status = 200) {
  return new Response(JSON.stringify({ tokens, total: tokens.length }), {
    status,
    headers: { 'Content-Type': 'application/json' },
  })
}

function jsonResponse(body: unknown, status = 200) {
  return new Response(JSON.stringify(body), {
    status,
    headers: { 'Content-Type': 'application/json' },
  })
}

function renderTab() {
  return render(
    <MemoryRouter>
      <AuthProvider>
        <TokensTab />
      </AuthProvider>
    </MemoryRouter>,
  )
}

// ── Parse helpers ─────────────────────────────────────────────────────────────

describe('parseToken', () => {
  it('returns null for non-objects', () => {
    expect(parseToken(null)).toBeNull()
    expect(parseToken('string')).toBeNull()
    expect(parseToken(42)).toBeNull()
  })

  it('returns null when token_prefix is missing or empty', () => {
    expect(parseToken({})).toBeNull()
    expect(parseToken({ token_prefix: '' })).toBeNull()
  })

  it('parses a full entry', () => {
    const token = parseToken(makeToken())
    expect(token).toEqual({
      token_id: 'aaaaaaaa-0000-4000-8000-000000000001',
      token_prefix: 'reg_a1b2c3',
      tenant_id: 'root/msp-a/prod',
      group: 'prod bulk enroll',
      created_at: '2026-07-10T00:00:00Z',
      expires_at: '2026-08-10T00:00:00Z',
      revoked: false,
      revoked_at: null,
    })
  })

  it('coerces non-string tenant_id and group to empty string', () => {
    const token = parseToken({ token_prefix: 'reg_xyz', tenant_id: 99, group: null })
    expect(token?.tenant_id).toBe('')
    expect(token?.group).toBe('')
  })

  it('sets expires_at to null when absent', () => {
    const token = parseToken({ token_prefix: 'reg_xyz', tenant_id: 'root' })
    expect(token?.expires_at).toBeNull()
  })

  it('sets revoked_at to null when absent', () => {
    const token = parseToken({ token_prefix: 'reg_xyz', tenant_id: 'root' })
    expect(token?.revoked_at).toBeNull()
  })

  it('parses revoked as boolean false when absent', () => {
    const token = parseToken({ token_prefix: 'reg_xyz', tenant_id: 'root' })
    expect(token?.revoked).toBe(false)
  })

  it('parses revoked:true', () => {
    const token = parseToken({ token_prefix: 'reg_xyz', tenant_id: 'root', revoked: true })
    expect(token?.revoked).toBe(true)
  })

  it('parses token_id when present', () => {
    const token = parseToken({
      token_prefix: 'reg_xyz',
      tenant_id: 'root',
      token_id: 'aaaaaaaa-0000-4000-8000-000000000099',
    })
    expect(token?.token_id).toBe('aaaaaaaa-0000-4000-8000-000000000099')
  })

  it('does not expose a token field even if wire data contains one', () => {
    const WIRE_FULL = 'reg_a1b2c3d4e5f6g7h8i9j0k1l2m3n4'
    const parsed = parseToken({ token_prefix: 'reg_a1b2c3', token: WIRE_FULL, tenant_id: 'root' })
    expect(parsed).not.toHaveProperty('token')
  })
})

describe('parseTokenList', () => {
  it('throws on non-object input', () => {
    expect(() => parseTokenList(null)).toThrow('unexpected response shape')
    expect(() => parseTokenList([])).toThrow('unexpected response shape')
    expect(() => parseTokenList('string')).toThrow('unexpected response shape')
  })

  it('throws when tokens field is not an array', () => {
    expect(() => parseTokenList({ tokens: null, total: 0 })).toThrow('unexpected response shape')
    expect(() => parseTokenList({ total: 0 })).toThrow('unexpected response shape')
  })

  it('parses a list of tokens', () => {
    const list = parseTokenList({ tokens: [makeToken()], total: 1 })
    expect(list).toHaveLength(1)
    expect(list[0]?.token_prefix).toBe('reg_a1b2c3')
    expect(list[0]?.token_id).toBe('aaaaaaaa-0000-4000-8000-000000000001')
  })

  it('drops tokens without a token_prefix', () => {
    const list = parseTokenList({ tokens: [{}, makeToken()], total: 2 })
    expect(list).toHaveLength(1)
  })
})

// ── List rendering ────────────────────────────────────────────────────────────

describe('TokensTab — list rendering', () => {
  it('shows a loading skeleton while the fetch is in-flight', () => {
    fetchMock.mockReturnValue(new Promise(() => {}))
    renderTab()
    expect(screen.getByTestId('tokens-loading')).toBeInTheDocument()
  })

  it('shows the empty state when no tokens exist', async () => {
    fetchMock.mockResolvedValue(makeTokensResponse([]))
    renderTab()
    await waitFor(() => expect(screen.getByTestId('tokens-empty')).toBeInTheDocument())
  })

  it('renders one row per token', async () => {
    fetchMock.mockResolvedValue(
      makeTokensResponse([
        makeToken(),
        makeToken({
          token_id: 'aaaaaaaa-0000-4000-8000-000000000002',
          token_prefix: 'reg_9f8e7d',
          group: 'client-1 onboarding',
        }),
      ]),
    )
    renderTab()
    await waitFor(() => expect(screen.getByTestId('tokens-table')).toBeInTheDocument())
    expect(screen.getAllByTestId('token-row')).toHaveLength(2)
  })

  it('renders an error card on a non-200 response', async () => {
    fetchMock.mockResolvedValue(makeTokensResponse([], 500))
    renderTab()
    await waitFor(() => expect(screen.getByRole('alert')).toBeInTheDocument())
    expect(screen.getByRole('alert')).toHaveTextContent('500')
  })

  it('renders an error card on a network failure', async () => {
    fetchMock.mockRejectedValue(new Error('network down'))
    renderTab()
    await waitFor(() => expect(screen.getByRole('alert')).toBeInTheDocument())
    expect(screen.getByText(/check your connection/i)).toBeInTheDocument()
  })

  it('retries the fetch when Retry is clicked', async () => {
    fetchMock
      .mockResolvedValueOnce(makeTokensResponse([], 500))
      .mockResolvedValueOnce(makeTokensResponse([]))
    renderTab()
    await waitFor(() => expect(screen.getByRole('alert')).toBeInTheDocument())
    screen.getByRole('button', { name: /retry/i }).click()
    await waitFor(() => expect(screen.getByTestId('tokens-empty')).toBeInTheDocument())
    expect(fetchMock).toHaveBeenCalledTimes(2)
  })
})

// ── Field rendering ───────────────────────────────────────────────────────────

describe('TokensTab — field rendering', () => {
  it('renders token_prefix, tenant_id, group, created_at as text content', async () => {
    fetchMock.mockResolvedValue(makeTokensResponse([makeToken()]))
    renderTab()
    await waitFor(() => expect(screen.getByTestId('tokens-table')).toBeInTheDocument())
    const row = screen.getAllByTestId('token-row')[0]!
    expect(within(row).getByTestId('token-prefix')).toHaveTextContent('reg_a1b2c3')
    expect(within(row).getByTestId('token-tenant')).toHaveTextContent('root/msp-a/prod')
    expect(within(row).getByTestId('token-group')).toHaveTextContent('prod bulk enroll')
    expect(within(row).getByTestId('token-created')).toHaveTextContent('2026-07-10T00:00:00Z')
  })

  it('renders expires_at when present', async () => {
    fetchMock.mockResolvedValue(makeTokensResponse([makeToken()]))
    renderTab()
    await waitFor(() => expect(screen.getByTestId('tokens-table')).toBeInTheDocument())
    const row = screen.getAllByTestId('token-row')[0]!
    expect(within(row).getByTestId('token-expires')).toHaveTextContent('2026-08-10T00:00:00Z')
  })

  it('renders em-dash when expires_at is absent', async () => {
    fetchMock.mockResolvedValue(
      makeTokensResponse([makeToken({ expires_at: undefined })]),
    )
    renderTab()
    await waitFor(() => expect(screen.getByTestId('tokens-table')).toBeInTheDocument())
    const row = screen.getAllByTestId('token-row')[0]!
    expect(within(row).getByTestId('token-expires')).toHaveTextContent('—')
  })

  it('renders em-dash for empty tenant_id', async () => {
    fetchMock.mockResolvedValue(
      makeTokensResponse([makeToken({ tenant_id: '' })]),
    )
    renderTab()
    await waitFor(() => expect(screen.getByTestId('tokens-table')).toBeInTheDocument())
    const row = screen.getAllByTestId('token-row')[0]!
    expect(within(row).getByTestId('token-tenant')).toHaveTextContent('—')
  })

  it('renders em-dash for empty group', async () => {
    fetchMock.mockResolvedValue(
      makeTokensResponse([makeToken({ group: '' })]),
    )
    renderTab()
    await waitFor(() => expect(screen.getByTestId('tokens-table')).toBeInTheDocument())
    const row = screen.getAllByTestId('token-row')[0]!
    expect(within(row).getByTestId('token-group')).toHaveTextContent('—')
  })
})

// ── Status badges ─────────────────────────────────────────────────────────────

describe('TokensTab — status badges', () => {
  it('shows Active for a non-revoked token with a future expiry', async () => {
    const futureDate = new Date(Date.now() + 30 * 24 * 60 * 60 * 1000).toISOString()
    fetchMock.mockResolvedValue(
      makeTokensResponse([makeToken({ revoked: false, expires_at: futureDate })]),
    )
    renderTab()
    await waitFor(() => expect(screen.getByTestId('tokens-table')).toBeInTheDocument())
    expect(screen.getByTestId('token-status')).toHaveTextContent('Active')
  })

  it('shows Active for a non-revoked token with no expiry', async () => {
    fetchMock.mockResolvedValue(
      makeTokensResponse([makeToken({ revoked: false, expires_at: undefined })]),
    )
    renderTab()
    await waitFor(() => expect(screen.getByTestId('tokens-table')).toBeInTheDocument())
    expect(screen.getByTestId('token-status')).toHaveTextContent('Active')
  })

  it('shows Expired for a non-revoked token with a past expiry', async () => {
    const pastDate = '2026-01-01T00:00:00Z'
    fetchMock.mockResolvedValue(
      makeTokensResponse([makeToken({ revoked: false, expires_at: pastDate })]),
    )
    renderTab()
    await waitFor(() => expect(screen.getByTestId('tokens-table')).toBeInTheDocument())
    expect(screen.getByTestId('token-status')).toHaveTextContent('Expired')
  })

  it('shows Revoked for a revoked token regardless of expiry', async () => {
    fetchMock.mockResolvedValue(
      makeTokensResponse([makeToken({ revoked: true, expires_at: undefined })]),
    )
    renderTab()
    await waitFor(() => expect(screen.getByTestId('tokens-table')).toBeInTheDocument())
    expect(screen.getByTestId('token-status')).toHaveTextContent('Revoked')
  })
})

// ── Mint ──────────────────────────────────────────────────────────────────────

describe('TokensTab — mint', () => {
  it('renders a mint form in the empty state', async () => {
    fetchMock.mockResolvedValue(makeTokensResponse([]))
    renderTab()
    await waitFor(() => expect(screen.getByTestId('tokens-empty')).toBeInTheDocument())
    expect(screen.getByTestId('mint-form')).toBeInTheDocument()
    expect(screen.getByTestId('mint-btn')).toBeInTheDocument()
  })

  it('renders a mint form when tokens exist', async () => {
    fetchMock.mockResolvedValue(makeTokensResponse([makeToken()]))
    renderTab()
    await waitFor(() => expect(screen.getByTestId('tokens-table')).toBeInTheDocument())
    expect(screen.getByTestId('mint-form')).toBeInTheDocument()
  })

  it('posts to the tokens endpoint and shows SecretOnceModal with the minted secret', async () => {
    const SECRET = 'reg_mintedtoken1234567890abcde'
    fetchMock
      .mockResolvedValueOnce(makeTokensResponse([]))                // initial GET
      .mockResolvedValueOnce(jsonResponse({ token: SECRET, token_id: 'uuid-1', token_prefix: 'reg_min' }, 201))  // POST
      .mockResolvedValueOnce(makeTokensResponse([makeToken()]))     // reload GET
    renderTab()
    await waitFor(() => expect(screen.getByTestId('mint-form')).toBeInTheDocument())

    fireEvent.change(screen.getByTestId('mint-controller-url'), { target: { value: 'https://ctrl.example.com' } })
    fireEvent.click(screen.getByTestId('mint-btn'))

    await waitFor(() => expect(screen.getByTestId('secret-once-modal')).toBeInTheDocument())
    expect(screen.getByTestId('secret-value')).toHaveTextContent(SECRET)
    // POST was called
    expect(fetchMock).toHaveBeenCalledWith(
      '/api/v1/registration/tokens',
      expect.objectContaining({ method: 'POST' }),
    )
  })

  it('shows SecretOnceModal with action label "Minted"', async () => {
    const SECRET = 'reg_mintedtoken1234567890abcde'
    fetchMock
      .mockResolvedValueOnce(makeTokensResponse([]))
      .mockResolvedValueOnce(jsonResponse({ token: SECRET }, 201))
      .mockResolvedValueOnce(makeTokensResponse([]))
    renderTab()
    await waitFor(() => expect(screen.getByTestId('mint-form')).toBeInTheDocument())
    fireEvent.change(screen.getByTestId('mint-controller-url'), { target: { value: 'https://ctrl.example.com' } })
    fireEvent.click(screen.getByTestId('mint-btn'))
    await waitFor(() => expect(screen.getByTestId('secret-once-modal')).toBeInTheDocument())
    expect(screen.getByRole('dialog')).toHaveTextContent(/minted/i)
  })

  it('shows mint error on non-201 response', async () => {
    fetchMock
      .mockResolvedValueOnce(makeTokensResponse([]))
      .mockResolvedValueOnce(new Response('bad', { status: 400 }))
    renderTab()
    await waitFor(() => expect(screen.getByTestId('mint-form')).toBeInTheDocument())
    fireEvent.change(screen.getByTestId('mint-controller-url'), { target: { value: 'https://ctrl.example.com' } })
    fireEvent.click(screen.getByTestId('mint-btn'))
    await waitFor(() => expect(screen.getByTestId('mint-error')).toBeInTheDocument())
    expect(screen.getByTestId('mint-error')).toHaveTextContent('400')
  })

  it('validates that controller URL is required', async () => {
    fetchMock.mockResolvedValue(makeTokensResponse([]))
    renderTab()
    await waitFor(() => expect(screen.getByTestId('mint-form')).toBeInTheDocument())
    // fireEvent.submit bypasses HTML5 required validation so React's own check runs.
    fireEvent.submit(screen.getByTestId('mint-form'))
    await waitFor(() => expect(screen.getByTestId('mint-error')).toBeInTheDocument())
    expect(screen.getByTestId('mint-error')).toHaveTextContent(/required/i)
  })
})

// ── Rotate ────────────────────────────────────────────────────────────────────

describe('TokensTab — rotate', () => {
  it('sends POST to the rotate endpoint and shows SecretOnceModal with rotated secret', async () => {
    const TOKEN_ID = 'aaaaaaaa-0000-4000-8000-000000000001'
    const SECRET = 'reg_rotatedtoken1234567890abcde'
    fetchMock
      .mockResolvedValueOnce(makeTokensResponse([makeToken({ token_id: TOKEN_ID })]))
      .mockResolvedValueOnce(jsonResponse({ token: SECRET, token_id: 'uuid-new', token_prefix: 'reg_rot' }, 201))
      .mockResolvedValueOnce(makeTokensResponse([makeToken({ token_id: 'uuid-new', token_prefix: 'reg_rot' })]))
    renderTab()
    await waitFor(() => expect(screen.getByTestId('tokens-table')).toBeInTheDocument())

    fireEvent.click(screen.getByTestId(`rotate-btn-${TOKEN_ID}`))

    await waitFor(() => expect(screen.getByTestId('secret-once-modal')).toBeInTheDocument())
    expect(screen.getByTestId('secret-value')).toHaveTextContent(SECRET)
    expect(screen.getByRole('dialog')).toHaveTextContent(/rotated/i)
  })

  it('shows action error on rotate failure', async () => {
    const TOKEN_ID = 'aaaaaaaa-0000-4000-8000-000000000001'
    fetchMock
      .mockResolvedValueOnce(makeTokensResponse([makeToken({ token_id: TOKEN_ID })]))
      .mockResolvedValueOnce(new Response('err', { status: 409 }))
    renderTab()
    await waitFor(() => expect(screen.getByTestId('tokens-table')).toBeInTheDocument())
    fireEvent.click(screen.getByTestId(`rotate-btn-${TOKEN_ID}`))
    await waitFor(() => expect(screen.getByTestId(`action-error-${TOKEN_ID}`)).toBeInTheDocument())
    expect(screen.getByTestId(`action-error-${TOKEN_ID}`)).toHaveTextContent('409')
  })
})

// ── Revoke ────────────────────────────────────────────────────────────────────

describe('TokensTab — revoke', () => {
  it('sends POST /{token_id}/revoke and reloads', async () => {
    const TOKEN_ID = 'aaaaaaaa-0000-4000-8000-000000000001'
    const revokedToken = makeToken({ token_id: TOKEN_ID, revoked: true })
    fetchMock
      .mockResolvedValueOnce(makeTokensResponse([makeToken({ token_id: TOKEN_ID })]))
      .mockResolvedValueOnce(jsonResponse({ token_id: TOKEN_ID, revoked: true }, 200))
      .mockResolvedValueOnce(makeTokensResponse([revokedToken]))
    renderTab()
    await waitFor(() => expect(screen.getByTestId('tokens-table')).toBeInTheDocument())

    fireEvent.click(screen.getByTestId(`revoke-btn-${TOKEN_ID}`))

    await waitFor(() =>
      expect(fetchMock).toHaveBeenCalledWith(
        `/api/v1/registration/tokens/${TOKEN_ID}/revoke`,
        expect.objectContaining({ method: 'POST' }),
      ),
    )
    // After reload the row shows Revoked
    await waitFor(() => expect(screen.getByTestId('token-status')).toHaveTextContent('Revoked'))
  })

  it('shows action error on revoke failure', async () => {
    const TOKEN_ID = 'aaaaaaaa-0000-4000-8000-000000000001'
    fetchMock
      .mockResolvedValueOnce(makeTokensResponse([makeToken({ token_id: TOKEN_ID })]))
      .mockResolvedValueOnce(new Response('err', { status: 500 }))
    renderTab()
    await waitFor(() => expect(screen.getByTestId('tokens-table')).toBeInTheDocument())
    fireEvent.click(screen.getByTestId(`revoke-btn-${TOKEN_ID}`))
    await waitFor(() => expect(screen.getByTestId(`action-error-${TOKEN_ID}`)).toBeInTheDocument())
    expect(screen.getByTestId(`action-error-${TOKEN_ID}`)).toHaveTextContent('500')
  })
})

// ── Delete ────────────────────────────────────────────────────────────────────

describe('TokensTab — delete', () => {
  it('sends DELETE /{token_id} and removes the row', async () => {
    const TOKEN_ID = 'aaaaaaaa-0000-4000-8000-000000000001'
    fetchMock
      .mockResolvedValueOnce(makeTokensResponse([makeToken({ token_id: TOKEN_ID })]))
      .mockResolvedValueOnce(new Response(null, { status: 204 }))
      .mockResolvedValueOnce(makeTokensResponse([]))
    renderTab()
    await waitFor(() => expect(screen.getByTestId('tokens-table')).toBeInTheDocument())

    fireEvent.click(screen.getByTestId(`delete-btn-${TOKEN_ID}`))

    await waitFor(() =>
      expect(fetchMock).toHaveBeenCalledWith(
        `/api/v1/registration/tokens/${TOKEN_ID}`,
        expect.objectContaining({ method: 'DELETE' }),
      ),
    )
    // After reload, empty state
    await waitFor(() => expect(screen.getByTestId('tokens-empty')).toBeInTheDocument())
  })

  it('shows action error on delete failure', async () => {
    const TOKEN_ID = 'aaaaaaaa-0000-4000-8000-000000000001'
    fetchMock
      .mockResolvedValueOnce(makeTokensResponse([makeToken({ token_id: TOKEN_ID })]))
      .mockResolvedValueOnce(new Response('err', { status: 500 }))
    renderTab()
    await waitFor(() => expect(screen.getByTestId('tokens-table')).toBeInTheDocument())
    fireEvent.click(screen.getByTestId(`delete-btn-${TOKEN_ID}`))
    await waitFor(() => expect(screen.getByTestId(`action-error-${TOKEN_ID}`)).toBeInTheDocument())
    expect(screen.getByTestId(`action-error-${TOKEN_ID}`)).toHaveTextContent('500')
  })
})

// ── Tokens without a stable id ────────────────────────────────────────────────

describe('TokensTab — token without token_id', () => {
  it('disables revoke and delete and never builds a degenerate URL', async () => {
    fetchMock.mockResolvedValueOnce(
      makeTokensResponse([makeToken({ token_id: '', token_prefix: 'reg_leg' })]),
    )
    renderTab()
    await waitFor(() => expect(screen.getByTestId('tokens-table')).toBeInTheDocument())

    // Row state is keyed by token_prefix when there is no id.
    expect(screen.getByTestId('revoke-btn-reg_leg')).toBeDisabled()
    expect(screen.getByTestId('delete-btn-reg_leg')).toBeDisabled()
    // Rotate addresses the tenant, not the token id — it stays available.
    expect(screen.getByTestId('rotate-btn-reg_leg')).toBeEnabled()

    fireEvent.click(screen.getByTestId('revoke-btn-reg_leg'))
    fireEvent.click(screen.getByTestId('delete-btn-reg_leg'))

    // Only the initial list GET was issued — no `/tokens//revoke` and no `/tokens/`.
    expect(fetchMock).toHaveBeenCalledTimes(1)
    expect(fetchMock.mock.calls[0]?.[0]).toBe('/api/v1/registration/tokens')
  })

  it('keeps per-row state separate for two tokens without an id', async () => {
    fetchMock
      .mockResolvedValueOnce(
        makeTokensResponse([
          makeToken({ token_id: '', token_prefix: 'reg_one' }),
          makeToken({ token_id: '', token_prefix: 'reg_two' }),
        ]),
      )
      .mockResolvedValueOnce(new Response('err', { status: 409 }))
    renderTab()
    await waitFor(() => expect(screen.getByTestId('tokens-table')).toBeInTheDocument())

    fireEvent.click(screen.getByTestId('rotate-btn-reg_one'))

    await waitFor(() => expect(screen.getByTestId('action-error-reg_one')).toBeInTheDocument())
    expect(screen.queryByTestId('action-error-reg_two')).toBeNull()
  })
})

// ── SecretOnceModal ───────────────────────────────────────────────────────────

describe('SecretOnceModal', () => {
  it('renders the secret value and a copy button', () => {
    const onDismiss = vi.fn()
    render(
      <SecretOnceModal
        secret="reg_secretvalue12345678901234"
        action="minted"
        onDismiss={onDismiss}
      />,
    )
    expect(screen.getByTestId('secret-value')).toHaveTextContent('reg_secretvalue12345678901234')
    expect(screen.getByTestId('copy-secret-btn')).toBeInTheDocument()
  })

  it('calls onDismiss when the dismiss button is clicked', async () => {
    const onDismiss = vi.fn()
    render(
      <SecretOnceModal
        secret="reg_secretvalue12345678901234"
        action="minted"
        onDismiss={onDismiss}
      />,
    )
    fireEvent.click(screen.getByTestId('dismiss-secret-btn'))
    expect(onDismiss).toHaveBeenCalledTimes(1)
  })

  it('shows "Minted" heading for minted action', () => {
    render(
      <SecretOnceModal
        secret="reg_secretvalue12345678901234"
        action="minted"
        onDismiss={() => {}}
      />,
    )
    expect(screen.getByRole('heading')).toHaveTextContent(/minted/i)
  })

  it('shows "Rotated" heading for rotated action', () => {
    render(
      <SecretOnceModal
        secret="reg_secretvalue12345678901234"
        action="rotated"
        onDismiss={() => {}}
      />,
    )
    expect(screen.getByRole('heading')).toHaveTextContent(/rotated/i)
  })

  it('includes a one-time warning message', () => {
    render(
      <SecretOnceModal
        secret="reg_secretvalue12345678901234"
        action="minted"
        onDismiss={() => {}}
      />,
    )
    expect(screen.getByTestId('secret-once-warning')).toBeInTheDocument()
    expect(screen.getByTestId('secret-once-warning')).toHaveTextContent(/not be shown again/i)
  })

  it('is dismissed — secret absent from DOM after onDismiss is called', async () => {
    const SECRET = 'reg_secretvalue12345678901234'
    function Wrapper() {
      const [show, setShow] = useState(true)
      return show ? (
        <SecretOnceModal secret={SECRET} action="minted" onDismiss={() => setShow(false)} />
      ) : (
        <div data-testid="dismissed" />
      )
    }
    render(<Wrapper />)
    expect(screen.getByTestId('secret-value')).toHaveTextContent(SECRET)
    fireEvent.click(screen.getByTestId('dismiss-secret-btn'))
    await waitFor(() => expect(screen.getByTestId('dismissed')).toBeInTheDocument())
    expect(document.body.textContent).not.toContain(SECRET)
  })
})

// ── Security: prefix-only guarantee (required AC) ─────────────────────────────

describe('TokensTab — token prefix security (required AC)', () => {
  it('renders only the token_prefix, never a full-length token string', async () => {
    const PREFIX = 'reg_x9y8z7'
    const WIRE_FULL = 'reg_x9y8z7w6v5u4t3s2r1q0p9o8n7m6l5k4j3i2h1g0f9e8d7c6b5a4'
    fetchMock.mockResolvedValue(
      makeTokensResponse([
        makeToken({ token_prefix: PREFIX, token: WIRE_FULL }),
      ]),
    )
    renderTab()
    await waitFor(() => expect(screen.getByTestId('tokens-table')).toBeInTheDocument())

    const rows = screen.getAllByTestId('token-row')
    expect(rows).toHaveLength(1)
    expect(within(rows[0]!).getByTestId('token-prefix')).toHaveTextContent(PREFIX)
    expect(document.body.textContent).not.toContain(WIRE_FULL)
  })

  it('renders multiple tokens each showing only their prefix, never the full string', async () => {
    const FULL_A = 'reg_aaaaaa1111111111111111111111111111111111111111111111111111'
    const FULL_B = 'reg_bbbbbb2222222222222222222222222222222222222222222222222222'
    fetchMock.mockResolvedValue(
      makeTokensResponse([
        makeToken({ token_prefix: 'reg_aaaaaa', token: FULL_A, token_id: 'uuid-a' }),
        makeToken({ token_prefix: 'reg_bbbbbb', token: FULL_B, token_id: 'uuid-b' }),
      ]),
    )
    renderTab()
    await waitFor(() => expect(screen.getAllByTestId('token-row')).toHaveLength(2))

    expect(document.body.textContent).not.toContain(FULL_A)
    expect(document.body.textContent).not.toContain(FULL_B)
    expect(screen.getAllByTestId('token-prefix')[0]).toHaveTextContent('reg_aaaaaa')
    expect(screen.getAllByTestId('token-prefix')[1]).toHaveTextContent('reg_bbbbbb')
  })

  it('secret shown in SecretOnceModal is absent from DOM after dismiss', async () => {
    const SECRET = 'reg_mintonce1234567890abcde'
    fetchMock
      .mockResolvedValueOnce(makeTokensResponse([]))
      .mockResolvedValueOnce(jsonResponse({ token: SECRET }, 201))
      .mockResolvedValueOnce(makeTokensResponse([]))
    renderTab()
    await waitFor(() => expect(screen.getByTestId('mint-form')).toBeInTheDocument())
    fireEvent.change(screen.getByTestId('mint-controller-url'), { target: { value: 'https://ctrl.example.com' } })
    fireEvent.click(screen.getByTestId('mint-btn'))
    await waitFor(() => expect(screen.getByTestId('secret-once-modal')).toBeInTheDocument())
    expect(document.body.textContent).toContain(SECRET)
    fireEvent.click(screen.getByTestId('dismiss-secret-btn'))
    await waitFor(() => expect(screen.queryByTestId('secret-once-modal')).toBeNull())
    expect(document.body.textContent).not.toContain(SECRET)
  })
})
