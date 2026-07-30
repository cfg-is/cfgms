// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz

/*
 * TokensTab test suite (Story #2935): list rendering, data states, parse
 * helpers, and the required token-prefix security assertion.
 *
 * Required AC: rendered token rows must never contain a full-length token
 * string in the DOM — only the prefix. Tests assert on textContent only,
 * never on innerHTML (security A9.1).
 *
 * The GET /api/v1/registration/tokens response is {tokens:[...], total:N}
 * — no {data:...} envelope — per handlers_registration_tokens.go:160.
 *
 * expires_at / revoked_at are optional (Go omitempty on pointer types)
 * — absent fields render as an em-dash placeholder, matching columns.ts.
 *
 * No mint, rotate, revoke, or delete affordance exists in this component.
 */
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'
import { cleanup, render, screen, waitFor, within } from '@testing-library/react'
import { MemoryRouter } from 'react-router'
import { AuthProvider } from '../auth/AuthContext.tsx'
import TokensTab, { parseToken, parseTokenList } from './TokensTab.tsx'

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
        makeToken({ token_prefix: 'reg_9f8e7d', group: 'client-1 onboarding' }),
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

// ── Security: prefix-only guarantee (required AC) ─────────────────────────────

describe('TokensTab — token prefix security (required AC)', () => {
  it('renders only the token_prefix, never a full-length token string', async () => {
    const PREFIX = 'reg_x9y8z7'
    // Simulates wire data that includes the full `token` field (as create/rotate
    // would return). The list endpoint contract omits it, but this test verifies
    // the component does not render it even if the wire unexpectedly includes it.
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

    // The prefix appears in the token-prefix cell
    expect(within(rows[0]!).getByTestId('token-prefix')).toHaveTextContent(PREFIX)

    // The full wire value must not appear anywhere in the DOM
    expect(document.body.textContent).not.toContain(WIRE_FULL)
  })

  it('renders multiple tokens each showing only their prefix, never the full string', async () => {
    const FULL_A = 'reg_aaaaaa1111111111111111111111111111111111111111111111111111'
    const FULL_B = 'reg_bbbbbb2222222222222222222222222222222222222222222222222222'
    fetchMock.mockResolvedValue(
      makeTokensResponse([
        makeToken({ token_prefix: 'reg_aaaaaa', token: FULL_A }),
        makeToken({ token_prefix: 'reg_bbbbbb', token: FULL_B }),
      ]),
    )
    renderTab()
    await waitFor(() => expect(screen.getAllByTestId('token-row')).toHaveLength(2))

    expect(document.body.textContent).not.toContain(FULL_A)
    expect(document.body.textContent).not.toContain(FULL_B)
    expect(screen.getAllByTestId('token-prefix')[0]).toHaveTextContent('reg_aaaaaa')
    expect(screen.getAllByTestId('token-prefix')[1]).toHaveTextContent('reg_bbbbbb')
  })
})

// ── No write affordances ──────────────────────────────────────────────────────

describe('TokensTab — no write affordances', () => {
  it('renders no mint, rotate, revoke, or delete button', async () => {
    fetchMock.mockResolvedValue(makeTokensResponse([makeToken()]))
    renderTab()
    await waitFor(() => expect(screen.getByTestId('tokens-table')).toBeInTheDocument())

    expect(screen.queryByRole('button', { name: /mint/i })).toBeNull()
    expect(screen.queryByRole('button', { name: /rotate/i })).toBeNull()
    expect(screen.queryByRole('button', { name: /revoke/i })).toBeNull()
    expect(screen.queryByRole('button', { name: /delete/i })).toBeNull()
  })

  it('renders no write controls even in the loading state', () => {
    fetchMock.mockReturnValue(new Promise(() => {}))
    renderTab()
    expect(screen.queryByRole('button', { name: /mint/i })).toBeNull()
    expect(screen.queryByRole('button', { name: /rotate/i })).toBeNull()
    expect(screen.queryByRole('button', { name: /revoke/i })).toBeNull()
  })

  it('renders no write controls in the empty state', async () => {
    fetchMock.mockResolvedValue(makeTokensResponse([]))
    renderTab()
    await waitFor(() => expect(screen.getByTestId('tokens-empty')).toBeInTheDocument())
    expect(screen.queryByRole('button', { name: /mint/i })).toBeNull()
    expect(screen.queryByRole('button')).toBeNull()
  })
})
