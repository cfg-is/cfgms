// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz

/*
 * EnrolmentTokensTab test suite (Issue #5451, Epic #5300).
 * Real AuthProvider, apiFetch and StepUpModal; only global fetch is stubbed at
 * the network edge.
 */
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'
import { act, cleanup, fireEvent, render, screen, waitFor, within } from '@testing-library/react'
import { MemoryRouter } from 'react-router'
import { AuthProvider } from '../auth/AuthContext.tsx'
import EnrolmentTokensTab from './EnrolmentTokensTab.tsx'

const fetchMock = vi.fn<typeof fetch>()

beforeEach(() => {
  vi.stubGlobal('fetch', fetchMock)
  fetchMock.mockReset()
})

afterEach(() => {
  vi.unstubAllGlobals()
  cleanup()
})

const SECRET = 'cfgms_et_SUPERSECRETVALUE0123456789'

function makeRow(overrides: Partial<Record<string, unknown>> = {}) {
  return {
    id: 'et-1',
    token_prefix: 'et-ab12',
    tenant_id: 'root/msp-a',
    created_at: '2026-10-01T00:00:00Z',
    created_by: 'admin@msp-a',
    expires_at: '2026-10-02T00:00:00Z',
    status: 'active',
    ...overrides,
  }
}

function json(status: number, body: unknown = {}, headers: Record<string, string> = {}) {
  return new Response(status === 204 ? null : JSON.stringify(body), {
    status,
    headers: { 'Content-Type': 'application/json', ...headers },
  })
}

const list = (rows: object[]) => json(200, { data: rows })

function elevation401() {
  return json(401, {}, { 'WWW-Authenticate': 'CFGMS-StepUp realm="cfgms", required="strong"' })
}

function renderTab() {
  return render(
    <MemoryRouter>
      <AuthProvider>
        <EnrolmentTokensTab />
      </AuthProvider>
    </MemoryRouter>,
  )
}

function postCalls(suffix: string) {
  return fetchMock.mock.calls.filter(
    ([u, init]) => String(u).endsWith(suffix) && init?.method === 'POST',
  )
}

describe('EnrolmentTokensTab', () => {
  it('list renders status and never renders a token value', async () => {
    fetchMock.mockResolvedValue(
      list([
        makeRow({ id: 'et-1', status: 'active', token: SECRET }),
        makeRow({ id: 'et-2', token_prefix: 'cfgms_et_cd34', status: 'spent', spent_at: '2026-10-01T01:00:00Z' }),
        makeRow({ id: 'et-3', token_prefix: 'cfgms_et_ef56', status: 'revoked' }),
        makeRow({ id: 'et-4', token_prefix: 'cfgms_et_gh78', status: 'expired' }),
        makeRow({ id: 'et-5', token_prefix: '<img src=x onerror=alert(1)>', status: 'bogus' }),
      ]),
    )
    const { container } = renderTab()
    await waitFor(() => expect(screen.getByTestId('enrolment-tokens-table')).toBeInTheDocument())
    const statuses = screen.getAllByTestId('enrolment-token-status').map((n) => n.textContent)
    expect(statuses).toEqual(['Active', 'Spent', 'Revoked', 'Expired', 'Unknown'])
    expect(screen.getByText('et-ab12')).toBeInTheDocument()
    expect(document.body.textContent).not.toContain(SECRET)
    expect(container.querySelector('img')).toBeNull()
  })

  it('offers revoke only on active rows', async () => {
    fetchMock.mockResolvedValue(
      list([makeRow({ id: 'et-1' }), makeRow({ id: 'et-2', status: 'spent' }), makeRow({ id: 'et-3', status: 'revoked' })]),
    )
    renderTab()
    await waitFor(() => expect(screen.getByTestId('enrolment-tokens-table')).toBeInTheDocument())
    expect(screen.getByTestId('et-revoke-btn-et-1')).toBeInTheDocument()
    expect(screen.queryByTestId('et-revoke-btn-et-2')).toBeNull()
    expect(screen.queryByTestId('et-revoke-btn-et-3')).toBeNull()
    // revoke-issued stays available for a spent token: it issued a credential.
    expect(screen.getByTestId('et-revoke-issued-btn-et-2')).toBeInTheDocument()
  })

  it('mint shows secret once', async () => {
    fetchMock
      .mockResolvedValueOnce(list([]))
      .mockResolvedValueOnce(json(201, { data: { id: 'et-9', token: SECRET, token_prefix: 'cfgms_et_zz', tenant_id: 'root/msp-a' } }))
      .mockResolvedValueOnce(list([makeRow({ id: 'et-9', token_prefix: 'cfgms_et_zz' })]))
    renderTab()
    await waitFor(() => expect(screen.getByTestId('enrolment-tokens-empty')).toBeInTheDocument())
    fireEvent.change(screen.getByTestId('et-mint-tenant'), { target: { value: 'root/msp-a' } })
    fireEvent.click(screen.getByTestId('et-mint-btn'))

    await waitFor(() => expect(screen.getByTestId('secret-value')).toHaveTextContent(SECRET))
    const mintCall = postCalls('/api/v1/enrolment-tokens')[0]!
    expect(JSON.parse(String(mintCall[1]?.body))).toEqual({ tenant_id: 'root/msp-a' })

    // The refreshed list never carries the value; closing discards it.
    await waitFor(() => expect(screen.getByTestId('enrolment-tokens-table')).toBeInTheDocument())
    fireEvent.click(screen.getByTestId('dismiss-secret-btn'))
    expect(screen.queryByTestId('secret-once-modal')).toBeNull()
    expect(document.body.textContent).not.toContain(SECRET)
  })

  it('mint rate limit shows a worded message', async () => {
    fetchMock.mockResolvedValueOnce(list([])).mockResolvedValueOnce(json(429, {}))
    renderTab()
    await waitFor(() => expect(screen.getByTestId('enrolment-tokens-empty')).toBeInTheDocument())
    fireEvent.change(screen.getByTestId('et-mint-tenant'), { target: { value: 'root/msp-a' } })
    fireEvent.click(screen.getByTestId('et-mint-btn'))
    await waitFor(() => expect(screen.getByTestId('et-mint-error')).toHaveTextContent(/too many.*try again/i))
    expect(screen.queryByTestId('secret-once-modal')).toBeNull()
  })

  it('revoke posts after inline confirm and refreshes', async () => {
    fetchMock
      .mockResolvedValueOnce(list([makeRow()]))
      .mockResolvedValueOnce(json(200, { data: {} }))
      .mockResolvedValueOnce(list([makeRow({ status: 'revoked' })]))
    renderTab()
    await waitFor(() => expect(screen.getByTestId('et-revoke-btn-et-1')).toBeInTheDocument())
    fireEvent.click(screen.getByTestId('et-revoke-btn-et-1'))
    expect(postCalls('/api/v1/enrolment-tokens/et-1/revoke')).toHaveLength(0)
    fireEvent.click(screen.getByTestId('et-confirm-btn'))
    await waitFor(() => expect(postCalls('/api/v1/enrolment-tokens/et-1/revoke')).toHaveLength(1))
    await waitFor(() => expect(screen.getByText('Revoked')).toBeInTheDocument())
  })

  it('revoke-issued needs confirm', async () => {
    fetchMock.mockResolvedValueOnce(list([makeRow()])).mockResolvedValue(json(200, { data: {} }))
    renderTab()
    await waitFor(() => expect(screen.getByTestId('et-revoke-issued-btn-et-1')).toBeInTheDocument())
    fireEvent.click(screen.getByTestId('et-revoke-issued-btn-et-1'))

    const row = screen.getByTestId('et-confirm-row')
    expect(within(row).getByText(/every credential this token issued/i)).toBeInTheDocument()
    expect(postCalls('/revoke-issued-credentials')).toHaveLength(0)

    // Cancel sends nothing.
    fireEvent.click(screen.getByTestId('et-cancel-btn'))
    expect(screen.queryByTestId('et-confirm-row')).toBeNull()
    expect(postCalls('/revoke-issued-credentials')).toHaveLength(0)

    fireEvent.click(screen.getByTestId('et-revoke-issued-btn-et-1'))
    fireEvent.click(screen.getByTestId('et-confirm-btn'))
    await waitFor(() =>
      expect(postCalls('/api/v1/enrolment-tokens/et-1/revoke-issued-credentials')).toHaveLength(1),
    )
  })

  it('surfaces a failed action', async () => {
    fetchMock.mockResolvedValueOnce(list([makeRow()])).mockResolvedValueOnce(json(500, {}))
    renderTab()
    await waitFor(() => expect(screen.getByTestId('et-revoke-btn-et-1')).toBeInTheDocument())
    fireEvent.click(screen.getByTestId('et-revoke-btn-et-1'))
    fireEvent.click(screen.getByTestId('et-confirm-btn'))
    await waitFor(() => expect(screen.getByTestId('et-action-error')).toHaveTextContent(/500/))
  })

  it('revoke and revoke-issued handle elevation 401 without a presence token', async () => {
    const MOCK_BEGIN = {
      data: {
        publicKey: {
          challenge: 'Y2hhbGxlbmdlLWJ5dGVz',
          timeout: 60000,
          rpId: 'localhost',
          allowCredentials: [],
          userVerification: 'required',
        },
      },
    }
    const toAB = (s: string) => new TextEncoder().encode(s).buffer as ArrayBuffer
    const cred = {
      id: 'cred-id',
      type: 'public-key',
      rawId: toAB('cred-id'),
      response: {
        clientDataJSON: toAB('{"type":"webauthn.get"}'),
        authenticatorData: toAB('a'),
        signature: toAB('s'),
        userHandle: null,
      },
      getClientExtensionResults: () => ({}),
      authenticatorAttachment: null,
      toJSON: () => ({}),
    }
    vi.stubGlobal('navigator', { credentials: { get: vi.fn().mockResolvedValue(cred) } })

    for (const [btn, suffix] of [
      ['et-revoke-btn-et-1', '/api/v1/enrolment-tokens/et-1/revoke'],
      ['et-revoke-issued-btn-et-1', '/api/v1/enrolment-tokens/et-1/revoke-issued-credentials'],
    ] as const) {
      cleanup()
      fetchMock.mockReset()
      let challenged = false
      fetchMock.mockImplementation((url) => {
        const u = String(url)
        if (u.includes('elevate/begin')) return Promise.resolve(json(200, MOCK_BEGIN))
        if (u.includes('elevate/finish')) return Promise.resolve(json(200, { assurance: 'strong' }))
        if (u.endsWith(suffix)) {
          if (!challenged) {
            challenged = true
            return Promise.resolve(elevation401())
          }
          return Promise.resolve(json(200, { data: {} }))
        }
        return Promise.resolve(list([makeRow()]))
      })
      renderTab()
      await waitFor(() => expect(screen.getByTestId(btn)).toBeInTheDocument())
      fireEvent.click(screen.getByTestId(btn))
      fireEvent.click(screen.getByTestId('et-confirm-btn'))
      await waitFor(() => screen.getByTestId('step-up-verify-btn'))
      act(() => screen.getByTestId('step-up-verify-btn').click())
      await waitFor(() => expect(postCalls(suffix)).toHaveLength(2))

      const retry = postCalls(suffix)[1]!
      expect(new Headers(retry[1]?.headers).get('X-Presence-Token')).toBeNull()
      expect(screen.queryByTestId('et-action-error')).toBeNull()
    }
  })

  it('shows an error card when the list fails', async () => {
    fetchMock.mockResolvedValue(json(500, {}))
    renderTab()
    await waitFor(() => expect(screen.getByText(/couldn't load enrolment tokens/i)).toBeInTheDocument())
  })
})
