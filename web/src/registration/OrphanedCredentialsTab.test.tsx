// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz

/*
 * OrphanedCredentialsTab test suite (Issue #5455, Epic #5300).
 * Real AuthProvider, apiFetch and StepUpModal; only global fetch is stubbed at
 * the network edge.
 */
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'
import { act, cleanup, fireEvent, render, screen, waitFor } from '@testing-library/react'
import { MemoryRouter } from 'react-router'
import { AuthProvider } from '../auth/AuthContext.tsx'
import OrphanedCredentialsTab, { parseOrphanedCredentialList } from './OrphanedCredentialsTab.tsx'

const fetchMock = vi.fn<typeof fetch>()

beforeEach(() => {
  vi.stubGlobal('fetch', fetchMock)
  fetchMock.mockReset()
})

afterEach(() => {
  vi.unstubAllGlobals()
  cleanup()
})

function makeRow(overrides: Partial<Record<string, unknown>> = {}) {
  return {
    request_id: 'creq-1',
    tenant_id: 'root/msp-a',
    serial: 'ABC123',
    account_id: 'acct-1',
    collected_at: '2026-10-01T00:00:00Z',
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
        <OrphanedCredentialsTab />
      </AuthProvider>
    </MemoryRouter>,
  )
}

function postCalls(suffix: string) {
  return fetchMock.mock.calls.filter(([u, init]) => String(u).endsWith(suffix) && init?.method === 'POST')
}

describe('OrphanedCredentialsTab', () => {
  it('renders empty, error and list states', async () => {
    fetchMock.mockResolvedValueOnce(list([]))
    const first = renderTab()
    await waitFor(() => expect(screen.getByTestId('orphaned-empty')).toBeInTheDocument())
    first.unmount()

    fetchMock.mockReset()
    fetchMock.mockResolvedValue(json(500, {}))
    const second = renderTab()
    await waitFor(() => expect(screen.getByText(/couldn't load orphaned credentials/i)).toBeInTheDocument())
    second.unmount()

    fetchMock.mockReset()
    fetchMock.mockResolvedValue(
      list([makeRow(), makeRow({ serial: '<img src=x onerror=alert(1)>', request_id: 'creq-2' })]),
    )
    const { container } = renderTab()
    await waitFor(() => expect(screen.getByTestId('orphaned-table')).toBeInTheDocument())
    expect(screen.getAllByTestId('orphaned-row')).toHaveLength(2)
    expect(screen.getByText('ABC123')).toBeInTheDocument()
    expect(container.querySelector('img')).toBeNull()
    expect(String(fetchMock.mock.calls[0]![0])).toBe('/api/v1/credential-requests/orphaned')
  })

  it('parser rejects items without a string serial', () => {
    const out = parseOrphanedCredentialList({
      data: [makeRow(), makeRow({ serial: 5 }), makeRow({ serial: '' }), null, 'x'],
    })
    expect(out.map((o) => o.serial)).toEqual(['ABC123'])
    expect(() => parseOrphanedCredentialList({ data: 'nope' })).toThrow()
  })

  it('sends nothing until Confirm, and Cancel aborts', async () => {
    fetchMock.mockResolvedValue(list([makeRow()]))
    renderTab()
    await waitFor(() => screen.getByTestId('orphaned-revoke-btn-ABC123'))
    fireEvent.click(screen.getByTestId('orphaned-revoke-btn-ABC123'))
    expect(postCalls('/revoke')).toHaveLength(0)
    fireEvent.click(screen.getByTestId('orphaned-cancel-btn'))
    expect(screen.queryByTestId('orphaned-confirm-row')).toBeNull()
    expect(postCalls('/revoke')).toHaveLength(0)
  })

  it('confirm posts the revoke and reloads the list', async () => {
    let revoked = false
    fetchMock.mockImplementation((url, init) => {
      if (String(url).endsWith('/orphaned/ABC123/revoke') && init?.method === 'POST') {
        revoked = true
        return Promise.resolve(json(200, { data: {} }))
      }
      return Promise.resolve(list(revoked ? [] : [makeRow()]))
    })
    renderTab()
    await waitFor(() => screen.getByTestId('orphaned-revoke-btn-ABC123'))
    fireEvent.click(screen.getByTestId('orphaned-revoke-btn-ABC123'))
    fireEvent.click(screen.getByTestId('orphaned-confirm-btn'))
    await waitFor(() => expect(screen.getByTestId('orphaned-empty')).toBeInTheDocument())
    expect(postCalls('/api/v1/credential-requests/orphaned/ABC123/revoke')).toHaveLength(1)
  })

  it('shows the status when revoke fails', async () => {
    fetchMock.mockImplementation((_url, init) =>
      Promise.resolve(init?.method === 'POST' ? json(500, {}) : list([makeRow()])),
    )
    renderTab()
    await waitFor(() => screen.getByTestId('orphaned-revoke-btn-ABC123'))
    fireEvent.click(screen.getByTestId('orphaned-revoke-btn-ABC123'))
    fireEvent.click(screen.getByTestId('orphaned-confirm-btn'))
    await waitFor(() => expect(screen.getByTestId('orphaned-action-error')).toHaveTextContent(/500/))
  })

  it('revoke handles elevation 401 without a presence token', async () => {
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

    const suffix = '/api/v1/credential-requests/orphaned/ABC123/revoke'
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
    await waitFor(() => screen.getByTestId('orphaned-revoke-btn-ABC123'))
    fireEvent.click(screen.getByTestId('orphaned-revoke-btn-ABC123'))
    fireEvent.click(screen.getByTestId('orphaned-confirm-btn'))
    await waitFor(() => screen.getByTestId('step-up-verify-btn'))
    act(() => screen.getByTestId('step-up-verify-btn').click())
    await waitFor(() => expect(postCalls(suffix)).toHaveLength(2))

    const retry = postCalls(suffix)[1]!
    expect(new Headers(retry[1]?.headers).get('X-Presence-Token')).toBeNull()
    expect(screen.queryByTestId('orphaned-action-error')).toBeNull()
  })
})
