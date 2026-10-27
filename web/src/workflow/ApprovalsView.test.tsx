// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz

/*
 * ApprovalsView test suite (Issue #5450, Epic #5300). Real AuthProvider, apiFetch
 * and StepUpModal; only global fetch is stubbed at the network edge.
 */
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'
import { cleanup, fireEvent, render, screen, waitFor } from '@testing-library/react'
import { MemoryRouter } from 'react-router'
import { AuthProvider } from '../auth/AuthContext.tsx'
import ApprovalsView from './ApprovalsView.tsx'

const fetchMock = vi.fn<typeof fetch>()

beforeEach(() => {
  fetchMock.mockReset()
  vi.stubGlobal('fetch', fetchMock)
})

afterEach(() => {
  vi.unstubAllGlobals()
  cleanup()
})

function jsonResponse(status: number, body: unknown = {}, headers: Record<string, string> = {}): Response {
  return new Response(status === 204 ? null : JSON.stringify(body), {
    status,
    headers: { 'Content-Type': 'application/json', ...headers },
  })
}

function makeApproval(overrides: Partial<Record<string, unknown>> = {}) {
  return {
    approval_id: 'appr-1',
    workflow_name: 'onboard-user',
    execution_id: 'exec-1',
    step_id: 'step-1',
    step_name: 'Manager sign-off',
    message: 'Please approve onboarding',
    requested_by: 'alice',
    status: 'pending',
    requested_at: '2026-10-01T00:00:00Z',
    ...overrides,
  }
}

function renderView() {
  return render(
    <MemoryRouter>
      <AuthProvider>
        <ApprovalsView />
      </AuthProvider>
    </MemoryRouter>,
  )
}

function decisionCalls() {
  return fetchMock.mock.calls.filter(
    ([u, init]) => String(u).includes('/decision') && init?.method === 'POST',
  )
}

describe('ApprovalsView', () => {
  it('lists pending approvals in server order', async () => {
    fetchMock.mockResolvedValue(
      jsonResponse(200, {
        data: [makeApproval(), makeApproval({ approval_id: 'appr-2', workflow_name: 'second' })],
      }),
    )
    renderView()
    const rows = await screen.findAllByTestId('approval-row')
    expect(rows).toHaveLength(2)
    expect(rows[0]).toHaveTextContent('onboard-user')
    expect(rows[1]).toHaveTextContent('second')
    expect(String(fetchMock.mock.calls[0]?.[0])).toBe('/api/v1/workflows/approvals')
  })

  it('shows the empty state and a load error', async () => {
    fetchMock.mockResolvedValueOnce(jsonResponse(200, { data: [] }))
    const { unmount } = renderView()
    expect(await screen.findByTestId('approvals-empty')).toBeInTheDocument()
    unmount()
    fetchMock.mockResolvedValueOnce(jsonResponse(500, {}))
    renderView()
    expect(await screen.findByText(/500/)).toBeInTheDocument()
  })

  it('ApprovalsView sends the chosen decision and justification', async () => {
    let decided = false
    fetchMock.mockImplementation((_url, init) => {
      if (init?.method === 'POST') {
        decided = true
        return Promise.resolve(jsonResponse(200, { data: {} }))
      }
      return Promise.resolve(jsonResponse(200, { data: decided ? [] : [makeApproval()] }))
    })
    renderView()
    fireEvent.change(await screen.findByTestId('approval-justification'), {
      target: { value: '  looks fine  ' },
    })
    fireEvent.click(screen.getByTestId('approval-reject-btn'))
    await waitFor(() => expect(decisionCalls()).toHaveLength(1))
    const [url, init] = decisionCalls()[0]!
    expect(String(url)).toBe('/api/v1/workflows/approvals/appr-1/decision')
    expect(JSON.parse(String(init?.body))).toEqual({ decision: 'reject', justification: 'looks fine' })
    expect(await screen.findByTestId('approvals-empty')).toBeInTheDocument()
    expect(screen.getByTestId('approval-notice')).toHaveTextContent(/rejection recorded/i)
  })

  it('sends approve when Approve is chosen', async () => {
    fetchMock.mockImplementation((_url, init) =>
      Promise.resolve(jsonResponse(200, { data: init?.method === 'POST' ? {} : [makeApproval()] })),
    )
    renderView()
    fireEvent.change(await screen.findByTestId('approval-justification'), { target: { value: 'ok' } })
    fireEvent.click(screen.getByTestId('approval-approve-btn'))
    await waitFor(() => expect(decisionCalls()).toHaveLength(1))
    expect(JSON.parse(String(decisionCalls()[0]![1]?.body))).toEqual({
      decision: 'approve',
      justification: 'ok',
    })
  })

  it('requires a justification for both decisions and bounds its length', async () => {
    fetchMock.mockResolvedValue(jsonResponse(200, { data: [makeApproval()] }))
    renderView()
    const input = await screen.findByTestId('approval-justification')
    expect(input).toHaveAttribute('maxlength', '4000')
    fireEvent.change(input, { target: { value: '   ' } })
    fireEvent.click(screen.getByTestId('approval-approve-btn'))
    expect(await screen.findByTestId('approval-row-error')).toHaveTextContent(/justification is required/i)
    fireEvent.click(screen.getByTestId('approval-reject-btn'))
    expect(decisionCalls()).toHaveLength(0)
  })

  it('renders the server error message and keeps the row', async () => {
    fetchMock.mockImplementation((_url, init) =>
      Promise.resolve(
        init?.method === 'POST'
          ? jsonResponse(409, { error: { message: 'already decided' } })
          : jsonResponse(200, { data: [makeApproval()] }),
      ),
    )
    renderView()
    fireEvent.change(await screen.findByTestId('approval-justification'), { target: { value: 'ok' } })
    fireEvent.click(screen.getByTestId('approval-approve-btn'))
    expect(await screen.findByTestId('approval-row-error')).toHaveTextContent('already decided')
    expect(screen.getAllByTestId('approval-row')).toHaveLength(1)
  })

  it('ApprovalsView renders approval fields as text, not HTML', async () => {
    const payload = '<img src=x onerror="alert(1)"><b>bold</b>'
    fetchMock.mockResolvedValue(
      jsonResponse(200, {
        data: [makeApproval({ workflow_name: payload, message: payload, requested_by: payload })],
      }),
    )
    const { container } = renderView()
    await screen.findByTestId('approval-row')
    expect(container.querySelector('img')).toBeNull()
    expect(container.querySelector('b')).toBeNull()
    expect(screen.getByTestId('approval-message').textContent).toBe(payload)
  })

  it('ApprovalsView decision handles elevation 401 without a presence token', async () => {
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
    const beginOptions = {
      data: {
        publicKey: {
          challenge: 'Y2hhbGxlbmdlLWJ5dGVz',
          timeout: 60000,
          rpId: 'localhost',
          allowCredentials: [{ type: 'public-key', id: 'Y3JlZGVudGlhbC1pZA', transports: ['internal'] }],
          userVerification: 'required',
        },
      },
    }
    let elevated = false
    fetchMock.mockImplementation((url, init) => {
      const u = String(url)
      if (u.includes('elevate/begin')) return Promise.resolve(jsonResponse(200, beginOptions))
      if (u.includes('elevate/finish')) {
        elevated = true
        return Promise.resolve(jsonResponse(200, { assurance: 'strong', elevated_at: '2026-01-01T00:00:00Z' }))
      }
      if (init?.method === 'POST') {
        if (!elevated) {
          return Promise.resolve(
            jsonResponse(401, {}, { 'WWW-Authenticate': 'CFGMS-StepUp realm="cfgms", required="strong"' }),
          )
        }
        return Promise.resolve(jsonResponse(200, { data: {} }))
      }
      return Promise.resolve(jsonResponse(200, { data: elevated ? [] : [makeApproval()] }))
    })

    renderView()
    fireEvent.change(await screen.findByTestId('approval-justification'), { target: { value: 'ok' } })
    fireEvent.click(screen.getByTestId('approval-approve-btn'))
    fireEvent.click(await screen.findByTestId('step-up-verify-btn'))

    expect(await screen.findByTestId('approvals-empty')).toBeInTheDocument()
    const posts = decisionCalls()
    expect(posts).toHaveLength(2)
    expect(new Headers(posts[1]?.[1]?.headers).get('X-Presence-Token')).toBeNull()
    expect(fetchMock.mock.calls.some(([u]) => String(u).includes('presence/'))).toBe(false)
  })
})
