// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'
import { act, render, screen, waitFor } from '@testing-library/react'
import StepUpModal from './StepUpModal.tsx'
import type { StepUpRequest } from '../api/client.ts'

// ── Helpers ──────────────────────────────────────────────────────────────────

function jsonResponse(status: number, body: unknown = {}): Response {
  return new Response(status === 204 ? null : JSON.stringify(body), {
    status,
    headers: { 'Content-Type': 'application/json' },
  })
}

/** Minimal presence/begin options JSON (matches go-webauthn CredentialAssertion shape). */
const MOCK_BEGIN_OPTIONS = {
  publicKey: {
    challenge: 'Y2hhbGxlbmdlLWJ5dGVz',
    timeout: 60000,
    rpId: 'localhost',
    allowCredentials: [
      {
        type: 'public-key' as const,
        id: 'Y3JlZGVudGlhbC1pZA',
        transports: ['internal'],
      },
    ],
    userVerification: 'required' as const,
  },
}

/** Minimal PublicKeyCredential stub matching the shape StepUpModal expects. */
function makePublicKeyCredential(id = 'cred-id-b64u'): PublicKeyCredential {
  const toArrayBuffer = (s: string) => new TextEncoder().encode(s).buffer as ArrayBuffer
  return {
    id,
    type: 'public-key',
    rawId: toArrayBuffer(id),
    response: {
      clientDataJSON: toArrayBuffer('{"type":"webauthn.get"}'),
      authenticatorData: toArrayBuffer('authenticator-data'),
      signature: toArrayBuffer('signature'),
      userHandle: null,
    } as AuthenticatorAssertionResponse,
    getClientExtensionResults: () => ({} as AuthenticationExtensionsClientOutputs),
    authenticatorAttachment: null,
    toJSON: () => ({}),
  } as unknown as PublicKeyCredential
}

const defaultRequest: StepUpRequest = {
  path: '/api/v1/modules/approvals/cfgms:test:1.0.0:AAAA/approve',
  init: { method: 'POST', body: JSON.stringify({ note: 'lgtm' }) },
  presenceRequired: true,
}

const fetchMock = vi.fn<typeof fetch>()

beforeEach(() => {
  fetchMock.mockReset()
  vi.stubGlobal('fetch', fetchMock)
})

afterEach(() => {
  vi.unstubAllGlobals()
})

// ── Loading and waiting states ────────────────────────────────────────────────

describe('StepUpModal — initial states', () => {
  it('shows a disabled "Preparing…" button while fetching the challenge', () => {
    // Presence/begin never resolves so the modal stays in loading state.
    fetchMock.mockReturnValue(new Promise(() => undefined))
    render(
      <StepUpModal
        request={defaultRequest}
        principalUsername="admin@msp-a"
        onSuccess={vi.fn()}
        onCancel={vi.fn()}
      />,
    )
    expect(screen.getByRole('button', { name: /preparing/i })).toBeDisabled()
  })

  it('shows "Verify with passkey" button after challenge arrives', async () => {
    fetchMock.mockResolvedValueOnce(jsonResponse(200, MOCK_BEGIN_OPTIONS))
    render(
      <StepUpModal
        request={defaultRequest}
        principalUsername="admin@msp-a"
        onSuccess={vi.fn()}
        onCancel={vi.fn()}
      />,
    )
    await waitFor(() =>
      expect(
        screen.getByTestId('step-up-verify-btn'),
      ).toBeInTheDocument(),
    )
  })

  it('shows the principal username in the description', async () => {
    fetchMock.mockResolvedValueOnce(jsonResponse(200, MOCK_BEGIN_OPTIONS))
    render(
      <StepUpModal
        request={defaultRequest}
        principalUsername="admin@msp-a"
        onSuccess={vi.fn()}
        onCancel={vi.fn()}
      />,
    )
    await waitFor(() =>
      expect(screen.getByText(/admin@msp-a/)).toBeInTheDocument(),
    )
  })

  it('shows error state when presence/begin fails', async () => {
    fetchMock.mockResolvedValueOnce(jsonResponse(403, { error: 'forbidden' }))
    render(
      <StepUpModal
        request={defaultRequest}
        principalUsername={null}
        onSuccess={vi.fn()}
        onCancel={vi.fn()}
      />,
    )
    await waitFor(() =>
      expect(screen.getByTestId('step-up-error')).toBeInTheDocument(),
    )
    expect(screen.getByTestId('step-up-retry-btn')).toBeInTheDocument()
  })
})

// ── Cancel ───────────────────────────────────────────────────────────────────

describe('StepUpModal — cancel', () => {
  it('calls onCancel when the cancel button is clicked', async () => {
    fetchMock.mockResolvedValueOnce(jsonResponse(200, MOCK_BEGIN_OPTIONS))
    const onCancel = vi.fn()
    render(
      <StepUpModal
        request={defaultRequest}
        principalUsername="admin@msp-a"
        onSuccess={vi.fn()}
        onCancel={onCancel}
      />,
    )
    // Wait for waiting state so Cancel is enabled.
    await waitFor(() => screen.getByTestId('step-up-verify-btn'))
    act(() => screen.getByTestId('step-up-cancel-btn').click())
    expect(onCancel).toHaveBeenCalledTimes(1)
  })

  it('cancel button is disabled while ceremony is in progress', async () => {
    fetchMock.mockResolvedValueOnce(jsonResponse(200, MOCK_BEGIN_OPTIONS))
    // credentials.get never resolves → keeps modal in 'running' phase.
    vi.stubGlobal('navigator', {
      credentials: { get: vi.fn(() => new Promise(() => undefined)) },
    })
    render(
      <StepUpModal
        request={defaultRequest}
        principalUsername={null}
        onSuccess={vi.fn()}
        onCancel={vi.fn()}
      />,
    )
    await waitFor(() => screen.getByTestId('step-up-verify-btn'))
    act(() => screen.getByTestId('step-up-verify-btn').click())
    await waitFor(() =>
      expect(screen.getByTestId('step-up-cancel-btn')).toBeDisabled(),
    )
  })
})

// ── Successful ceremony ───────────────────────────────────────────────────────

describe('StepUpModal — successful assertion', () => {
  it('calls onSuccess with the retry response after full ceremony', async () => {
    const mockCred = makePublicKeyCredential()
    vi.stubGlobal('navigator', {
      credentials: { get: vi.fn().mockResolvedValue(mockCred) },
    })

    const retryResponse = jsonResponse(200, { ok: true })
    fetchMock.mockImplementation((url) => {
      const u = String(url)
      if (u.includes('presence/begin')) return Promise.resolve(jsonResponse(200, MOCK_BEGIN_OPTIONS))
      if (u.includes('presence/finish')) {
        return Promise.resolve(
          jsonResponse(200, { presence_token: 'tok-abc123', expires_in: 30 }),
        )
      }
      // retry of the original request
      return Promise.resolve(retryResponse)
    })

    const onSuccess = vi.fn()
    render(
      <StepUpModal
        request={defaultRequest}
        principalUsername="admin@msp-a"
        onSuccess={onSuccess}
        onCancel={vi.fn()}
      />,
    )

    await waitFor(() => screen.getByTestId('step-up-verify-btn'))
    act(() => screen.getByTestId('step-up-verify-btn').click())

    await waitFor(() => expect(onSuccess).toHaveBeenCalledTimes(1))
    const [response] = onSuccess.mock.calls[0] as [Response]
    expect(response.status).toBe(200)
  })

  it('sends X-Presence-Token header on the retry request', async () => {
    const mockCred = makePublicKeyCredential()
    vi.stubGlobal('navigator', {
      credentials: { get: vi.fn().mockResolvedValue(mockCred) },
    })

    fetchMock.mockImplementation((url) => {
      const u = String(url)
      if (u.includes('presence/begin')) return Promise.resolve(jsonResponse(200, MOCK_BEGIN_OPTIONS))
      if (u.includes('presence/finish')) {
        return Promise.resolve(
          jsonResponse(200, { presence_token: 'test-presence-token', expires_in: 30 }),
        )
      }
      return Promise.resolve(jsonResponse(200, {}))
    })

    const onSuccess = vi.fn()
    render(
      <StepUpModal
        request={defaultRequest}
        principalUsername={null}
        onSuccess={onSuccess}
        onCancel={vi.fn()}
      />,
    )

    await waitFor(() => screen.getByTestId('step-up-verify-btn'))
    act(() => screen.getByTestId('step-up-verify-btn').click())
    await waitFor(() => expect(onSuccess).toHaveBeenCalledTimes(1))

    // Find the retry call (the one that's not begin or finish).
    const retryCalls = fetchMock.mock.calls.filter(
      ([u]) =>
        !String(u).includes('presence/begin') && !String(u).includes('presence/finish'),
    )
    expect(retryCalls.length).toBe(1)
    const retryHeaders = new Headers(retryCalls[0]?.[1]?.headers)
    expect(retryHeaders.get('X-Presence-Token')).toBe('test-presence-token')
  })
})

// ── Assertion failure / cancel ────────────────────────────────────────────────

describe('StepUpModal — assertion failure', () => {
  it('shows error when credentials.get() throws NotAllowedError (user cancelled)', async () => {
    vi.stubGlobal('navigator', {
      credentials: {
        get: vi.fn().mockRejectedValue(
          new DOMException('User cancelled', 'NotAllowedError'),
        ),
      },
    })

    fetchMock.mockResolvedValueOnce(jsonResponse(200, MOCK_BEGIN_OPTIONS))
    render(
      <StepUpModal
        request={defaultRequest}
        principalUsername={null}
        onSuccess={vi.fn()}
        onCancel={vi.fn()}
      />,
    )

    await waitFor(() => screen.getByTestId('step-up-verify-btn'))
    act(() => screen.getByTestId('step-up-verify-btn').click())

    await waitFor(() =>
      expect(screen.getByTestId('step-up-error')).toBeInTheDocument(),
    )
    expect(screen.getByTestId('step-up-error').textContent).toMatch(/cancelled/i)
  })

  it('shows error when presence/finish fails', async () => {
    const mockCred = makePublicKeyCredential()
    vi.stubGlobal('navigator', {
      credentials: { get: vi.fn().mockResolvedValue(mockCred) },
    })

    fetchMock.mockImplementation((url) => {
      const u = String(url)
      if (u.includes('presence/begin')) return Promise.resolve(jsonResponse(200, MOCK_BEGIN_OPTIONS))
      if (u.includes('presence/finish')) return Promise.resolve(jsonResponse(400, { error: 'WEBAUTHN_VERIFY_ERROR' }))
      return Promise.resolve(jsonResponse(200, {}))
    })

    render(
      <StepUpModal
        request={defaultRequest}
        principalUsername={null}
        onSuccess={vi.fn()}
        onCancel={vi.fn()}
      />,
    )

    await waitFor(() => screen.getByTestId('step-up-verify-btn'))
    act(() => screen.getByTestId('step-up-verify-btn').click())

    await waitFor(() =>
      expect(screen.getByTestId('step-up-error')).toBeInTheDocument(),
    )
    expect(screen.getByTestId('step-up-retry-btn')).toBeInTheDocument()
  })

  it('does not call onSuccess or onCancel after assertion failure', async () => {
    vi.stubGlobal('navigator', {
      credentials: {
        get: vi.fn().mockRejectedValue(new DOMException('fail', 'NotAllowedError')),
      },
    })

    fetchMock.mockResolvedValueOnce(jsonResponse(200, MOCK_BEGIN_OPTIONS))
    const onSuccess = vi.fn()
    const onCancel = vi.fn()
    render(
      <StepUpModal
        request={defaultRequest}
        principalUsername={null}
        onSuccess={onSuccess}
        onCancel={onCancel}
      />,
    )

    await waitFor(() => screen.getByTestId('step-up-verify-btn'))
    act(() => screen.getByTestId('step-up-verify-btn').click())
    await waitFor(() => screen.getByTestId('step-up-error'))

    expect(onSuccess).not.toHaveBeenCalled()
    expect(onCancel).not.toHaveBeenCalled()
  })
})

// ── Retry ─────────────────────────────────────────────────────────────────────

describe('StepUpModal — retry', () => {
  it('calls presence/begin again when Try again is clicked', async () => {
    fetchMock
      .mockResolvedValueOnce(jsonResponse(403, { error: 'forbidden' }))
      .mockResolvedValueOnce(jsonResponse(200, MOCK_BEGIN_OPTIONS))

    render(
      <StepUpModal
        request={defaultRequest}
        principalUsername={null}
        onSuccess={vi.fn()}
        onCancel={vi.fn()}
      />,
    )

    // First begin fails → error state.
    await waitFor(() => screen.getByTestId('step-up-retry-btn'))
    act(() => screen.getByTestId('step-up-retry-btn').click())

    // Second begin succeeds → waiting state.
    await waitFor(() => screen.getByTestId('step-up-verify-btn'))
    const beginCalls = fetchMock.mock.calls.filter(([u]) =>
      String(u).includes('presence/begin'),
    )
    expect(beginCalls.length).toBe(2)
  })
})

// ── Accessibility: no click-outside dismissal ─────────────────────────────────

describe('StepUpModal — security constraints', () => {
  it('clicking the backdrop does NOT call onCancel', async () => {
    fetchMock.mockResolvedValueOnce(jsonResponse(200, MOCK_BEGIN_OPTIONS))
    const onCancel = vi.fn()
    render(
      <StepUpModal
        request={defaultRequest}
        principalUsername={null}
        onSuccess={vi.fn()}
        onCancel={onCancel}
      />,
    )

    await waitFor(() => screen.getByTestId('step-up-verify-btn'))
    // Click directly on the overlay element (not a button inside).
    act(() => screen.getByTestId('step-up-overlay').click())
    expect(onCancel).not.toHaveBeenCalled()
  })

  it('renders with role=dialog and aria-modal=true', async () => {
    fetchMock.mockResolvedValueOnce(jsonResponse(200, MOCK_BEGIN_OPTIONS))
    render(
      <StepUpModal
        request={defaultRequest}
        principalUsername={null}
        onSuccess={vi.fn()}
        onCancel={vi.fn()}
      />,
    )
    await waitFor(() => screen.getByRole('dialog'))
    expect(screen.getByRole('dialog')).toHaveAttribute('aria-modal', 'true')
  })
})
