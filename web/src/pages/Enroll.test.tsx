// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz

/*
 * Tests for the first-passkey enrollment page (Story #2968).
 *
 * Coverage:
 *  - Token is read from the URL (never from session/storage)
 *  - Server-side token validation (begin) before the ceremony is offered
 *  - WebAuthn create ceremony drives navigator.credentials.create
 *  - Terminal error states: invalid/expired/reused token, already-enrolled account
 *  - Ceremony cancellation returns to ready state (no infinite retry for token errors)
 *  - Success: navigate to '/' after finish responds 201
 */
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'
import { render, screen, waitFor } from '@testing-library/react'
import { fireEvent } from '@testing-library/react'
import { MemoryRouter, Route, Routes } from 'react-router'
import Enroll from './Enroll.tsx'
import { onSessionConfirmed, onSessionExpired } from '../api/client.ts'

// ── Helpers ──────────────────────────────────────────────────────────────────

function jsonResponse(status: number, body: unknown = {}): Response {
  return new Response(status === 204 ? null : JSON.stringify(body), {
    status,
    headers: { 'Content-Type': 'application/json' },
  })
}

const MOCK_ENROLL_OPTIONS = {
  publicKey: {
    challenge: 'Y2hhbGxlbmdlLWJ5dGVz',
    rp: { id: 'localhost', name: 'CFGMS' },
    user: {
      id: 'dXNlci1pZA',
      name: 'admin@msp-a',
      displayName: 'Admin User',
    },
    pubKeyCredParams: [{ type: 'public-key' as const, alg: -7 }],
    timeout: 60000,
    excludeCredentials: [],
    authenticatorSelection: {
      userVerification: 'required' as const,
    },
  },
}

function makeAttestationCredential(): PublicKeyCredential {
  const toArrayBuffer = (s: string) => new TextEncoder().encode(s).buffer as ArrayBuffer
  return {
    id: 'Y3JlZA',
    type: 'public-key',
    rawId: toArrayBuffer('cred'),
    response: {
      clientDataJSON: toArrayBuffer('{"type":"webauthn.create"}'),
      attestationObject: toArrayBuffer('attestation-object'),
      getTransports: () => [],
    } as unknown as AuthenticatorAttestationResponse,
    getClientExtensionResults: () => ({} as AuthenticationExtensionsClientOutputs),
    authenticatorAttachment: null,
    toJSON: () => ({}),
  } as unknown as PublicKeyCredential
}

/** Render Enroll at /enroll/<token>, with a mock navigate target. */
function renderEnroll(token = 'abc123') {
  const navLog: string[] = []

  const { unmount } = render(
    <MemoryRouter initialEntries={[`/enroll/${token}`]}>
      <Routes>
        <Route path="/enroll/:token" element={<Enroll />} />
        <Route path="/" element={<div data-testid="app-root">APP</div>} />
      </Routes>
    </MemoryRouter>,
  )

  return { navLog, unmount }
}

// ── Setup ────────────────────────────────────────────────────────────────────

const fetchMock = vi.fn<typeof fetch>()

beforeEach(() => {
  fetchMock.mockReset()
  vi.stubGlobal('fetch', fetchMock)
  onSessionConfirmed(null)
  onSessionExpired(null)
})

afterEach(() => {
  vi.unstubAllGlobals()
})

// ── Token read from URL ───────────────────────────────────────────────────────

describe('token source', () => {
  it('reads token from the URL and sends it as X-Enrollment-Token on the begin POST', async () => {
    fetchMock.mockResolvedValue(jsonResponse(200, MOCK_ENROLL_OPTIONS))

    renderEnroll('magic-token-abc123')

    await waitFor(() => {
      const call = fetchMock.mock.calls.find((c) =>
        String(c[0]).includes('/api/v1/web/passkey/enroll/begin'),
      )
      expect(call).toBeDefined()
      const headers = new Headers(call?.[1]?.headers)
      expect(headers.get('X-Enrollment-Token')).toBe('magic-token-abc123')
    })
  })

  it('shows validating state while the begin request is in flight', () => {
    // never resolves
    fetchMock.mockImplementation(() => new Promise(() => {}))

    renderEnroll('tok')

    expect(screen.getByText(/validating your link/i)).toBeInTheDocument()
  })

  it('never reads the token from sessionStorage or localStorage', async () => {
    const getItem = vi.spyOn(Storage.prototype, 'getItem')
    fetchMock.mockResolvedValue(jsonResponse(200, MOCK_ENROLL_OPTIONS))

    renderEnroll('tok-url')

    await waitFor(() => screen.getByRole('button', { name: /register a passkey/i }))
    expect(getItem).not.toHaveBeenCalled()
    getItem.mockRestore()
  })
})

// ── Server-side token validation ──────────────────────────────────────────────

describe('token validation', () => {
  it('shows the register button after the server confirms the token is valid', async () => {
    fetchMock.mockResolvedValue(jsonResponse(200, MOCK_ENROLL_OPTIONS))

    renderEnroll()

    await waitFor(() =>
      expect(screen.getByRole('button', { name: /register a passkey/i })).toBeInTheDocument(),
    )
  })

  it('shows a terminal error when the begin request returns 401 (invalid/expired token)', async () => {
    fetchMock.mockResolvedValue(jsonResponse(401))

    renderEnroll()

    await waitFor(() =>
      expect(screen.getByRole('alert')).toHaveTextContent(/invalid or has already been used/i),
    )
    expect(screen.queryByRole('button', { name: /register/i })).not.toBeInTheDocument()
  })

  it('shows a terminal error when the begin request returns 400', async () => {
    fetchMock.mockResolvedValue(jsonResponse(400))

    renderEnroll()

    await waitFor(() =>
      expect(screen.getByRole('alert')).toHaveTextContent(/invalid or has already been used/i),
    )
  })

  it('shows a generic error when the begin request returns 503', async () => {
    fetchMock.mockResolvedValue(jsonResponse(503))

    renderEnroll()

    await waitFor(() =>
      expect(screen.getByRole('alert')).toHaveTextContent(/try again later/i),
    )
  })

  it('does not offer the ceremony before the begin response arrives', () => {
    fetchMock.mockImplementation(() => new Promise(() => {}))

    renderEnroll()

    expect(screen.queryByRole('button', { name: /register/i })).not.toBeInTheDocument()
  })
})

// ── WebAuthn create ceremony ──────────────────────────────────────────────────

describe('WebAuthn create ceremony', () => {
  it('calls navigator.credentials.create with the server-provided options', async () => {
    const credCreate = vi.fn().mockResolvedValue(makeAttestationCredential())
    vi.stubGlobal('navigator', { credentials: { create: credCreate } })

    fetchMock.mockImplementation((input) => {
      const url = String(input)
      if (url.includes('/enroll/begin')) return Promise.resolve(jsonResponse(200, MOCK_ENROLL_OPTIONS))
      return Promise.resolve(jsonResponse(201))
    })

    renderEnroll()
    await waitFor(() => screen.getByRole('button', { name: /register a passkey/i }))

    fireEvent.click(screen.getByRole('button', { name: /register a passkey/i }))

    await waitFor(() => expect(credCreate).toHaveBeenCalledOnce())
    const createArgs = credCreate.mock.calls[0]?.[0] as PublicKeyCredentialCreationOptions
    expect(createArgs.publicKey).toBeDefined()
    const pk = createArgs.publicKey!
    // Challenge is decoded from base64url string to a typed byte buffer
    expect(pk.challenge).toBeInstanceOf(Uint8Array)
    // user.id is decoded from base64url string to a typed byte buffer
    expect(pk.user?.id).toBeInstanceOf(Uint8Array)
    expect(pk.rp?.name).toBe('CFGMS')
  })

  it('sends the attestation to the finish endpoint with X-Enrollment-Token', async () => {
    const mockCred = makeAttestationCredential()
    vi.stubGlobal('navigator', { credentials: { create: vi.fn().mockResolvedValue(mockCred) } })

    fetchMock.mockImplementation((input) => {
      const url = String(input)
      if (url.includes('/enroll/begin')) return Promise.resolve(jsonResponse(200, MOCK_ENROLL_OPTIONS))
      if (url.includes('/enroll/finish')) return Promise.resolve(jsonResponse(201))
      return Promise.resolve(jsonResponse(200))
    })

    renderEnroll('the-magic-token')
    await waitFor(() => screen.getByRole('button', { name: /register a passkey/i }))

    fireEvent.click(screen.getByRole('button', { name: /register a passkey/i }))

    await waitFor(() => {
      const finishCall = fetchMock.mock.calls.find((c) =>
        String(c[0]).includes('/enroll/finish'),
      )
      expect(finishCall).toBeDefined()
      const headers = new Headers(finishCall?.[1]?.headers)
      expect(headers.get('X-Enrollment-Token')).toBe('the-magic-token')
      const body = JSON.parse(String(finishCall?.[1]?.body)) as Record<string, unknown>
      expect(body.type).toBe('public-key')
      expect(typeof body.id).toBe('string')
    })
  })

  it('shows the waiting state while the ceremony is in progress', async () => {
    let resolveCreate!: (c: PublicKeyCredential) => void
    const credCreate = vi.fn(
      () => new Promise<PublicKeyCredential>((r) => { resolveCreate = r }),
    )
    vi.stubGlobal('navigator', { credentials: { create: credCreate } })

    fetchMock.mockResolvedValue(jsonResponse(200, MOCK_ENROLL_OPTIONS))

    renderEnroll()
    await waitFor(() => screen.getByRole('button', { name: /register a passkey/i }))

    fireEvent.click(screen.getByRole('button', { name: /register a passkey/i }))

    await waitFor(() =>
      expect(screen.getByText(/waiting for your passkey/i)).toBeInTheDocument(),
    )

    // Resolve to unblock cleanup
    resolveCreate(makeAttestationCredential())
  })
})

// ── Terminal error states ─────────────────────────────────────────────────────

describe('terminal error states', () => {
  it('shows terminal error when finish returns 409 (already enrolled)', async () => {
    vi.stubGlobal('navigator', {
      credentials: { create: vi.fn().mockResolvedValue(makeAttestationCredential()) },
    })

    fetchMock.mockImplementation((input) => {
      const url = String(input)
      if (url.includes('/enroll/begin')) return Promise.resolve(jsonResponse(200, MOCK_ENROLL_OPTIONS))
      return Promise.resolve(jsonResponse(409))
    })

    renderEnroll()
    await waitFor(() => screen.getByRole('button', { name: /register a passkey/i }))

    fireEvent.click(screen.getByRole('button', { name: /register a passkey/i }))

    await waitFor(() =>
      expect(screen.getByRole('alert')).toHaveTextContent(/already has a passkey enrolled/i),
    )
  })

  it('shows terminal error when finish returns 410 (token revoked)', async () => {
    vi.stubGlobal('navigator', {
      credentials: { create: vi.fn().mockResolvedValue(makeAttestationCredential()) },
    })

    fetchMock.mockImplementation((input) => {
      const url = String(input)
      if (url.includes('/enroll/begin')) return Promise.resolve(jsonResponse(200, MOCK_ENROLL_OPTIONS))
      return Promise.resolve(jsonResponse(410))
    })

    renderEnroll()
    await waitFor(() => screen.getByRole('button', { name: /register a passkey/i }))

    fireEvent.click(screen.getByRole('button', { name: /register a passkey/i }))

    await waitFor(() =>
      expect(screen.getByRole('alert')).toHaveTextContent(/revoked/i),
    )
  })

  it('shows terminal error when finish returns 400 (link already used)', async () => {
    vi.stubGlobal('navigator', {
      credentials: { create: vi.fn().mockResolvedValue(makeAttestationCredential()) },
    })

    fetchMock.mockImplementation((input) => {
      const url = String(input)
      if (url.includes('/enroll/begin')) return Promise.resolve(jsonResponse(200, MOCK_ENROLL_OPTIONS))
      return Promise.resolve(jsonResponse(400))
    })

    renderEnroll()
    await waitFor(() => screen.getByRole('button', { name: /register a passkey/i }))

    fireEvent.click(screen.getByRole('button', { name: /register a passkey/i }))

    await waitFor(() =>
      expect(screen.getByRole('alert')).toHaveTextContent(/already been used/i),
    )
  })

  it('terminal error state has no retry button', async () => {
    fetchMock.mockResolvedValue(jsonResponse(401))

    renderEnroll()

    await waitFor(() => screen.getByRole('alert'))
    expect(screen.queryByRole('button', { name: /try again/i })).not.toBeInTheDocument()
    expect(screen.queryByRole('button', { name: /register/i })).not.toBeInTheDocument()
  })
})

// ── Ceremony cancellation ─────────────────────────────────────────────────────

describe('ceremony cancellation', () => {
  it('returns to ready state when the user cancels the WebAuthn ceremony', async () => {
    const credCreate = vi.fn().mockRejectedValue(
      new DOMException('User cancelled', 'NotAllowedError'),
    )
    vi.stubGlobal('navigator', { credentials: { create: credCreate } })

    fetchMock.mockResolvedValue(jsonResponse(200, MOCK_ENROLL_OPTIONS))

    renderEnroll()
    await waitFor(() => screen.getByRole('button', { name: /register a passkey/i }))

    fireEvent.click(screen.getByRole('button', { name: /register a passkey/i }))

    // After cancellation, the button should reappear (not a terminal error)
    await waitFor(() =>
      expect(screen.getByRole('button', { name: /register a passkey/i })).toBeInTheDocument(),
    )
    expect(screen.queryByRole('alert')).not.toBeInTheDocument()
  })
})

// ── Success routing ───────────────────────────────────────────────────────────

describe('success routing', () => {
  it('navigates to / after a successful enrollment (finish returns 201)', async () => {
    vi.stubGlobal('navigator', {
      credentials: { create: vi.fn().mockResolvedValue(makeAttestationCredential()) },
    })

    fetchMock.mockImplementation((input) => {
      const url = String(input)
      if (url.includes('/enroll/begin')) return Promise.resolve(jsonResponse(200, MOCK_ENROLL_OPTIONS))
      if (url.includes('/enroll/finish')) return Promise.resolve(jsonResponse(201))
      return Promise.resolve(jsonResponse(200))
    })

    renderEnroll()
    await waitFor(() => screen.getByRole('button', { name: /register a passkey/i }))

    fireEvent.click(screen.getByRole('button', { name: /register a passkey/i }))

    await waitFor(() =>
      expect(screen.getByTestId('app-root')).toBeInTheDocument(),
    )
  })

  it('fires the onSessionConfirmed listener via apiFetch on the finish call', async () => {
    const confirmed = vi.fn()
    onSessionConfirmed(confirmed)

    vi.stubGlobal('navigator', {
      credentials: { create: vi.fn().mockResolvedValue(makeAttestationCredential()) },
    })

    fetchMock.mockImplementation((input) => {
      const url = String(input)
      if (url.includes('/enroll/begin')) return Promise.resolve(jsonResponse(200, MOCK_ENROLL_OPTIONS))
      if (url.includes('/enroll/finish')) return Promise.resolve(jsonResponse(201))
      return Promise.resolve(jsonResponse(200))
    })

    renderEnroll()
    await waitFor(() => screen.getByRole('button', { name: /register a passkey/i }))

    fireEvent.click(screen.getByRole('button', { name: /register a passkey/i }))

    await waitFor(() => expect(confirmed).toHaveBeenCalled())
  })
})
