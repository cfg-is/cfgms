// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz

/*
 * ApiKeysView test suite (Issue #5441, Epic #5300). Real AuthProvider, apiFetch
 * and StepUpModal; only global fetch is stubbed at the network edge.
 */
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'
import { cleanup, fireEvent, render, screen, waitFor } from '@testing-library/react'
import { MemoryRouter } from 'react-router'
import { AuthProvider } from '../auth/AuthContext.tsx'
import ApiKeysView from './ApiKeysView.tsx'

const fetchMock = vi.fn<typeof fetch>()

beforeEach(() => {
  fetchMock.mockReset()
  vi.stubGlobal('fetch', fetchMock)
})

afterEach(() => {
  vi.unstubAllGlobals()
  cleanup()
  localStorage.clear()
})

function jsonResponse(status: number, body: unknown = {}, headers: Record<string, string> = {}): Response {
  return new Response(status === 204 ? null : JSON.stringify(body), {
    status,
    headers: { 'Content-Type': 'application/json', ...headers },
  })
}

function makeKey(overrides: Partial<Record<string, unknown>> = {}) {
  return {
    id: 'key-abc123',
    name: 'ci-deploy',
    permissions: ['steward:list', 'steward:read'],
    created_at: '2026-10-01T00:00:00Z',
    tenant_id: 'msp-a',
    ...overrides,
  }
}

const SECRET = 'cfgms_live_SECRETVALUE123'

function renderView() {
  return render(
    <MemoryRouter>
      <AuthProvider>
        <ApiKeysView />
      </AuthProvider>
    </MemoryRouter>,
  )
}

function callsTo(method: string) {
  return fetchMock.mock.calls.filter(([u, init]) => {
    return String(u).startsWith('/api/v1/api-keys') && (init?.method ?? 'GET') === method
  })
}

async function createKey(name = 'ci-deploy', perms = 'steward:list\nsteward:read, extra:x') {
  fireEvent.change(await screen.findByTestId('api-key-name'), { target: { value: name } })
  fireEvent.change(screen.getByTestId('api-key-permissions'), { target: { value: perms } })
  fireEvent.click(screen.getByTestId('api-key-create-btn'))
}

describe('ApiKeysView list', () => {
  it('shows id, name, scope, created and expiry and never a secret', async () => {
    fetchMock.mockResolvedValue(
      jsonResponse(200, {
        data: [makeKey({ key: SECRET, expires_at: '2027-01-01T00:00:00Z' }), makeKey({ id: 'key-2', name: '' })],
      }),
    )
    renderView()
    const rows = await screen.findAllByTestId('api-key-row')
    expect(rows).toHaveLength(2)
    expect(screen.getAllByTestId('api-key-id')[0]).toHaveTextContent('key-abc123')
    expect(screen.getAllByTestId('api-key-name-cell')[0]).toHaveTextContent('ci-deploy')
    expect(screen.getAllByTestId('api-key-scope')[0]).toHaveTextContent('steward:list, steward:read')
    expect(screen.getAllByTestId('api-key-created')[0]).toHaveTextContent('2026-10-01T00:00:00Z')
    expect(screen.getAllByTestId('api-key-expires')[0]).toHaveTextContent('2027-01-01T00:00:00Z')
    expect(screen.getAllByTestId('api-key-expires')[1]).toHaveTextContent('—')
    expect(document.body.textContent).not.toContain(SECRET)
  })

  it('renders markup in wire values as text only', async () => {
    fetchMock.mockResolvedValue(jsonResponse(200, { data: [makeKey({ name: '<img src=x onerror=alert(1)>' })] }))
    renderView()
    expect(await screen.findByTestId('api-key-name-cell')).toHaveTextContent('<img src=x onerror=alert(1)>')
    expect(document.querySelector('img')).toBeNull()
  })

  it('shows the empty state and an error card on failure', async () => {
    fetchMock.mockResolvedValueOnce(jsonResponse(200, { data: [] }))
    renderView()
    expect(await screen.findByTestId('api-keys-empty')).toBeInTheDocument()
    cleanup()
    fetchMock.mockResolvedValueOnce(jsonResponse(500))
    renderView()
    expect(await screen.findByText(/couldn't load api keys/i)).toBeInTheDocument()
  })
})

describe('ApiKeysView create', () => {
  it('ApiKeysView create shows secret once and clears it on close', async () => {
    const writeText = vi.fn().mockResolvedValue(undefined)
    vi.stubGlobal('navigator', { clipboard: { writeText } })
    let created = false
    fetchMock.mockImplementation((_url, init) => {
      if (init?.method === 'POST') {
        created = true
        return Promise.resolve(jsonResponse(201, { data: { ...makeKey(), key: SECRET } }))
      }
      return Promise.resolve(jsonResponse(200, { data: created ? [makeKey()] : [] }))
    })
    renderView()
    await createKey()

    const field = (await screen.findByTestId('api-key-secret-value')) as HTMLInputElement
    expect(field.value).toBe(SECRET)
    expect(field.readOnly).toBe(true)

    const init = callsTo('POST')[0]?.[1]
    expect(JSON.parse(String(init?.body))).toEqual({
      name: 'ci-deploy',
      permissions: ['steward:list', 'steward:read', 'extra:x'],
    })

    fireEvent.click(screen.getByTestId('api-key-copy-btn'))
    await waitFor(() => expect(writeText).toHaveBeenCalledWith(SECRET))

    // The refreshed list never carries the secret.
    await screen.findByTestId('api-key-row')
    expect(screen.getAllByDisplayValue(SECRET)).toHaveLength(1)

    fireEvent.click(screen.getByTestId('api-key-secret-close-btn'))
    expect(screen.queryByTestId('api-key-secret-panel')).toBeNull()
    expect(document.body.textContent).not.toContain(SECRET)
    expect(screen.queryByDisplayValue(SECRET)).toBeNull()
    expect(JSON.stringify({ ...localStorage })).not.toContain(SECRET)
    expect(JSON.stringify({ ...sessionStorage })).not.toContain(SECRET)
    expect(window.location.href).not.toContain(SECRET)
  })

  it('shows the server error verbatim and no secret panel', async () => {
    fetchMock.mockImplementation((_url, init) =>
      Promise.resolve(
        init?.method === 'POST'
          ? jsonResponse(400, { error: { message: 'unknown permission: extra:x' } })
          : jsonResponse(200, { data: [] }),
      ),
    )
    renderView()
    await createKey()
    expect(await screen.findByTestId('api-key-create-error')).toHaveTextContent('unknown permission: extra:x')
    expect(screen.queryByTestId('api-key-secret-panel')).toBeNull()
  })

  it('requires a name before sending', async () => {
    fetchMock.mockResolvedValue(jsonResponse(200, { data: [] }))
    renderView()
    await createKey('  ')
    expect(await screen.findByTestId('api-key-create-error')).toHaveTextContent(/name is required/i)
    expect(callsTo('POST')).toHaveLength(0)
  })

  it('ApiKeysView create handles elevation 401 without a presence token', async () => {
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
        return Promise.resolve(jsonResponse(201, { data: { ...makeKey(), key: SECRET } }))
      }
      return Promise.resolve(jsonResponse(200, { data: [] }))
    })

    renderView()
    await createKey()
    fireEvent.click(await screen.findByTestId('step-up-verify-btn'))

    expect(await screen.findByTestId('api-key-secret-value')).toHaveProperty('value', SECRET)
    const posts = callsTo('POST')
    expect(posts).toHaveLength(2)
    const retry = posts[1]?.[1]
    expect(new Headers(retry?.headers).get('X-Presence-Token')).toBeNull()
    expect(fetchMock.mock.calls.some(([u]) => String(u).includes('presence/'))).toBe(false)
  })
})

describe('ApiKeysView delete', () => {
  it('ApiKeysView delete requires the inline confirm before sending', async () => {
    let deleted = false
    fetchMock.mockImplementation((_url, init) => {
      if (init?.method === 'DELETE') {
        deleted = true
        return Promise.resolve(jsonResponse(204))
      }
      return Promise.resolve(jsonResponse(200, { data: deleted ? [] : [makeKey()] }))
    })
    renderView()
    fireEvent.click(await screen.findByTestId('api-key-delete-btn-key-abc123'))
    expect(screen.getByTestId('api-key-confirm-row')).toBeInTheDocument()
    expect(callsTo('DELETE')).toHaveLength(0)

    // Cancel sends nothing and restores the button.
    fireEvent.click(screen.getByTestId('api-key-cancel-btn'))
    expect(screen.queryByTestId('api-key-confirm-row')).toBeNull()
    expect(callsTo('DELETE')).toHaveLength(0)

    fireEvent.click(screen.getByTestId('api-key-delete-btn-key-abc123'))
    fireEvent.click(screen.getByTestId('api-key-confirm-btn'))
    await waitFor(() => expect(callsTo('DELETE')).toHaveLength(1))
    expect(String(callsTo('DELETE')[0]?.[0])).toBe('/api/v1/api-keys/key-abc123')
    expect(await screen.findByTestId('api-keys-empty')).toBeInTheDocument()
  })

  it('shows the server error when delete fails and keeps the row', async () => {
    fetchMock.mockImplementation((_url, init) =>
      Promise.resolve(
        init?.method === 'DELETE'
          ? jsonResponse(403, { error: { message: 'forbidden by policy' } })
          : jsonResponse(200, { data: [makeKey()] }),
      ),
    )
    renderView()
    fireEvent.click(await screen.findByTestId('api-key-delete-btn-key-abc123'))
    fireEvent.click(screen.getByTestId('api-key-confirm-btn'))
    expect(await screen.findByTestId('api-key-delete-error')).toHaveTextContent('forbidden by policy')
    expect(screen.getByTestId('api-key-row')).toBeInTheDocument()
  })
})
