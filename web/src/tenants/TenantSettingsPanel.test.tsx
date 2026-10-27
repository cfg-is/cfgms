// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz

/*
 * TenantSettingsPanel tests (Issue #5444). Real AuthProvider, apiFetch and
 * StepUpModal; only the network edge (global fetch) and the WebAuthn browser
 * API are stubbed.
 */
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'
import { cleanup, fireEvent, render, screen, waitFor } from '@testing-library/react'
import { MemoryRouter } from 'react-router'
import { AuthProvider } from '../auth/AuthContext.tsx'
import TenantSettingsPanel from './TenantSettingsPanel.tsx'

const fetchMock = vi.fn<typeof fetch>()

beforeEach(() => {
  vi.stubGlobal('fetch', fetchMock)
  fetchMock.mockReset()
})

afterEach(() => {
  vi.unstubAllGlobals()
  cleanup()
})

const json = (status: number, body: unknown, headers: Record<string, string> = {}) =>
  new Response(JSON.stringify(body), { status, headers: { 'Content-Type': 'application/json', ...headers } })
const envelope = (data: unknown) => ({ data, timestamp: new Date().toISOString() })

const credential = {
  id: 'cred-id',
  type: 'public-key',
  rawId: new TextEncoder().encode('cred-id').buffer,
  response: {
    clientDataJSON: new TextEncoder().encode('{"type":"webauthn.get"}').buffer,
    authenticatorData: new TextEncoder().encode('authenticator-data').buffer,
    signature: new TextEncoder().encode('signature').buffer,
    userHandle: null,
  },
  getClientExtensionResults: () => ({}),
  authenticatorAttachment: null,
  toJSON: () => ({}),
}

const beginOptions = envelope({
  publicKey: {
    challenge: 'Y2hhbGxlbmdl',
    timeout: 60000,
    rpId: 'localhost',
    allowCredentials: [{ type: 'public-key', id: 'Y3JlZA', transports: ['internal'] }],
    userVerification: 'required',
  },
})

const presenceChallenge = (permission: string) =>
  json(401, { error: 'step_up_required' }, {
    'WWW-Authenticate': `CFGMS-StepUp realm="cfgms", required="strong", presence="required", permission="${permission}"`,
  })
const elevationChallenge = (permission: string) =>
  json(401, { error: 'step_up_required' }, {
    'WWW-Authenticate': `CFGMS-StepUp realm="cfgms", required="strong", permission="${permission}"`,
  })

const REFRESH = '/api/v1/tenants/root/msp-a/refresh-policy'
const ASSURANCE = '/api/v1/tenants/root/msp-a/assurance-policy'

function putsTo(url: string) {
  return fetchMock.mock.calls.filter(([u, i]) => String(u) === url && i?.method === 'PUT')
}

function renderPanel() {
  return render(
    <MemoryRouter>
      <AuthProvider>
        <TenantSettingsPanel tenantId="root/msp-a" />
      </AuthProvider>
    </MemoryRouter>,
  )
}

function readRoutes(url: string): Response | null {
  if (url === REFRESH) return json(200, envelope({ tenant_id: 'root/msp-a', mode: 'require_approval', max_dormancy_days: 30 }))
  if (url === ASSURANCE) {
    return json(200, envelope({
      tenant_id: 'root/msp-a',
      overrides: [{ permission_id: 'refresh:set-policy', min_override: 'strong', require_user_presence: true }],
    }))
  }
  return null
}

describe('TenantSettingsPanel — rendering', () => {
  it('loads both policies into labelled sections and states the raise-only rule', async () => {
    fetchMock.mockImplementation((input) => Promise.resolve(readRoutes(String(input)) ?? json(404, {})))
    renderPanel()

    await waitFor(() => expect(screen.getByTestId('refresh-mode-select')).toHaveValue('require_approval'))
    expect(screen.getByTestId('refresh-dormancy-input')).toHaveValue('30')
    expect(screen.getByRole('region', { name: 'Refresh policy' })).toBeInTheDocument()
    expect(screen.getByRole('region', { name: 'Assurance policy' })).toBeInTheDocument()
    await waitFor(() => expect(screen.getByLabelText('Permission ID 1')).toHaveValue('refresh:set-policy'))
    expect(screen.getByTestId('assurance-raise-only-note')).toHaveTextContent(/can only raise the bar/i)
  })

  it('shows a load error as text without crashing the other section', async () => {
    fetchMock.mockImplementation((input) => {
      const url = String(input)
      if (url === REFRESH) return Promise.resolve(json(500, { error: { message: '<img src=x onerror=alert(1)>' } }))
      return Promise.resolve(readRoutes(url) ?? json(404, {}))
    })
    renderPanel()
    await waitFor(() => expect(screen.getByTestId('refresh-policy-load-error')).toHaveTextContent('<img src=x'))
    expect(document.querySelector('img')).toBeNull()
    await waitFor(() => expect(screen.getByLabelText('Permission ID 1')).toBeInTheDocument())
  })

  it('rejects a malformed GET payload with a worded error', async () => {
    fetchMock.mockImplementation((input) =>
      Promise.resolve(String(input) === REFRESH ? json(200, envelope({ mode: 'bogus' })) : (readRoutes(String(input)) ?? json(404, {}))),
    )
    renderPanel()
    await waitFor(() => expect(screen.getByTestId('refresh-policy-load-error')).toHaveTextContent(/malformed/))
  })
})

describe('TenantSettingsPanel refresh policy save sends X-Presence-Token after the tap [REQUIRED]', () => {
  it('retries the PUT with the minted presence token', async () => {
    vi.stubGlobal('navigator', { credentials: { get: vi.fn().mockResolvedValue(credential) } })
    fetchMock.mockImplementation((input, init) => {
      const url = String(input)
      if (url.includes('presence/begin')) return Promise.resolve(json(200, beginOptions))
      if (url.includes('presence/finish')) return Promise.resolve(json(200, envelope({ presence_token: 'tap-token-1', expires_in: 30 })))
      if (url === REFRESH && init?.method === 'PUT') {
        if (new Headers(init.headers).get('X-Presence-Token') === 'tap-token-1') {
          return Promise.resolve(json(200, envelope({ tenant_id: 'root/msp-a', mode: 'reject', max_dormancy_days: 30 })))
        }
        return Promise.resolve(presenceChallenge('refresh:set-policy'))
      }
      return Promise.resolve(readRoutes(url) ?? json(404, {}))
    })
    renderPanel()
    await waitFor(() => expect(screen.getByTestId('refresh-mode-select')).toHaveValue('require_approval'))

    fireEvent.change(screen.getByTestId('refresh-mode-select'), { target: { value: 'reject' } })
    fireEvent.click(screen.getByTestId('refresh-save-btn'))

    await waitFor(() => expect(screen.getByTestId('step-up-overlay')).toBeInTheDocument())
    expect(putsTo(REFRESH)).toHaveLength(1)
    await waitFor(() => screen.getByTestId('step-up-verify-btn'))
    fireEvent.click(screen.getByTestId('step-up-verify-btn'))

    await waitFor(() => expect(putsTo(REFRESH)).toHaveLength(2))
    const retry = putsTo(REFRESH)[1]?.[1]
    expect(new Headers(retry?.headers).get('X-Presence-Token')).toBe('tap-token-1')
    expect(JSON.parse(String(retry?.body))).toEqual({ mode: 'reject', max_dormancy_days: 30 })
    await waitFor(() => expect(screen.getByTestId('refresh-saved')).toBeInTheDocument())
  })

  it('sends no second mutation and shows a worded message when the modal is cancelled', async () => {
    const get = vi.fn()
    vi.stubGlobal('navigator', { credentials: { get } })
    fetchMock.mockImplementation((input, init) => {
      const url = String(input)
      if (url.includes('presence/begin')) return Promise.resolve(json(200, beginOptions))
      if (url === REFRESH && init?.method === 'PUT') return Promise.resolve(presenceChallenge('refresh:set-policy'))
      return Promise.resolve(readRoutes(url) ?? json(404, {}))
    })
    renderPanel()
    await waitFor(() => expect(screen.getByTestId('refresh-mode-select')).toBeInTheDocument())

    fireEvent.click(screen.getByTestId('refresh-save-btn'))
    await waitFor(() => expect(screen.getByRole('dialog')).toBeInTheDocument())
    fireEvent.click(screen.getByTestId('step-up-cancel-btn'))

    await waitFor(() => expect(screen.getByTestId('refresh-save-error')).toHaveTextContent(/cancelled.*nothing was saved/i))
    expect(putsTo(REFRESH)).toHaveLength(1)
    expect(get).not.toHaveBeenCalled()
  })

  it('shows the server message verbatim for a rejected rule', async () => {
    fetchMock.mockImplementation((input, init) => {
      const url = String(input)
      if (url === REFRESH && init?.method === 'PUT') {
        return Promise.resolve(json(400, { error: { code: 'INVALID', message: 'max_dormancy_days exceeds platform limit' } }))
      }
      return Promise.resolve(readRoutes(url) ?? json(404, {}))
    })
    renderPanel()
    await waitFor(() => expect(screen.getByTestId('refresh-mode-select')).toBeInTheDocument())
    fireEvent.click(screen.getByTestId('refresh-save-btn'))
    await waitFor(() => expect(screen.getByTestId('refresh-save-error')).toHaveTextContent('max_dormancy_days exceeds platform limit'))
  })

  it('refuses a non-numeric dormancy locally', async () => {
    fetchMock.mockImplementation((input) => Promise.resolve(readRoutes(String(input)) ?? json(404, {})))
    renderPanel()
    await waitFor(() => expect(screen.getByTestId('refresh-mode-select')).toBeInTheDocument())
    fireEvent.change(screen.getByTestId('refresh-dormancy-input'), { target: { value: 'abc' } })
    fireEvent.click(screen.getByTestId('refresh-save-btn'))
    expect(screen.getByTestId('refresh-save-error')).toHaveTextContent(/whole number/)
    expect(putsTo(REFRESH)).toHaveLength(0)
  })
})

describe('TenantSettingsPanel assurance policy save handles elevation 401 without a presence token [REQUIRED]', () => {
  it('retries the PUT after elevation with no X-Presence-Token', async () => {
    vi.stubGlobal('navigator', { credentials: { get: vi.fn().mockResolvedValue(credential) } })
    let elevated = false
    fetchMock.mockImplementation((input, init) => {
      const url = String(input)
      if (url.includes('elevate/begin')) return Promise.resolve(json(200, beginOptions))
      if (url.includes('elevate/finish')) {
        elevated = true
        return Promise.resolve(json(200, { assurance: 'strong', elevated_at: '2026-01-01T00:00:00Z' }))
      }
      if (url === ASSURANCE && init?.method === 'PUT') {
        if (elevated) return Promise.resolve(json(200, envelope({ tenant_id: 'root/msp-a', overrides: [] })))
        return Promise.resolve(elevationChallenge('assurance-policy:set'))
      }
      return Promise.resolve(readRoutes(url) ?? json(404, {}))
    })
    renderPanel()
    await waitFor(() => expect(screen.getByLabelText('Permission ID 1')).toBeInTheDocument())

    fireEvent.click(screen.getByText('Remove'))
    fireEvent.click(screen.getByTestId('assurance-save-btn'))

    await waitFor(() => expect(screen.getByTestId('step-up-overlay')).toBeInTheDocument())
    await waitFor(() => screen.getByTestId('step-up-verify-btn'))
    fireEvent.click(screen.getByTestId('step-up-verify-btn'))

    await waitFor(() => expect(putsTo(ASSURANCE)).toHaveLength(2))
    const retry = putsTo(ASSURANCE)[1]?.[1]
    expect(new Headers(retry?.headers).get('X-Presence-Token')).toBeNull()
    expect(JSON.parse(String(retry?.body))).toEqual({ overrides: [] })
    expect(fetchMock.mock.calls.some(([u]) => String(u).includes('presence/'))).toBe(false)
    await waitFor(() => expect(screen.getByTestId('assurance-saved')).toBeInTheDocument())
  })

  it('sends the wire fields for an added override and shows a server error verbatim', async () => {
    fetchMock.mockImplementation((input, init) => {
      const url = String(input)
      if (url === ASSURANCE && init?.method === 'PUT') {
        return Promise.resolve(json(400, { error: { code: 'INVALID', message: 'unknown permission_id "zz:zz"' } }))
      }
      return Promise.resolve(readRoutes(url) ?? json(404, {}))
    })
    renderPanel()
    await waitFor(() => expect(screen.getByLabelText('Permission ID 1')).toBeInTheDocument())

    fireEvent.click(screen.getByTestId('assurance-add-btn'))
    fireEvent.change(screen.getByLabelText('Permission ID 2'), { target: { value: 'zz:zz' } })
    fireEvent.change(screen.getByLabelText('Minimum assurance 2'), { target: { value: 'basic' } })
    fireEvent.click(screen.getByLabelText('Require user presence 2'))
    fireEvent.click(screen.getByTestId('assurance-save-btn'))

    await waitFor(() => expect(screen.getByTestId('assurance-save-error')).toHaveTextContent('unknown permission_id "zz:zz"'))
    expect(JSON.parse(String(putsTo(ASSURANCE)[0]?.[1]?.body))).toEqual({
      overrides: [
        { permission_id: 'refresh:set-policy', min_override: 'strong', require_user_presence: true },
        { permission_id: 'zz:zz', min_override: 'basic', require_user_presence: true },
      ],
    })
  })

  it('refuses an override with an empty permission ID locally', async () => {
    fetchMock.mockImplementation((input) => Promise.resolve(readRoutes(String(input)) ?? json(404, {})))
    renderPanel()
    await waitFor(() => expect(screen.getByLabelText('Permission ID 1')).toBeInTheDocument())
    fireEvent.click(screen.getByTestId('assurance-add-btn'))
    fireEvent.click(screen.getByTestId('assurance-save-btn'))
    expect(screen.getByTestId('assurance-save-error')).toHaveTextContent(/permission ID/)
    expect(putsTo(ASSURANCE)).toHaveLength(0)
  })
})

const CS_CRED = '/api/v1/tenants/root/msp-a/config-source/credential'
const CS_TEST = '/api/v1/tenants/root/msp-a/config-source/test'

async function fillConfigSource() {
  await waitFor(() => expect(screen.getByTestId('config-source-url-input')).toBeInTheDocument())
  fireEvent.change(screen.getByTestId('config-source-url-input'), { target: { value: 'https://git.example.com/org/configs.git' } })
  fireEvent.change(screen.getByTestId('config-source-token-input'), { target: { value: 'secret-token' } })
}

describe('TenantSettingsPanel config source', () => {
  it('save handles elevation 401 without a presence token', async () => {
    vi.stubGlobal('navigator', { credentials: { get: vi.fn().mockResolvedValue(credential) } })
    let elevated = false
    fetchMock.mockImplementation((input, init) => {
      const url = String(input)
      if (url.includes('elevate/begin')) return Promise.resolve(json(200, beginOptions))
      if (url.includes('elevate/finish')) {
        elevated = true
        return Promise.resolve(json(200, { assurance: 'strong', elevated_at: '2026-01-01T00:00:00Z' }))
      }
      if (url === CS_CRED && init?.method === 'PUT') {
        if (elevated) {
          return Promise.resolve(json(200, envelope({ credential_ref: 'root/msp-a/config-source-git', bound_repository_url: 'https://git.example.com/org/configs.git' })))
        }
        return Promise.resolve(elevationChallenge('tenant:manage'))
      }
      return Promise.resolve(readRoutes(url) ?? json(404, {}))
    })
    renderPanel()
    await fillConfigSource()
    fireEvent.click(screen.getByTestId('config-source-save-btn'))

    await waitFor(() => expect(screen.getByTestId('step-up-overlay')).toBeInTheDocument())
    await waitFor(() => screen.getByTestId('step-up-verify-btn'))
    fireEvent.click(screen.getByTestId('step-up-verify-btn'))

    await waitFor(() => expect(putsTo(CS_CRED)).toHaveLength(2))
    const retry = putsTo(CS_CRED)[1]?.[1]
    expect(new Headers(retry?.headers).get('X-Presence-Token')).toBeNull()
    expect(JSON.parse(String(retry?.body))).toEqual({ url: 'https://git.example.com/org/configs.git', token: 'secret-token' })
    expect(fetchMock.mock.calls.some(([u]) => String(u).includes('presence/'))).toBe(false)
    await waitFor(() => expect(screen.getByTestId('config-source-saved')).toHaveTextContent('root/msp-a/config-source-git'))
  })

  it('clears the token field after save', async () => {
    fetchMock.mockImplementation((input, init) => {
      const url = String(input)
      if (url === CS_CRED && init?.method === 'PUT') {
        return Promise.resolve(json(200, envelope({ credential_ref: 'r', bound_repository_url: 'u' })))
      }
      return Promise.resolve(readRoutes(url) ?? json(404, {}))
    })
    renderPanel()
    await fillConfigSource()
    const input = screen.getByTestId('config-source-token-input')
    expect(input).toHaveAttribute('type', 'password')
    expect(input).toHaveAttribute('autocomplete', 'off')
    fireEvent.click(screen.getByTestId('config-source-save-btn'))
    await waitFor(() => expect(screen.getByTestId('config-source-saved')).toBeInTheDocument())
    expect(input).toHaveValue('')
    expect(JSON.stringify(Object.entries(localStorage)) + JSON.stringify(Object.entries(sessionStorage))).not.toContain('secret-token')
  })

  it('clears the token and shows the server text when the save fails', async () => {
    fetchMock.mockImplementation((input, init) => {
      const url = String(input)
      if (url === CS_CRED && init?.method === 'PUT') {
        return Promise.resolve(json(400, { error: { message: 'bad <b>url</b>' } }))
      }
      return Promise.resolve(readRoutes(url) ?? json(404, {}))
    })
    renderPanel()
    await fillConfigSource()
    fireEvent.click(screen.getByTestId('config-source-save-btn'))
    await waitFor(() => expect(screen.getByTestId('config-source-save-error')).toHaveTextContent('bad <b>url</b>'))
    expect(screen.getByTestId('config-source-token-input')).toHaveValue('')
    expect(document.querySelector('b')).toBeNull()
  })

  it('test button posts and renders the result as text', async () => {
    fetchMock.mockImplementation((input, init) => {
      const url = String(input)
      if (url === CS_TEST && init?.method === 'POST') {
        return Promise.resolve(json(200, envelope({ reachable: false, error: '<i>dial timeout</i>' })))
      }
      return Promise.resolve(readRoutes(url) ?? json(404, {}))
    })
    renderPanel()
    await waitFor(() => expect(screen.getByTestId('config-source-test-btn')).toBeInTheDocument())
    fireEvent.click(screen.getByTestId('config-source-test-btn'))
    await waitFor(() => expect(screen.getByTestId('config-source-test-result')).toHaveTextContent('Not reachable: <i>dial timeout</i>'))
    expect(document.querySelector('i')).toBeNull()
  })
})

describe('TenantSettingsPanel config source validation', () => {
  it('refuses an empty URL, an empty token and an oversized token locally', async () => {
    fetchMock.mockImplementation((input) => Promise.resolve(readRoutes(String(input)) ?? json(404, {})))
    renderPanel()
    await waitFor(() => expect(screen.getByTestId('config-source-url-input')).toBeInTheDocument())

    fireEvent.click(screen.getByTestId('config-source-save-btn'))
    expect(screen.getByTestId('config-source-save-error')).toHaveTextContent(/URL is required/)

    fireEvent.change(screen.getByTestId('config-source-url-input'), { target: { value: 'https://git.example.com/r.git' } })
    fireEvent.click(screen.getByTestId('config-source-save-btn'))
    expect(screen.getByTestId('config-source-save-error')).toHaveTextContent(/Token is required/)

    fireEvent.change(screen.getByTestId('config-source-token-input'), { target: { value: 'x'.repeat(4097) } })
    fireEvent.click(screen.getByTestId('config-source-save-btn'))
    expect(screen.getByTestId('config-source-save-error')).toHaveTextContent(/at most 4096/)
    expect(putsTo(CS_CRED)).toHaveLength(0)
  })
})

const M365 = '/api/v1/tenants/root/msp-a/m365-connection'
const GDAP_CUSTOMERS = '/api/v1/tenants/root/msp-a/m365-gdap-customers'
const GDAP_LINKS = '/api/v1/tenants/root/msp-a/m365-gdap-links'
const m365Conn = {
  tenant_id: 'root/msp-a',
  mode: 'direct',
  app_id: 'app-1',
  m365_tenant_id: 'dir-1',
  has_client_secret: true,
}

function callsTo(url: string, method: string) {
  return fetchMock.mock.calls.filter(([u, i]) => String(u) === url && (i?.method ?? 'GET') === method)
}

async function fillM365(secret = 'client-secret-1') {
  await waitFor(() => expect(screen.getByTestId('m365-app-id-input')).toBeInTheDocument())
  fireEvent.change(screen.getByTestId('m365-app-id-input'), { target: { value: 'app-1' } })
  fireEvent.change(screen.getByTestId('m365-tenant-id-input'), { target: { value: 'dir-1' } })
  fireEvent.change(screen.getByTestId('m365-secret-input'), { target: { value: secret } })
}

function stepUp() {
  vi.stubGlobal('navigator', { credentials: { get: vi.fn().mockResolvedValue(credential) } })
  return (url: string) => {
    if (url.includes('elevate/begin')) return json(200, beginOptions)
    if (url.includes('elevate/finish')) return json(200, { assurance: 'strong', elevated_at: '2026-01-01T00:00:00Z' })
    return null
  }
}

describe('TenantSettingsPanel m365', () => {
  it('save and clear handle elevation 401 without a presence token', async () => {
    const ceremony = stepUp()
    let elevated = false
    let connected = false
    fetchMock.mockImplementation((input, init) => {
      const url = String(input)
      const step = ceremony(url)
      if (step) {
        if (url.includes('finish')) elevated = true
        return Promise.resolve(step)
      }
      if (url === M365 && init?.method === 'PUT') {
        if (!elevated) return Promise.resolve(elevationChallenge('tenant:manage'))
        connected = true
        return Promise.resolve(json(200, envelope(m365Conn)))
      }
      if (url === M365 && init?.method === 'DELETE') {
        if (!elevated) return Promise.resolve(elevationChallenge('tenant:manage'))
        connected = false
        return Promise.resolve(json(200, envelope({ tenant_id: 'root/msp-a', deleted: true })))
      }
      if (url === M365) return Promise.resolve(connected ? json(200, envelope(m365Conn)) : json(404, { error: { message: 'none' } }))
      return Promise.resolve(readRoutes(url) ?? json(404, {}))
    })
    renderPanel()
    await fillM365()
    fireEvent.click(screen.getByTestId('m365-save-btn'))
    await waitFor(() => screen.getByTestId('step-up-verify-btn'))
    fireEvent.click(screen.getByTestId('step-up-verify-btn'))

    await waitFor(() => expect(callsTo(M365, 'PUT')).toHaveLength(2))
    const retry = callsTo(M365, 'PUT')[1]?.[1]
    expect(new Headers(retry?.headers).get('X-Presence-Token')).toBeNull()
    expect(JSON.parse(String(retry?.body))).toEqual({ app_id: 'app-1', m365_tenant_id: 'dir-1', client_secret: 'client-secret-1', replace: false })
    await waitFor(() => expect(screen.getByTestId('m365-secret-badge')).toHaveTextContent('Client secret set'))

    // Clear: nothing is sent until Confirm.
    elevated = false
    fireEvent.click(screen.getByTestId('m365-clear-btn'))
    expect(callsTo(M365, 'DELETE')).toHaveLength(0)
    fireEvent.click(screen.getByTestId('m365-clear-confirm-btn'))
    await waitFor(() => screen.getByTestId('step-up-verify-btn'))
    fireEvent.click(screen.getByTestId('step-up-verify-btn'))
    await waitFor(() => expect(callsTo(M365, 'DELETE')).toHaveLength(2))
    expect(new Headers(callsTo(M365, 'DELETE')[1]?.[1]?.headers).get('X-Presence-Token')).toBeNull()
    await waitFor(() => expect(screen.getByTestId('m365-none')).toBeInTheDocument())
    expect(fetchMock.mock.calls.some(([u]) => String(u).includes('presence/'))).toBe(false)
  })

  it('secret field is cleared after save', async () => {
    fetchMock.mockImplementation((input, init) => {
      const url = String(input)
      if (url === M365 && init?.method === 'PUT') return Promise.resolve(json(400, { error: { message: 'bad <b>app</b>' } }))
      return Promise.resolve(readRoutes(url) ?? json(404, {}))
    })
    renderPanel()
    await fillM365()
    const input = screen.getByTestId('m365-secret-input')
    expect(input).toHaveAttribute('type', 'password')
    expect(input).toHaveAttribute('autocomplete', 'off')
    fireEvent.click(screen.getByTestId('m365-save-btn'))
    await waitFor(() => expect(screen.getByTestId('m365-save-error')).toHaveTextContent('bad <b>app</b>'))
    expect(input).toHaveValue('')
    expect(document.querySelector('b')).toBeNull()
    expect(JSON.stringify(Object.entries(localStorage)) + JSON.stringify(Object.entries(sessionStorage))).not.toContain('client-secret-1')
  })

  it('offers Replace on 409 and resends with replace true', async () => {
    fetchMock.mockImplementation((input, init) => {
      const url = String(input)
      if (url === M365 && init?.method === 'PUT') {
        const body = JSON.parse(String(init.body)) as { replace: boolean }
        return Promise.resolve(body.replace ? json(200, envelope(m365Conn)) : json(409, { error: { message: 'exists' } }))
      }
      if (url === M365) return Promise.resolve(json(200, envelope(m365Conn)))
      return Promise.resolve(readRoutes(url) ?? json(404, {}))
    })
    renderPanel()
    await fillM365()
    fireEvent.click(screen.getByTestId('m365-save-btn'))
    await waitFor(() => expect(screen.getByTestId('m365-save-btn')).toHaveTextContent('Replace connection'))
    expect(screen.getByTestId('m365-secret-input')).toHaveValue('')
    fireEvent.change(screen.getByTestId('m365-secret-input'), { target: { value: 'client-secret-2' } })
    fireEvent.click(screen.getByTestId('m365-save-btn'))
    await waitFor(() => expect(callsTo(M365, 'PUT')).toHaveLength(2))
    expect(JSON.parse(String(callsTo(M365, 'PUT')[1]?.[1]?.body))).toMatchObject({ replace: true, client_secret: 'client-secret-2' })
  })

  it('cancel on the inline confirm sends nothing', async () => {
    fetchMock.mockImplementation((input) => {
      const url = String(input)
      if (url === M365) return Promise.resolve(json(200, envelope(m365Conn)))
      return Promise.resolve(readRoutes(url) ?? json(404, {}))
    })
    renderPanel()
    await waitFor(() => screen.getByTestId('m365-clear-btn'))
    fireEvent.click(screen.getByTestId('m365-clear-btn'))
    fireEvent.click(screen.getByTestId('m365-clear-cancel-btn'))
    expect(screen.queryByTestId('m365-clear-confirm')).toBeNull()
    expect(callsTo(M365, 'DELETE')).toHaveLength(0)
  })

  it('discovers GDAP customers, links the chosen ones and clears the secret each call', async () => {
    fetchMock.mockImplementation((input, init) => {
      const url = String(input)
      if (url === GDAP_CUSTOMERS && init?.method === 'POST') {
        return Promise.resolve(json(200, envelope({
          msp_tenant_id: 'root/msp-a',
          customers: [{ customer_tenant_id: 'c-1', name: '<i>Acme</i>', status: 'active', expires_at: '2027-01-01T00:00:00Z', roles: ['Helpdesk'], link_state: 'unlinked' }],
        })))
      }
      if (url === GDAP_LINKS && init?.method === 'POST') {
        return Promise.resolve(json(200, envelope({ msp_tenant_id: 'root/msp-a', linked: [{ customer_tenant_id: 'c-1', tenant_id: 'root/msp-a/client-1' }] })))
      }
      return Promise.resolve(readRoutes(url) ?? json(404, {}))
    })
    renderPanel()
    await waitFor(() => screen.getByTestId('gdap-partner-input'))
    fireEvent.change(screen.getByTestId('gdap-partner-input'), { target: { value: 'partner-1' } })
    fireEvent.change(screen.getByTestId('gdap-app-id-input'), { target: { value: 'app-1' } })
    fireEvent.change(screen.getByTestId('gdap-secret-input'), { target: { value: 'partner-secret' } })
    fireEvent.click(screen.getByTestId('gdap-discover-btn'))
    await waitFor(() => expect(screen.getByTestId('gdap-customer-row')).toHaveTextContent('<i>Acme</i>'))
    expect(document.querySelector('i')).toBeNull()
    expect(screen.getByTestId('gdap-secret-input')).toHaveValue('')

    fireEvent.change(screen.getByLabelText('Client tenant for c-1'), { target: { value: 'root/msp-a/client-1' } })
    fireEvent.change(screen.getByTestId('gdap-roles-input'), { target: { value: 'Helpdesk, Reader' } })
    fireEvent.change(screen.getByTestId('gdap-secret-input'), { target: { value: 'partner-secret' } })
    fireEvent.click(screen.getByTestId('gdap-link-btn'))
    await waitFor(() => expect(screen.getByTestId('gdap-linked')).toHaveTextContent('Linked 1 customer'))
    expect(JSON.parse(String(callsTo(GDAP_LINKS, 'POST')[0]?.[1]?.body))).toEqual({
      partner_tenant_id: 'partner-1',
      app_id: 'app-1',
      client_secret: 'partner-secret',
      links: [{ customer_tenant_id: 'c-1', tenant_id: 'root/msp-a/client-1' }],
      gdap_roles: ['Helpdesk', 'Reader'],
      replace: false,
    })
    expect(screen.getByTestId('gdap-secret-input')).toHaveValue('')
  })
})
