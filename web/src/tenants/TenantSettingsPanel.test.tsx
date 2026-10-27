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
