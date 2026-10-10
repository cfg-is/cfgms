// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'
import { cleanup, fireEvent, render, screen, waitFor } from '@testing-library/react'
import CrossingPrompt from './CrossingPrompt.tsx'
import type { TenantInfo } from './useTenants.ts'

const fetchMock = vi.fn<typeof fetch>()

beforeEach(() => {
  fetchMock.mockReset()
  vi.stubGlobal('fetch', fetchMock)
})

afterEach(() => {
  cleanup()
  vi.unstubAllGlobals()
})

function json(status: number, body: unknown): Response {
  return new Response(JSON.stringify(body), { status, headers: { 'Content-Type': 'application/json' } })
}

const future = () => new Date(Date.now() + 20 * 60_000).toISOString()

function crossingBody(over: Record<string, unknown> = {}) {
  return {
    id: 'c-1',
    tenant_id: 'msp-a',
    kind: 'break_glass',
    justification: 'outage response',
    reason_category: 'account_recovery',
    approval_state: 'approved',
    expires_at: future(),
    revoked_at: null,
    ...over,
  }
}

function msp(over: Partial<TenantInfo> = {}): TenantInfo {
  return {
    id: 'msp-a', name: 'Acme MSP', description: '', parent_id: 'root', status: 'active',
    directly_suspended: false, cascade_suspended_from: null, created_at: '', updated_at: '',
    deviceCount: 0, boundary: true, accessible: false, techCount: 0, clientTenantCount: 0,
    ...over,
  }
}

const goodText = 'MSP owner lost both passkeys; ticket INC-4821'

function fill(reason = 'account_recovery', text = goodText) {
  fireEvent.change(screen.getByTestId('crossing-reason'), { target: { value: reason } })
  fireEvent.change(screen.getByTestId('crossing-justification'), { target: { value: text } })
}

function setup(over: Partial<React.ComponentProps<typeof CrossingPrompt>> = {}) {
  const onGranted = vi.fn()
  const onCancel = vi.fn()
  render(
    <CrossingPrompt
      tenantId="msp-a"
      visibleTenants={[msp()]}
      onGranted={onGranted}
      onCancel={onCancel}
      pollIntervalMs={15}
      {...over}
    />,
  )
  return { onGranted, onCancel }
}

describe('CrossingPrompt — form', () => {
  it('shows the grant guidance first, then the break-glass form', () => {
    setup()
    const grant = screen.getByTestId('crossing-path-grant')
    const bg = screen.getByTestId('crossing-path-break-glass')
    expect(grant.compareDocumentPosition(bg) & Node.DOCUMENT_POSITION_FOLLOWING).toBeTruthy()
    expect(grant).toHaveTextContent('1 to 24 hours')
    expect(grant).toHaveTextContent('whole root support team')
    expect(grant.querySelector('button')).toBeNull()
    expect(bg).toHaveTextContent('email')
    expect(bg).toHaveTextContent('audit log')
  })

  it('blocks submit until a reason and a 10-1000 character justification are present', () => {
    setup()
    const submit = screen.getByTestId('crossing-submit-btn')
    expect(submit).toBeDisabled()
    fill('', goodText)
    expect(submit).toBeDisabled()
    fill('legal_request', 'too short')
    expect(submit).toBeDisabled()
    expect(screen.getByTestId('crossing-count')).toHaveTextContent('9 / 1000')
    fill('legal_request', '          ')
    expect(submit).toBeDisabled()
    fill('legal_request', goodText)
    expect(submit).toBeEnabled()
    expect(fetchMock).not.toHaveBeenCalled()
  })

  it('caps the justification at 1000 characters', () => {
    setup()
    expect(screen.getByTestId('crossing-justification')).toHaveAttribute('maxlength', '1000')
  })

  it('offers only the advertised reason categories', () => {
    setup({ reasonCategories: ['legal_request', 'billing_dispute'] })
    const values = [...screen.getByTestId('crossing-reason').querySelectorAll('option')].map((o) => o.getAttribute('value'))
    expect(values).toEqual(['', 'legal_request', 'billing_dispute'])
  })

  it('posts both fields to the break-glass endpoint and reports an active crossing', async () => {
    fetchMock.mockResolvedValueOnce(json(201, { data: crossingBody() }))
    const { onGranted } = setup()
    fill('security_incident', goodText)
    fireEvent.click(screen.getByTestId('crossing-submit-btn'))
    await waitFor(() => expect(onGranted).toHaveBeenCalledTimes(1))
    expect(onGranted.mock.calls[0]![0]).toMatchObject({ id: 'c-1', tenantId: 'msp-a' })
    const [url, init] = fetchMock.mock.calls[0]!
    expect(url).toBe('/api/v1/tenants/msp-a/break-glass')
    expect(init?.method).toBe('POST')
    expect(JSON.parse(String(init?.body))).toEqual({ reason_category: 'security_incident', justification: goodText })
    expect(new Headers(init?.headers).get('X-Justification')).toBeNull()
  })

  it('does not keep the justification in browser storage', async () => {
    fetchMock.mockResolvedValueOnce(json(201, { data: crossingBody() }))
    const { onGranted } = setup()
    fill()
    fireEvent.click(screen.getByTestId('crossing-submit-btn'))
    await waitFor(() => expect(onGranted).toHaveBeenCalled())
    for (const store of [window.localStorage, window.sessionStorage]) {
      for (let i = 0; i < store.length; i++) {
        expect(store.getItem(store.key(i)!)).not.toContain(goodText)
      }
    }
  })
})

describe('CrossingPrompt — errors and cancel', () => {
  it('shows a 400 inline and keeps the prompt open', async () => {
    fetchMock.mockResolvedValueOnce(
      json(400, { error: { code: 'JUSTIFICATION_REQUIRED', message: 'justification is required (10-1000 characters)' } }),
    )
    const { onGranted, onCancel } = setup()
    fill()
    fireEvent.click(screen.getByTestId('crossing-submit-btn'))
    expect(await screen.findByTestId('crossing-error')).toHaveTextContent('justification is required')
    expect(screen.getByTestId('crossing-prompt')).toBeInTheDocument()
    expect(screen.getByTestId('crossing-submit-btn')).toBeEnabled()
    expect(onGranted).not.toHaveBeenCalled()
    expect(onCancel).not.toHaveBeenCalled()
  })

  it('shows a 403 NOT_ROOT_SCOPED inline without closing', async () => {
    fetchMock.mockResolvedValueOnce(json(403, { error: { code: 'NOT_ROOT_SCOPED', message: 'raw server text' } }))
    const { onCancel } = setup()
    fill()
    fireEvent.click(screen.getByTestId('crossing-submit-btn'))
    expect(await screen.findByTestId('crossing-error')).toHaveTextContent('Only a root-scoped session can use break-glass')
    expect(screen.getByTestId('crossing-prompt')).toBeInTheDocument()
    expect(onCancel).not.toHaveBeenCalled()
  })

  it('shows a generic message for a 5xx', async () => {
    fetchMock.mockResolvedValueOnce(json(500, { error: { code: 'BREAK_GLASS_FAILED', message: 'db: secret detail' } }))
    setup()
    fill()
    fireEvent.click(screen.getByTestId('crossing-submit-btn'))
    const err = await screen.findByTestId('crossing-error')
    expect(err).toHaveTextContent('Break-glass request failed')
    expect(err).not.toHaveTextContent('secret detail')
  })

  it('cancel button and Escape both cancel', () => {
    const first = setup()
    fireEvent.click(screen.getByTestId('crossing-cancel-btn'))
    expect(first.onCancel).toHaveBeenCalledTimes(1)
    cleanup()
    const second = setup()
    fireEvent.keyDown(document, { key: 'Escape' })
    expect(second.onCancel).toHaveBeenCalledTimes(1)
  })

  it('traps Tab inside the dialog', () => {
    setup()
    const submitless = screen.getByTestId('crossing-cancel-btn')
    // Submit is disabled, so Cancel is the last focusable control.
    submitless.focus()
    fireEvent.keyDown(document, { key: 'Tab' })
    expect(screen.getByTestId('crossing-prompt').contains(document.activeElement)).toBe(true)
    expect(document.activeElement).toBe(screen.getByTestId('crossing-reason'))
  })
})

describe('CrossingPrompt — pending approval', () => {
  async function submitPending(onGrantedExpected = false) {
    fetchMock.mockResolvedValueOnce(
      json(201, { data: crossingBody({ approval_state: 'pending' }) }),
    )
    const handlers = setup()
    fill()
    fireEvent.click(screen.getByTestId('crossing-submit-btn'))
    await screen.findByTestId('crossing-waiting')
    expect(handlers.onGranted).toHaveBeenCalledTimes(onGrantedExpected ? 1 : 0)
    return handlers
  }

  it('shows the waiting state and grants only once the active feed lists the tenant', async () => {
    const { onGranted } = await submitPending()
    expect(screen.getByTestId('crossing-wait-justification')).toHaveTextContent(goodText)
    // Two polls: the feed lists a different tenant, then ours.
    fetchMock
      .mockResolvedValueOnce(json(200, { data: [crossingBody({ id: 'c-x', tenant_id: 'msp-other' })] }))
      .mockResolvedValue(json(200, { data: [crossingBody({ id: 'c-2', tenant_id: 'msp-a' })] }))
    await waitFor(() => expect(onGranted).toHaveBeenCalledTimes(1))
    expect(onGranted.mock.calls[0]![0]).toMatchObject({ id: 'c-2', tenantId: 'msp-a' })
    const urls = fetchMock.mock.calls.map((c) => String(c[0]))
    expect(urls.filter((u) => u === '/api/v1/tenant-crossings/active').length).toBeGreaterThanOrEqual(2)
  })

  it('keeps polling through a failed poll', async () => {
    const { onGranted } = await submitPending()
    fetchMock
      .mockResolvedValueOnce(json(500, { error: { code: 'LIST_FAILED', message: 'x' } }))
      .mockResolvedValue(json(200, { data: [crossingBody({ id: 'c-3' })] }))
    await waitFor(() => expect(onGranted).toHaveBeenCalledTimes(1))
  })

  it('Stop waiting cancels and stops polling', async () => {
    const { onGranted, onCancel } = await submitPending()
    fetchMock.mockResolvedValue(json(200, { data: [] }))
    fireEvent.click(screen.getByTestId('crossing-stop-btn'))
    expect(onCancel).toHaveBeenCalledTimes(1)
    cleanup()
    const calls = fetchMock.mock.calls.length
    await new Promise((r) => setTimeout(r, 60))
    expect(fetchMock.mock.calls.length).toBe(calls)
    expect(onGranted).not.toHaveBeenCalled()
  })
})

describe('CrossingPrompt — visibility rule', () => {
  it('names an MSP that is in the visible tenant list', () => {
    setup()
    expect(screen.getByTestId('crossing-prompt')).toHaveTextContent('Acme MSP')
    expect(screen.getByTestId('crossing-tenant-label')).toHaveTextContent('Acme MSP')
  })

  it('never renders the ID, a name or a path of a tenant outside the visible list', async () => {
    const clientId = 'client-secret-7'
    const { container } = render(
      <CrossingPrompt
        tenantId={clientId}
        visibleTenants={[msp()]}
        onGranted={vi.fn()}
        onCancel={vi.fn()}
        pollIntervalMs={15}
      />,
    )
    expect(screen.getByTestId('crossing-tenant-label')).toHaveTextContent('this tenant')
    expect(container.textContent).not.toContain(clientId)
    expect(container.textContent).not.toContain('Acme MSP')
    // The waiting state does not leak it either.
    fetchMock.mockResolvedValueOnce(
      json(201, { data: crossingBody({ tenant_id: clientId, approval_state: 'pending' }) }),
    )
    fill()
    fireEvent.click(screen.getByTestId('crossing-submit-btn'))
    await screen.findByTestId('crossing-waiting')
    expect(container.textContent).not.toContain(clientId)
    expect(fetchMock.mock.calls[0]![0]).toBe(`/api/v1/tenants/${clientId}/break-glass`)
  })

  it('loads the visible list itself when none is provided', async () => {
    fetchMock.mockResolvedValueOnce(
      json(200, {
        data: [
          { id: 'msp-a', name: 'Loaded MSP', parent_id: 'root', status: 'active' },
        ],
      }),
    )
    render(<CrossingPrompt tenantId="msp-a" onGranted={vi.fn()} onCancel={vi.fn()} />)
    await waitFor(() => expect(screen.getByTestId('crossing-tenant-label')).toHaveTextContent('Loaded MSP'))
    expect(fetchMock.mock.calls[0]![0]).toBe('/api/v1/tenants')
  })

  it('renders the MSP name and justification as text, never markup', async () => {
    const markup = '<img src=x onerror=alert(1)> ticket INC-1'
    fetchMock.mockResolvedValueOnce(json(201, { data: crossingBody({ approval_state: 'pending' }) }))
    const { container } = render(
      <CrossingPrompt
        tenantId="msp-a"
        visibleTenants={[msp({ name: '<b>Evil</b>' })]}
        onGranted={vi.fn()}
        onCancel={vi.fn()}
        pollIntervalMs={15}
      />,
    )
    expect(container.querySelector('b')?.textContent).not.toBe('Evil')
    fill('account_recovery', markup)
    fireEvent.click(screen.getByTestId('crossing-submit-btn'))
    await screen.findByTestId('crossing-waiting')
    expect(container.querySelector('img')).toBeNull()
    expect(screen.getByTestId('crossing-wait-justification').textContent).toBe(markup)
  })
})
