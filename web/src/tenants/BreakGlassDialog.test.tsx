// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz

import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'
import { cleanup, fireEvent, render, screen, waitFor } from '@testing-library/react'
import BreakGlassDialog from './BreakGlassDialog.tsx'

const fetchMock = vi.fn<typeof fetch>()

beforeEach(() => {
  vi.stubGlobal('fetch', fetchMock)
  fetchMock.mockReset()
})
afterEach(() => {
  vi.unstubAllGlobals()
  cleanup()
})

function json(status: number, body: unknown) {
  return new Response(JSON.stringify(body), { status, headers: { 'Content-Type': 'application/json' } })
}

function fill(tenant: string, reason: string) {
  fireEvent.change(screen.getByTestId('break-glass-tenant-input'), { target: { value: tenant } })
  fireEvent.change(screen.getByTestId('break-glass-justification-input'), { target: { value: reason } })
}

describe('BreakGlassDialog', () => {
  it('shows the fixed 30-minute window', () => {
    render(<BreakGlassDialog onInvoked={vi.fn()} onClose={vi.fn()} />)
    expect(screen.getByTestId('break-glass-window')).toHaveTextContent('30-minute')
  })

  it('rejects a justification under 10 characters with the server bounds', () => {
    render(<BreakGlassDialog onInvoked={vi.fn()} onClose={vi.fn()} />)
    fill('msp-a', 'too short')
    fireEvent.click(screen.getByTestId('break-glass-submit-btn'))
    expect(screen.getByTestId('break-glass-error')).toHaveTextContent('10-1000')
    expect(fetchMock).not.toHaveBeenCalled()
  })

  it('rejects a justification over 1000 characters', () => {
    render(<BreakGlassDialog onInvoked={vi.fn()} onClose={vi.fn()} />)
    fill('msp-a', 'x'.repeat(1001))
    fireEvent.click(screen.getByTestId('break-glass-submit-btn'))
    expect(screen.getByTestId('break-glass-error')).toHaveTextContent('10-1000')
    expect(fetchMock).not.toHaveBeenCalled()
  })

  it('requires a target tenant', () => {
    render(<BreakGlassDialog onInvoked={vi.fn()} onClose={vi.fn()} />)
    fill('  ', 'a valid justification')
    fireEvent.click(screen.getByTestId('break-glass-submit-btn'))
    expect(screen.getByTestId('break-glass-error')).toHaveTextContent('tenant ID is required')
  })

  it('sends X-Justification and reports the crossing on success', async () => {
    fetchMock.mockResolvedValueOnce(
      json(201, { data: { ID: 'c-1', TenantID: 'msp-a', ExpiresAt: '2030-01-01T00:00:00Z', Justification: 'outage response' } }),
    )
    const onInvoked = vi.fn()
    render(<BreakGlassDialog onInvoked={onInvoked} onClose={vi.fn()} />)
    fill('msp-a', 'outage response')
    fireEvent.click(screen.getByTestId('break-glass-submit-btn'))
    await waitFor(() => expect(onInvoked).toHaveBeenCalledTimes(1))
    expect(new Headers(fetchMock.mock.calls[0]![1]?.headers).get('X-Justification')).toBe('outage response')
    expect(onInvoked.mock.calls[0]![0]).toMatchObject({ id: 'c-1', tenantId: 'msp-a' })
  })

  it('renders a 403 as an error and does not invoke', async () => {
    fetchMock.mockResolvedValueOnce(
      json(403, { error: { code: 'NOT_ROOT_SCOPED', message: 'break-glass is only available to root-scoped callers' } }),
    )
    const onInvoked = vi.fn()
    render(<BreakGlassDialog onInvoked={onInvoked} onClose={vi.fn()} />)
    fill('msp-a', 'outage response')
    fireEvent.click(screen.getByTestId('break-glass-submit-btn'))
    expect(await screen.findByTestId('break-glass-error')).toHaveTextContent('only available to root-scoped')
    expect(onInvoked).not.toHaveBeenCalled()
    // Dialog stays open with the entered values.
    expect(screen.getByTestId('break-glass-justification-input')).toHaveValue('outage response')
  })

  it('cancel closes', () => {
    const onClose = vi.fn()
    render(<BreakGlassDialog onInvoked={vi.fn()} onClose={onClose} />)
    fireEvent.click(screen.getByTestId('break-glass-cancel-btn'))
    expect(onClose).toHaveBeenCalled()
  })
})
