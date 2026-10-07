// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz

import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'
import { cleanup, fireEvent, render, screen, waitFor } from '@testing-library/react'
import SupportAccessDialog from './SupportAccessDialog.tsx'

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

function renderDialog(onGranted = vi.fn()) {
  render(<SupportAccessDialog tenantId="msp-a" tenantName="MSP A" onGranted={onGranted} onClose={vi.fn()} />)
  return onGranted
}

describe('SupportAccessDialog', () => {
  it('shows help text naming the root operator principal ID', () => {
    renderDialog()
    expect(screen.getByTestId('support-principal-help')).toHaveTextContent("root operator's principal ID")
  })

  it('requires an operator principal ID', () => {
    renderDialog()
    fireEvent.click(screen.getByTestId('support-submit-btn'))
    expect(screen.getByTestId('support-principal-error')).toHaveTextContent('required')
    expect(fetchMock).not.toHaveBeenCalled()
  })

  it.each(['0', '1441', '1.5', ''])('rejects duration %j', (value) => {
    renderDialog()
    fireEvent.change(screen.getByTestId('support-principal-input'), { target: { value: 'root-op' } })
    fireEvent.change(screen.getByTestId('support-duration-input'), { target: { value } })
    fireEvent.click(screen.getByTestId('support-submit-btn'))
    expect(screen.getByTestId('support-error')).toHaveTextContent('between 1 and 1440')
    expect(fetchMock).not.toHaveBeenCalled()
  })

  it('rejects a provided justification outside 10-1000', () => {
    renderDialog()
    fireEvent.change(screen.getByTestId('support-principal-input'), { target: { value: 'root-op' } })
    fireEvent.change(screen.getByTestId('support-justification-input'), { target: { value: 'short' } })
    fireEvent.click(screen.getByTestId('support-submit-btn'))
    expect(screen.getByTestId('support-error')).toHaveTextContent('10-1000')
  })

  it('posts principal_id, duration_minutes and justification', async () => {
    fetchMock.mockResolvedValueOnce(json(201, { data: { ID: 'g-1', TenantID: 'msp-a', Kind: 'grant' } }))
    const onGranted = renderDialog()
    fireEvent.change(screen.getByTestId('support-principal-input'), { target: { value: ' root-op ' } })
    fireEvent.change(screen.getByTestId('support-duration-input'), { target: { value: '120' } })
    fireEvent.change(screen.getByTestId('support-justification-input'), { target: { value: 'quarterly review' } })
    fireEvent.click(screen.getByTestId('support-submit-btn'))
    await waitFor(() => expect(onGranted).toHaveBeenCalledTimes(1))
    const [url, init] = fetchMock.mock.calls[0]!
    expect(url).toBe('/api/v1/tenants/msp-a/access-grants')
    expect(JSON.parse(String(init?.body))).toEqual({
      principal_id: 'root-op',
      duration_minutes: 120,
      justification: 'quarterly review',
    })
  })

  it('a 400 shows the inline principal-ID error and keeps the dialog open with the values', async () => {
    fetchMock.mockResolvedValueOnce(
      json(400, { error: { code: 'MISSING_PRINCIPAL_ID', message: 'principal_id is required' } }),
    )
    const onGranted = renderDialog()
    fireEvent.change(screen.getByTestId('support-principal-input'), { target: { value: 'bogus' } })
    fireEvent.change(screen.getByTestId('support-duration-input'), { target: { value: '45' } })
    fireEvent.click(screen.getByTestId('support-submit-btn'))
    expect(await screen.findByTestId('support-principal-error')).toHaveTextContent('principal_id is required')
    expect(onGranted).not.toHaveBeenCalled()
    expect(screen.getByTestId('support-access-dialog')).toBeInTheDocument()
    expect(screen.getByTestId('support-principal-input')).toHaveValue('bogus')
    expect(screen.getByTestId('support-duration-input')).toHaveValue(45)
    expect(screen.getByTestId('support-submit-btn')).not.toBeDisabled()
  })

  it('shows a non-400 failure as a general error', async () => {
    fetchMock.mockResolvedValueOnce(json(401, { error: 'tenant_crossing_required' }))
    renderDialog()
    fireEvent.change(screen.getByTestId('support-principal-input'), { target: { value: 'root-op' } })
    fireEvent.click(screen.getByTestId('support-submit-btn'))
    expect(await screen.findByTestId('support-error')).toHaveTextContent('crossing is required')
  })
})
