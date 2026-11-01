// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz

/*
 * TenantDevicesPanel suite (Story #4586): Loading / Error / Empty / Ready states,
 * steward links, pagination request shape.
 */
import { beforeEach, afterEach, describe, expect, it, vi } from 'vitest'
import { cleanup, fireEvent, render, screen } from '@testing-library/react'
import { MemoryRouter } from 'react-router'
import { AuthProvider } from '../auth/AuthContext.tsx'
import TenantDevicesPanel from './TenantDevicesPanel.tsx'

const fetchMock = vi.fn<typeof fetch>()

beforeEach(() => {
  fetchMock.mockReset()
  vi.stubGlobal('fetch', fetchMock)
})

afterEach(() => {
  vi.unstubAllGlobals()
  cleanup()
})

function respond(body: unknown, status = 200) {
  fetchMock.mockImplementation(() =>
    Promise.resolve(
      new Response(JSON.stringify(body), {
        status,
        headers: { 'Content-Type': 'application/json' },
      }),
    ),
  )
}

function renderPanel(onClose = () => {}) {
  return render(
    <MemoryRouter>
      <AuthProvider>
        <TenantDevicesPanel tenantId="root/msp-a/acme-corp" onClose={onClose} />
      </AuthProvider>
    </MemoryRouter>,
  )
}

describe('TenantDevicesPanel', () => {
  it('shows the loading state while pending', () => {
    fetchMock.mockImplementation(() => new Promise<Response>(() => {}))
    renderPanel()
    expect(screen.getByTestId('tenant-devices-loading')).toBeInTheDocument()
  })

  it('renders devices with status pills and links to the steward page', async () => {
    respond({
      devices: [
        { steward_id: 's-1', hostname: 'host-1', status: 'compliant' },
        { steward_id: 's-2', hostname: '', status: 'critical' },
      ],
      total: 2,
    })
    renderPanel()
    const rows = await screen.findAllByTestId('tenant-device-row')
    expect(rows).toHaveLength(2)
    expect(screen.getByRole('link', { name: 'host-1' })).toHaveAttribute('href', '/stewards/s-1')
    expect(screen.getByRole('link', { name: 's-2' })).toHaveAttribute('href', '/stewards/s-2')
    expect(screen.getByText('No drift')).toBeInTheDocument()
    expect(screen.getByText('Critical')).toBeInTheDocument()
    const url = String(fetchMock.mock.calls[0]![0])
    expect(url).toContain('/api/v1/compliance/tenants/root%2Fmsp-a%2Facme-corp/devices')
    expect(url).toContain('limit=50&offset=0')
  })

  it('shows the empty state for a tenant with no devices', async () => {
    respond({ devices: [], total: 0 })
    renderPanel()
    expect(await screen.findByTestId('tenant-devices-empty')).toBeInTheDocument()
  })

  it('shows the error state with retry on failure', async () => {
    respond({}, 503)
    renderPanel()
    await screen.findByRole('alert')
    respond({ devices: [], total: 0 })
    fireEvent.click(screen.getByRole('button', { name: 'Retry' }))
    expect(await screen.findByTestId('tenant-devices-empty')).toBeInTheDocument()
  })

  it('requests the next page', async () => {
    respond({
      devices: Array.from({ length: 50 }, (_, i) => ({
        steward_id: `s-${i}`,
        hostname: `h-${i}`,
        status: 'compliant',
      })),
      total: 80,
    })
    renderPanel()
    await screen.findAllByTestId('tenant-device-row')
    fireEvent.click(screen.getByRole('button', { name: 'Next' }))
    await screen.findAllByTestId('tenant-device-row')
    expect(String(fetchMock.mock.calls.at(-1)?.[0])).toContain('offset=50')
  })

  it('calls onClose', async () => {
    respond({ devices: [], total: 0 })
    const onClose = vi.fn()
    renderPanel(onClose)
    await screen.findByTestId('tenant-devices-empty')
    fireEvent.click(screen.getByRole('button', { name: 'Close' }))
    expect(onClose).toHaveBeenCalled()
  })
})
