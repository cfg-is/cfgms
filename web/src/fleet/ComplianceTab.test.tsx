// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz

/*
 * ComplianceTab suite (Story #3273): loading / error / populated / empty-patches
 * states for the per-steward compliance tab.
 *
 * Two endpoints are fetched in parallel on mount:
 *   GET /api/v1/stewards/{id}/compliance        → status badge
 *   GET /api/v1/stewards/{id}/compliance/report → detailed report
 *
 * fetch is stubbed at the global level; tests verify observable DOM output.
 */
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'
import { cleanup, fireEvent, render, screen } from '@testing-library/react'
import { MemoryRouter, Route, Routes } from 'react-router'
import ComplianceTab from './ComplianceTab.tsx'
import type { ComplianceStatusResponse, ComplianceReportResponse } from './ComplianceTab.tsx'

const fetchMock = vi.fn<typeof fetch>()

beforeEach(() => {
  fetchMock.mockReset()
  vi.stubGlobal('fetch', fetchMock)
})

afterEach(() => {
  cleanup()
  vi.unstubAllGlobals()
})

function renderTab(stewardId = 'stw-001') {
  return render(
    <MemoryRouter initialEntries={[`/stewards/${encodeURIComponent(stewardId)}`]}>
      <Routes>
        <Route path="/stewards/:id" element={<ComplianceTab />} />
      </Routes>
    </MemoryRouter>,
  )
}

function makeStatusResponse(overrides: Partial<ComplianceStatusResponse> = {}): ComplianceStatusResponse {
  return {
    device_id: 'stw-001',
    device_name: 'stw-001',
    status: 'compliant',
    connection_status: 'online',
    days_until_breach: 0,
    last_checked: '2026-08-18T10:00:00Z',
    alert_level: 'info',
    ...overrides,
  }
}

function makeReportResponse(overrides: Partial<ComplianceReportResponse> = {}): ComplianceReportResponse {
  return {
    device_id: 'stw-001',
    device_name: 'stw-001',
    status: 'compliant',
    connection_status: 'online',
    days_until_breach: 0,
    missing_patches: [],
    os_version: 'Ubuntu 24.04 LTS',
    last_patch_date: '2026-08-15T00:00:00Z',
    report_generated_at: '2026-08-18T10:00:00Z',
    policy: {
      critical_deadline_days: 7,
      important_deadline_days: 14,
      moderate_deadline_days: 30,
      low_deadline_days: 60,
      warning_threshold_days: 7,
      critical_threshold_days: 1,
      maintenance_windows_configured: false,
    },
    ...overrides,
  }
}

function mockBothEndpoints(
  status: ComplianceStatusResponse = makeStatusResponse(),
  report: ComplianceReportResponse = makeReportResponse(),
) {
  // First fetch call → /compliance (status)
  fetchMock.mockResolvedValueOnce(
    new Response(JSON.stringify(status), {
      status: 200,
      headers: { 'Content-Type': 'application/json' },
    }),
  )
  // Second fetch call → /compliance/report
  fetchMock.mockResolvedValueOnce(
    new Response(JSON.stringify(report), {
      status: 200,
      headers: { 'Content-Type': 'application/json' },
    }),
  )
}

describe('ComplianceTab loading state', () => {
  it('shows a loading skeleton before responses arrive', () => {
    fetchMock.mockReturnValue(new Promise(() => {}))
    renderTab()
    expect(screen.getByTestId('compliance-loading')).toBeTruthy()
    expect(screen.getByLabelText('Loading compliance data')).toBeTruthy()
  })
})

describe('ComplianceTab error state', () => {
  it('renders an error card on network failure and allows retry', async () => {
    fetchMock.mockRejectedValueOnce(new Error('network down'))
    // Let the second fetch pend to avoid additional state updates
    fetchMock.mockReturnValue(new Promise(() => {}))
    renderTab()

    const alert = await screen.findByRole('alert')
    expect(alert.textContent).toContain('Couldn')

    // Retry: mock both endpoints to succeed
    fetchMock.mockReset()
    mockBothEndpoints()
    fireEvent.click(screen.getByRole('button', { name: /retry/i }))
    expect(await screen.findByTestId('compliance-pill')).toBeTruthy()
  })

  it('renders an error card on non-OK status response', async () => {
    fetchMock.mockResolvedValueOnce(
      new Response('steward not found', { status: 404 }),
    )
    fetchMock.mockReturnValue(new Promise(() => {}))
    renderTab()

    const alert = await screen.findByRole('alert')
    expect(alert.textContent).toContain('404')
  })
})

describe('ComplianceTab populated state', () => {
  it('fetches both compliance endpoints with the encoded steward ID', async () => {
    mockBothEndpoints()
    renderTab()
    await screen.findByTestId('compliance-pill')

    const urls = fetchMock.mock.calls.map((call) => String(call[0]))
    expect(urls).toContain('/api/v1/stewards/stw-001/compliance')
    expect(urls).toContain('/api/v1/stewards/stw-001/compliance/report')
  })

  it('encodes special characters in the steward ID', async () => {
    mockBothEndpoints(makeStatusResponse({ device_id: 'stw/special' }))
    renderTab('stw/special')
    await screen.findByTestId('compliance-pill')

    const urls = fetchMock.mock.calls.map((call) => String(call[0]))
    expect(urls.some((u) => u.includes('stw%2Fspecial'))).toBe(true)
  })

  it('renders the compliant status pill', async () => {
    mockBothEndpoints(makeStatusResponse({ status: 'compliant', alert_level: 'info' }))
    renderTab()

    const pill = await screen.findByTestId('compliance-pill')
    expect(pill.textContent).toContain('Compliant')
    expect(pill.className).toContain('ok')
  })

  it('renders the warning status pill', async () => {
    mockBothEndpoints(makeStatusResponse({ status: 'warning', alert_level: 'warning' }))
    renderTab()

    const pill = await screen.findByTestId('compliance-pill')
    expect(pill.textContent).toContain('Warning')
    expect(pill.className).toContain('warn')
  })

  it('renders the critical status pill', async () => {
    mockBothEndpoints(makeStatusResponse({ status: 'critical', alert_level: 'critical' }))
    renderTab()

    const pill = await screen.findByTestId('compliance-pill')
    expect(pill.textContent).toContain('Critical')
    expect(pill.className).toContain('crit')
  })

  it('renders alert level, connection status, and last checked from the status endpoint', async () => {
    mockBothEndpoints(
      makeStatusResponse({
        alert_level: 'warning',
        connection_status: 'online',
        last_checked: '2026-08-18T10:00:00Z',
      }),
    )
    renderTab()
    await screen.findByTestId('compliance-pill')

    expect(screen.getByText('warning')).toBeTruthy()
    expect(screen.getByText('online')).toBeTruthy()
    expect(screen.getByText('2026-08-18T10:00:00Z')).toBeTruthy()
  })

  it('renders days_until_breach as — when zero (placeholder value)', async () => {
    mockBothEndpoints(makeStatusResponse({ days_until_breach: 0 }))
    renderTab()
    await screen.findByTestId('compliance-pill')
    expect(screen.getByText('—')).toBeTruthy()
  })

  it('renders non-zero days_until_breach as a number', async () => {
    mockBothEndpoints(makeStatusResponse({ days_until_breach: 5 }))
    renderTab()
    await screen.findByTestId('compliance-pill')
    expect(screen.getByText('5')).toBeTruthy()
  })

  it('renders OS version and last patch date from the report endpoint', async () => {
    mockBothEndpoints(
      makeStatusResponse(),
      makeReportResponse({
        os_version: 'Ubuntu 24.04 LTS',
        last_patch_date: '2026-08-15T00:00:00Z',
      }),
    )
    renderTab()
    await screen.findByTestId('compliance-pill')

    expect(screen.getByText('Ubuntu 24.04 LTS')).toBeTruthy()
    expect(screen.getByText('2026-08-15T00:00:00Z')).toBeTruthy()
  })

  it('renders policy thresholds from the report endpoint', async () => {
    mockBothEndpoints(
      makeStatusResponse(),
      makeReportResponse({
        policy: {
          critical_deadline_days: 7,
          important_deadline_days: 14,
          moderate_deadline_days: 30,
          low_deadline_days: 60,
          warning_threshold_days: 7,
          critical_threshold_days: 1,
          maintenance_windows_configured: false,
        },
      }),
    )
    renderTab()
    await screen.findByTestId('compliance-pill')

    expect(screen.getByText('7 days')).toBeTruthy()  // critical deadline
    expect(screen.getByText('14 days')).toBeTruthy() // important deadline
    expect(screen.getByText('30 days')).toBeTruthy() // moderate deadline
    expect(screen.getByText('60 days')).toBeTruthy() // low deadline
  })
})

describe('ComplianceTab empty-patches state', () => {
  it('renders the no-missing-patches notice when the list is empty (honest rendering)', async () => {
    mockBothEndpoints(
      makeStatusResponse(),
      makeReportResponse({ missing_patches: [] }),
    )
    renderTab()
    await screen.findByTestId('compliance-pill')

    expect(screen.getByTestId('no-missing-patches')).toBeTruthy()
    expect(screen.queryByTestId('patches-table')).toBeNull()
  })
})

describe('ComplianceTab with missing patches', () => {
  it('renders a patches table with patch title, severity, and days overdue', async () => {
    mockBothEndpoints(
      makeStatusResponse({ status: 'critical' }),
      makeReportResponse({
        missing_patches: [
          {
            id: 'KB5040442',
            title: 'Cumulative Update for Windows',
            severity: 'critical',
            category: 'Security',
            release_date: '2026-07-01T00:00:00Z',
            days_overdue: 10,
            days_until_due: 0,
          },
          {
            id: 'KB5041578',
            title: 'Windows Defender Definition Update',
            severity: 'important',
            category: 'Security',
            release_date: '2026-08-01T00:00:00Z',
            days_overdue: 0,
            days_until_due: 4,
          },
        ],
      }),
    )
    renderTab()
    await screen.findByTestId('compliance-pill')

    const table = screen.getByTestId('patches-table')
    expect(table).toBeTruthy()
    expect(screen.getByText('Cumulative Update for Windows')).toBeTruthy()
    expect(screen.getByText('Windows Defender Definition Update')).toBeTruthy()
    expect(screen.getByText('critical')).toBeTruthy()
    expect(screen.getByText('important')).toBeTruthy()
    expect(screen.getByText('10')).toBeTruthy()
    expect(screen.queryByTestId('no-missing-patches')).toBeNull()
  })
})
