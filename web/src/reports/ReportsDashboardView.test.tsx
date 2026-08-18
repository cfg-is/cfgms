// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz

/*
 * ReportsDashboardView suite (Story #3270): all four data states plus a
 * rendered-KPI-values assertion. Fetch mocking follows the established
 * fetch-mock approach from FleetOverview.test.tsx: vi.stubGlobal + per-URL
 * dispatch inside mockImplementation, fresh Response objects per call.
 */
import { beforeEach, afterEach, describe, expect, it, vi } from 'vitest'
import { cleanup, fireEvent, render, screen, waitFor } from '@testing-library/react'
import { MemoryRouter } from 'react-router'
import { AuthProvider } from '../auth/AuthContext.tsx'
import ReportsDashboardView from './ReportsDashboardView.tsx'

const fetchMock = vi.fn<typeof fetch>()

beforeEach(() => {
  fetchMock.mockReset()
  vi.stubGlobal('fetch', fetchMock)
})

afterEach(() => {
  vi.unstubAllGlobals()
  cleanup()
})

const OVERVIEW_BODY = {
  summary: {
    devices_analyzed: 1284,
    drift_events_total: 212,
    compliance_score: 92.5,
    critical_issues: 7,
    trend_direction: 'improving',
    key_insights: [
      'Drift events fell 18% week over week.',
      'Seven hosts account for 61% of all critical findings.',
    ],
    recommended_actions: [
      'Re-converge the 7 hosts carrying critical findings.',
    ],
  },
  metadata: {
    template: 'executive-dashboard',
    device_count: 1284,
    data_points: 8988,
    generation_ms: 412,
    cache_hit: false,
  },
  time_range: { start: '2026-08-04T00:00:00Z', end: '2026-08-11T00:00:00Z' },
  generated_at: '2026-08-11T12:04:11Z',
}

const TRENDS_BODY = {
  charts: [
    {
      id: 'drift-trend',
      type: 'line',
      title: 'Drift events over time',
      series: [
        {
          name: 'Drift events',
          data: [
            { x: '2026-08-04', y: 58 },
            { x: '2026-08-05', y: 51 },
            { x: '2026-08-06', y: 44 },
            { x: '2026-08-07', y: 47 },
            { x: '2026-08-08', y: 33 },
            { x: '2026-08-09', y: 29 },
            { x: '2026-08-10', y: 26 },
            { x: '2026-08-11', y: 22 },
          ],
        },
      ],
      x_axis: { title: 'Date', type: 'time' },
      y_axis: { title: 'Events', type: 'numeric' },
      config: { show_legend: false },
    },
  ],
  time_range: { start: '2026-08-04T00:00:00Z', end: '2026-08-11T00:00:00Z' },
  generated_at: '2026-08-11T12:04:11Z',
}

function mockDashboard(
  overviewBody = OVERVIEW_BODY,
  trendsBody = TRENDS_BODY,
) {
  fetchMock.mockImplementation((input) => {
    const url = String(input)
    if (url.includes('/dashboard/overview')) {
      return Promise.resolve(
        new Response(JSON.stringify(overviewBody), {
          status: 200,
          headers: { 'Content-Type': 'application/json' },
        }),
      )
    }
    if (url.includes('/dashboard/trends')) {
      return Promise.resolve(
        new Response(JSON.stringify(trendsBody), {
          status: 200,
          headers: { 'Content-Type': 'application/json' },
        }),
      )
    }
    return Promise.resolve(new Response('{}', { status: 404 }))
  })
}

function mockError(status = 503) {
  fetchMock.mockImplementation(() =>
    Promise.resolve(
      new Response('{}', {
        status,
        headers: { 'Content-Type': 'application/json' },
      }),
    ),
  )
}

function renderView() {
  return render(
    <MemoryRouter>
      <AuthProvider>
        <ReportsDashboardView />
      </AuthProvider>
    </MemoryRouter>,
  )
}

describe('loading state', () => {
  it('shows skeleton tiles while requests are pending', () => {
    fetchMock.mockImplementation(() => new Promise<Response>(() => {}))
    renderView()
    expect(screen.getByTestId('reports-loading')).toBeInTheDocument()
    expect(screen.queryByTestId('reports-ready')).not.toBeInTheDocument()
    expect(screen.queryByRole('alert')).not.toBeInTheDocument()
    expect(screen.queryByTestId('reports-empty')).not.toBeInTheDocument()
  })
})

describe('error state', () => {
  it('shows an error notice with retry when overview request fails', async () => {
    mockError(503)
    renderView()
    await screen.findByRole('alert')
    expect(
      screen.getByText(/Could not generate the dashboard overview/i),
    ).toBeInTheDocument()
    expect(screen.getByText(/503/)).toBeInTheDocument()
    expect(screen.queryByTestId('reports-ready')).not.toBeInTheDocument()
  })

  it('retries on clicking Retry and shows ready state on success', async () => {
    mockError(503)
    renderView()
    await screen.findByRole('alert')

    mockDashboard()
    fireEvent.click(screen.getByRole('button', { name: /retry/i }))
    await screen.findByTestId('reports-ready')
    expect(screen.queryByRole('alert')).not.toBeInTheDocument()
  })

  it('shows error when trends request fails and overview succeeds', async () => {
    fetchMock.mockImplementation((input) => {
      const url = String(input)
      if (url.includes('/dashboard/overview')) {
        return Promise.resolve(
          new Response(JSON.stringify(OVERVIEW_BODY), {
            status: 200,
            headers: { 'Content-Type': 'application/json' },
          }),
        )
      }
      return Promise.resolve(
        new Response('{}', { status: 500, headers: { 'Content-Type': 'application/json' } }),
      )
    })
    renderView()
    await screen.findByRole('alert')
    expect(screen.getByText(/500/)).toBeInTheDocument()
  })
})

describe('empty state', () => {
  it('shows empty notice when devices_analyzed is 0', async () => {
    const emptyOverview = {
      ...OVERVIEW_BODY,
      summary: { ...OVERVIEW_BODY.summary, devices_analyzed: 0 },
    }
    const emptyTrends = {
      charts: [],
      time_range: TRENDS_BODY.time_range,
      generated_at: TRENDS_BODY.generated_at,
    }
    mockDashboard(emptyOverview, emptyTrends)
    renderView()
    await screen.findByTestId('reports-empty')
    expect(screen.getByText(/No data in this window/i)).toBeInTheDocument()
    expect(screen.queryByTestId('kpi-tiles')).not.toBeInTheDocument()
    expect(screen.queryByTestId('reports-ready')).not.toBeInTheDocument()
  })
})

describe('ready state', () => {
  it('renders KPI tile values from the overview summary', async () => {
    mockDashboard()
    renderView()
    await screen.findByTestId('reports-ready')

    expect(screen.getByTestId('kpi-devices-analyzed').textContent).toContain('1,284')
    expect(screen.getByTestId('kpi-drift-events').textContent).toContain('212')
    expect(screen.getByTestId('kpi-critical-issues').textContent).toContain('7')
    expect(screen.getByTestId('kpi-generation-ms').textContent).toContain('412')
  })

  it('renders the compliance score and trend direction pill', async () => {
    mockDashboard()
    renderView()
    await waitFor(() => {
      expect(screen.getByTestId('compliance-score')).toBeInTheDocument()
    })
    expect(screen.getByTestId('compliance-score').textContent).toContain('92.5')
    expect(screen.getByTestId('trend-direction-pill').textContent).toContain('Improving')
  })

  it('renders the trend chart using the TrendChart primitive', async () => {
    mockDashboard()
    renderView()
    await screen.findByTestId('trend-chart')
    expect(screen.getByText('Drift events over time')).toBeInTheDocument()
  })

  it('renders key insights and recommended actions', async () => {
    mockDashboard()
    renderView()
    await screen.findByTestId('reports-ready')
    expect(
      screen.getByText('Drift events fell 18% week over week.'),
    ).toBeInTheDocument()
    expect(
      screen.getByText('Re-converge the 7 hosts carrying critical findings.'),
    ).toBeInTheDocument()
  })

  it('omits key-insights and recommended-actions panels when lists are empty', async () => {
    const noInsightsOverview = {
      ...OVERVIEW_BODY,
      summary: { ...OVERVIEW_BODY.summary, key_insights: [], recommended_actions: [] },
    }
    mockDashboard(noInsightsOverview)
    renderView()
    await screen.findByTestId('reports-ready')
    expect(screen.queryByText('Key insights')).not.toBeInTheDocument()
    expect(screen.queryByText('Recommended actions')).not.toBeInTheDocument()
  })

  it('renders "computed fresh" sub-label when cache_hit is false', async () => {
    mockDashboard()
    renderView()
    await screen.findByTestId('kpi-generation-ms')
    expect(screen.getByTestId('kpi-generation-ms').textContent).toContain('computed fresh')
  })

  it('shows the trend chart panel when charts array is non-empty', async () => {
    mockDashboard()
    renderView()
    await screen.findByTestId('reports-ready')
    expect(screen.getByTestId('trend-chart')).toBeInTheDocument()
  })

  it('omits the trend chart panel when charts array is empty', async () => {
    const noChartsTrends = { charts: [], time_range: TRENDS_BODY.time_range, generated_at: TRENDS_BODY.generated_at }
    mockDashboard(OVERVIEW_BODY, noChartsTrends)
    renderView()
    await screen.findByTestId('reports-ready')
    expect(screen.queryByTestId('trend-chart')).not.toBeInTheDocument()
  })
})
