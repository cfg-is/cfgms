// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz

/*
 * ReportsDashboardView suite (Story #3270, #3271): all four data states plus
 * a rendered-KPI-values assertion (Story #3270), and Templates tab integration
 * tests covering the TemplateDetailLoader and renderTemplatesTab state machine
 * (Story #3271). Fetch mocking follows the established fetch-mock approach from
 * FleetOverview.test.tsx: vi.stubGlobal + per-URL dispatch inside mockImplementation,
 * fresh Response objects per call.
 */
import { beforeEach, afterEach, describe, expect, it, vi } from 'vitest'
import { act, cleanup, fireEvent, render, screen, waitFor } from '@testing-library/react'
import { MemoryRouter } from 'react-router'
import { AuthProvider } from '../auth/AuthContext.tsx'
import ReportsDashboardView, { TemplateDetailLoader } from './ReportsDashboardView.tsx'
import type { TemplateInfo } from './TemplateList.tsx'

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

const TEMPLATE_DETAIL = {
  name: 'compliance-summary',
  type: 'compliance',
  description: 'Summarises compliance posture across all enrolled devices.',
  parameters: [],
  supported_formats: ['json', 'csv'],
}

const TEMPLATES_LIST = {
  templates: [TEMPLATE_DETAIL],
  count: 1,
}

function mockFullDashboardAndTemplates() {
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
    if (url.includes('/dashboard/trends')) {
      return Promise.resolve(
        new Response(JSON.stringify(TRENDS_BODY), {
          status: 200,
          headers: { 'Content-Type': 'application/json' },
        }),
      )
    }
    if (/\/api\/v1\/reports\/templates\/[^/]+$/.test(url)) {
      return Promise.resolve(
        new Response(JSON.stringify(TEMPLATE_DETAIL), {
          status: 200,
          headers: { 'Content-Type': 'application/json' },
        }),
      )
    }
    if (url.includes('/api/v1/reports/templates')) {
      return Promise.resolve(
        new Response(JSON.stringify(TEMPLATES_LIST), {
          status: 200,
          headers: { 'Content-Type': 'application/json' },
        }),
      )
    }
    return Promise.resolve(new Response('{}', { status: 404 }))
  })
}

describe('Templates tab — tab switching', () => {
  it('shows the tab bar in the ready state', async () => {
    mockDashboard()
    renderView()
    await screen.findByTestId('reports-ready')
    expect(screen.getByTestId('reports-tabs')).toBeInTheDocument()
    expect(screen.getByTestId('tab-overview')).toBeInTheDocument()
    expect(screen.getByTestId('tab-templates')).toBeInTheDocument()
  })

  it('defaults to the Overview tab', async () => {
    mockDashboard()
    renderView()
    await screen.findByTestId('reports-ready')
    expect(screen.getByTestId('tab-overview')).toHaveAttribute('aria-selected', 'true')
    expect(screen.getByTestId('tab-templates')).toHaveAttribute('aria-selected', 'false')
  })

  it('shows the template list when switching to the Templates tab', async () => {
    mockFullDashboardAndTemplates()
    renderView()
    await screen.findByTestId('reports-ready')

    fireEvent.click(screen.getByTestId('tab-templates'))
    await screen.findByTestId('template-list-table')
    expect(screen.queryByTestId('kpi-tiles')).not.toBeInTheDocument()
  })

  it('returns to Overview content when switching back to the Overview tab', async () => {
    mockFullDashboardAndTemplates()
    renderView()
    await screen.findByTestId('reports-ready')

    fireEvent.click(screen.getByTestId('tab-templates'))
    await screen.findByTestId('template-list-table')

    fireEvent.click(screen.getByTestId('tab-overview'))
    await screen.findByTestId('kpi-tiles')
    expect(screen.queryByTestId('template-list-table')).not.toBeInTheDocument()
  })
})

describe('Templates tab — TemplateDetailLoader', () => {
  it('shows the loading skeleton while fetching template detail', async () => {
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
      if (url.includes('/dashboard/trends')) {
        return Promise.resolve(
          new Response(JSON.stringify(TRENDS_BODY), {
            status: 200,
            headers: { 'Content-Type': 'application/json' },
          }),
        )
      }
      if (url.includes('/api/v1/reports/templates')) {
        return Promise.resolve(
          new Response(JSON.stringify(TEMPLATES_LIST), {
            status: 200,
            headers: { 'Content-Type': 'application/json' },
          }),
        )
      }
      // Template detail request stays pending
      return new Promise<Response>(() => {})
    })

    renderView()
    await screen.findByTestId('reports-ready')
    fireEvent.click(screen.getByTestId('tab-templates'))
    await screen.findByTestId('template-list-table')

    fireEvent.click(screen.getByText('compliance-summary'))
    await screen.findByTestId('template-detail-loading')
  })

  it('shows GenerateReportForm after template detail loads successfully', async () => {
    vi.spyOn(URL, 'createObjectURL').mockReturnValue('blob:mock')
    vi.spyOn(URL, 'revokeObjectURL').mockImplementation(() => {})
    mockFullDashboardAndTemplates()

    renderView()
    await screen.findByTestId('reports-ready')
    fireEvent.click(screen.getByTestId('tab-templates'))
    await screen.findByTestId('template-list-table')

    fireEvent.click(screen.getByText('compliance-summary'))
    // After loading, GenerateReportForm appears with template name
    await screen.findByRole('button', { name: /generate/i })
    expect(screen.getByText('compliance-summary')).toBeInTheDocument()
    vi.restoreAllMocks()
  })

  it('shows error notice when template detail fetch fails', async () => {
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
      if (url.includes('/dashboard/trends')) {
        return Promise.resolve(
          new Response(JSON.stringify(TRENDS_BODY), {
            status: 200,
            headers: { 'Content-Type': 'application/json' },
          }),
        )
      }
      if (/\/api\/v1\/reports\/templates\/[^/]+$/.test(url)) {
        return Promise.resolve(
          new Response('{}', {
            status: 404,
            headers: { 'Content-Type': 'application/json' },
          }),
        )
      }
      if (url.includes('/api/v1/reports/templates')) {
        return Promise.resolve(
          new Response(JSON.stringify(TEMPLATES_LIST), {
            status: 200,
            headers: { 'Content-Type': 'application/json' },
          }),
        )
      }
      return Promise.resolve(new Response('{}', { status: 404 }))
    })

    renderView()
    await screen.findByTestId('reports-ready')
    fireEvent.click(screen.getByTestId('tab-templates'))
    await screen.findByTestId('template-list-table')

    fireEvent.click(screen.getByText('compliance-summary'))
    await screen.findByRole('alert')
    expect(screen.getByText(/Could not load template detail/i)).toBeInTheDocument()
  })

  it('recovers to template list when "Back to list" is clicked after error', async () => {
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
      if (url.includes('/dashboard/trends')) {
        return Promise.resolve(
          new Response(JSON.stringify(TRENDS_BODY), {
            status: 200,
            headers: { 'Content-Type': 'application/json' },
          }),
        )
      }
      if (/\/api\/v1\/reports\/templates\/[^/]+$/.test(url)) {
        return Promise.resolve(
          new Response('{}', {
            status: 404,
            headers: { 'Content-Type': 'application/json' },
          }),
        )
      }
      if (url.includes('/api/v1/reports/templates')) {
        return Promise.resolve(
          new Response(JSON.stringify(TEMPLATES_LIST), {
            status: 200,
            headers: { 'Content-Type': 'application/json' },
          }),
        )
      }
      return Promise.resolve(new Response('{}', { status: 404 }))
    })

    renderView()
    await screen.findByTestId('reports-ready')
    fireEvent.click(screen.getByTestId('tab-templates'))
    await screen.findByTestId('template-list-table')

    fireEvent.click(screen.getByText('compliance-summary'))
    await screen.findByRole('alert')

    fireEvent.click(screen.getByRole('button', { name: /back to list/i }))
    await screen.findByTestId('template-list-table')
    expect(screen.queryByRole('alert')).not.toBeInTheDocument()
  })

  it('fetches GET /api/v1/reports/templates/{name} when a template is selected', async () => {
    mockFullDashboardAndTemplates()

    renderView()
    await screen.findByTestId('reports-ready')
    fireEvent.click(screen.getByTestId('tab-templates'))
    await screen.findByTestId('template-list-table')
    fireEvent.click(screen.getByText('compliance-summary'))

    await waitFor(() => {
      const calls = fetchMock.mock.calls.map((c) => String(c[0]))
      expect(calls.some((u) => u.includes('/api/v1/reports/templates/compliance-summary'))).toBe(true)
    })
  })
})

describe('Templates tab — Back from GenerateReportForm', () => {
  it('returns to template list when Back is clicked in GenerateReportForm', async () => {
    vi.spyOn(URL, 'createObjectURL').mockReturnValue('blob:mock')
    vi.spyOn(URL, 'revokeObjectURL').mockImplementation(() => {})
    mockFullDashboardAndTemplates()

    renderView()
    await screen.findByTestId('reports-ready')
    fireEvent.click(screen.getByTestId('tab-templates'))
    await screen.findByTestId('template-list-table')

    fireEvent.click(screen.getByText('compliance-summary'))
    await screen.findByRole('button', { name: /generate/i })

    fireEvent.click(screen.getByRole('button', { name: /back/i }))
    await screen.findByTestId('template-list-table')
    expect(screen.queryByRole('button', { name: /generate/i })).not.toBeInTheDocument()
    vi.restoreAllMocks()
  })

  it('resets a ready selection back to the list when the tab is switched away and back', async () => {
    vi.spyOn(URL, 'createObjectURL').mockReturnValue('blob:mock')
    vi.spyOn(URL, 'revokeObjectURL').mockImplementation(() => {})
    mockFullDashboardAndTemplates()

    renderView()
    await screen.findByTestId('reports-ready')
    fireEvent.click(screen.getByTestId('tab-templates'))
    await screen.findByTestId('template-list-table')

    fireEvent.click(screen.getByText('compliance-summary'))
    await screen.findByRole('button', { name: /generate/i })

    fireEvent.click(screen.getByTestId('tab-overview'))
    await screen.findByTestId('kpi-tiles')

    fireEvent.click(screen.getByTestId('tab-templates'))
    await screen.findByTestId('template-list-table')
    expect(screen.queryByRole('button', { name: /generate/i })).not.toBeInTheDocument()
    vi.restoreAllMocks()
  })

  it('shows the error notice when the template detail request rejects', async () => {
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
      if (url.includes('/dashboard/trends')) {
        return Promise.resolve(
          new Response(JSON.stringify(TRENDS_BODY), {
            status: 200,
            headers: { 'Content-Type': 'application/json' },
          }),
        )
      }
      if (/\/api\/v1\/reports\/templates\/[^/]+$/.test(url)) {
        return Promise.reject(new TypeError('Failed to fetch'))
      }
      if (url.includes('/api/v1/reports/templates')) {
        return Promise.resolve(
          new Response(JSON.stringify(TEMPLATES_LIST), {
            status: 200,
            headers: { 'Content-Type': 'application/json' },
          }),
        )
      }
      return Promise.resolve(new Response('{}', { status: 404 }))
    })

    renderView()
    await screen.findByTestId('reports-ready')
    fireEvent.click(screen.getByTestId('tab-templates'))
    await screen.findByTestId('template-list-table')

    fireEvent.click(screen.getByText('compliance-summary'))
    await screen.findByRole('alert')
    expect(screen.getByText(/Could not load template detail/i)).toBeInTheDocument()
    expect(screen.getByText('Failed to fetch')).toBeInTheDocument()
    expect(screen.queryByTestId('template-detail-loading')).not.toBeInTheDocument()
  })
})

/*
 * TemplateDetailLoader unit tests: the parent-driven cases above exercise the
 * loader through the four-phase state machine; these pin the loader's own
 * contract — which callback fires with which payload, and the cancellation
 * guard that must suppress both callbacks after unmount.
 */
describe('TemplateDetailLoader', () => {
  function jsonResponse(body: unknown, status = 200) {
    return new Response(JSON.stringify(body), {
      status,
      headers: { 'Content-Type': 'application/json' },
    })
  }

  // Flushes the promise chain inside the loader effect (fetch → .json() →
  // callback) without leaning on a timeout budget.
  async function flush() {
    await act(async () => {
      await new Promise((resolve) => setTimeout(resolve, 0))
      await new Promise((resolve) => setTimeout(resolve, 0))
    })
  }

  function renderLoader(name = 'compliance-summary') {
    const onLoaded = vi.fn<(info: TemplateInfo) => void>()
    const onError = vi.fn<(msg: string) => void>()
    const view = render(
      <TemplateDetailLoader name={name} onLoaded={onLoaded} onError={onError} />,
    )
    return { onLoaded, onError, view }
  }

  it('renders a busy skeleton while the request is pending', () => {
    fetchMock.mockImplementation(() => new Promise<Response>(() => {}))
    const { onLoaded, onError } = renderLoader()

    const skeleton = screen.getByTestId('template-detail-loading')
    expect(skeleton).toBeInTheDocument()
    expect(skeleton).toHaveAttribute('aria-busy', 'true')
    expect(onLoaded).not.toHaveBeenCalled()
    expect(onError).not.toHaveBeenCalled()
  })

  it('requests the detail endpoint with the template name percent-encoded', async () => {
    fetchMock.mockImplementation(() => Promise.resolve(jsonResponse(TEMPLATE_DETAIL)))
    renderLoader('drift/weekly report')
    await flush()

    const urls = fetchMock.mock.calls.map((c) => String(c[0]))
    expect(urls).toContain('/api/v1/reports/templates/drift%2Fweekly%20report')
  })

  it('calls onLoaded with the parsed template on a 200 response', async () => {
    fetchMock.mockImplementation(() => Promise.resolve(jsonResponse(TEMPLATE_DETAIL)))
    const { onLoaded, onError } = renderLoader()
    await flush()

    expect(onError).not.toHaveBeenCalled()
    expect(onLoaded).toHaveBeenCalledTimes(1)
    expect(onLoaded).toHaveBeenCalledWith({
      name: 'compliance-summary',
      type: 'compliance',
      description: 'Summarises compliance posture across all enrolled devices.',
      parameters: [],
      supported_formats: ['json', 'csv'],
    })
  })

  it('normalises absent and wrongly-typed fields to safe defaults', async () => {
    fetchMock.mockImplementation(() =>
      Promise.resolve(jsonResponse({ name: 'drift', type: 7, parameters: 'nope' })),
    )
    const { onLoaded, onError } = renderLoader('drift')
    await flush()

    expect(onError).not.toHaveBeenCalled()
    expect(onLoaded).toHaveBeenCalledWith({
      name: 'drift',
      type: '',
      description: '',
      parameters: [],
      supported_formats: [],
    })
  })

  it('calls onError with the status when the response is not ok', async () => {
    fetchMock.mockImplementation(() => Promise.resolve(jsonResponse({}, 503)))
    const { onLoaded, onError } = renderLoader()
    await flush()

    expect(onLoaded).not.toHaveBeenCalled()
    expect(onError).toHaveBeenCalledTimes(1)
    expect(onError.mock.calls.at(0)?.at(0)).toBe(
      'GET /api/v1/reports/templates/compliance-summary — 503',
    )
  })

  it('calls onError with the rejection message when the fetch rejects', async () => {
    fetchMock.mockImplementation(() => Promise.reject(new TypeError('Failed to fetch')))
    const { onLoaded, onError } = renderLoader()
    await flush()

    expect(onLoaded).not.toHaveBeenCalled()
    expect(onError).toHaveBeenCalledWith('Failed to fetch')
  })

  it('calls onError with a fallback message when the rejection carries no message', async () => {
    fetchMock.mockImplementation(() => Promise.reject(new Error('')))
    const { onLoaded, onError } = renderLoader()
    await flush()

    expect(onLoaded).not.toHaveBeenCalled()
    expect(onError).toHaveBeenCalledWith(
      'GET /api/v1/reports/templates/compliance-summary failed',
    )
  })

  it('calls onError when the body is not a template object', async () => {
    fetchMock.mockImplementation(() => Promise.resolve(jsonResponse('not-a-template')))
    const { onLoaded, onError } = renderLoader()
    await flush()

    expect(onLoaded).not.toHaveBeenCalled()
    expect(onError).toHaveBeenCalledWith('unexpected template response shape')
  })

  it('keeps the skeleton mounted until a callback fires', async () => {
    let settle!: (r: Response) => void
    fetchMock.mockImplementation(
      () => new Promise<Response>((resolve) => { settle = resolve }),
    )
    const { onLoaded } = renderLoader()
    expect(screen.getByTestId('template-detail-loading')).toBeInTheDocument()

    settle(jsonResponse(TEMPLATE_DETAIL))
    await flush()
    expect(onLoaded).toHaveBeenCalledTimes(1)
  })

  it('suppresses both callbacks when the response settles after unmount', async () => {
    let settle!: (r: Response) => void
    fetchMock.mockImplementation(
      () => new Promise<Response>((resolve) => { settle = resolve }),
    )
    const { onLoaded, onError, view } = renderLoader()

    view.unmount()
    settle(jsonResponse(TEMPLATE_DETAIL))
    await flush()

    expect(onLoaded).not.toHaveBeenCalled()
    expect(onError).not.toHaveBeenCalled()
  })

  it('suppresses onError when the request fails after unmount', async () => {
    let fail!: (cause: unknown) => void
    fetchMock.mockImplementation(
      () => new Promise<Response>((_resolve, reject) => { fail = reject }),
    )
    const { onLoaded, onError, view } = renderLoader()

    view.unmount()
    fail(new TypeError('Failed to fetch'))
    await flush()

    expect(onLoaded).not.toHaveBeenCalled()
    expect(onError).not.toHaveBeenCalled()
  })
})
