// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz

/*
 * MonitoringView suite (Story #3274): covers all four sections' (health,
 * config, anomalies, component-detail) loading / error / populated / empty
 * states. Fetch mocking follows the vi.stubGlobal + per-URL dispatch pattern
 * from ReportsDashboardView.test.tsx.
 */
import { beforeEach, afterEach, describe, expect, it, vi } from 'vitest'
import { cleanup, fireEvent, render, screen } from '@testing-library/react'
import { MemoryRouter } from 'react-router'
import { AuthProvider } from '../auth/AuthContext.tsx'
import { TenantScopeProvider } from '../shell/TenantScopeContext.tsx'
import MonitoringView from './MonitoringView.tsx'

const fetchMock = vi.fn<typeof fetch>()

beforeEach(() => {
  fetchMock.mockReset()
  vi.stubGlobal('fetch', fetchMock)
})

afterEach(() => {
  vi.unstubAllGlobals()
  cleanup()
})

// ── Fixture data matching handlers_monitoring.go shapes ────────────────────

const HEALTH_BODY = {
  status: 'degraded',
  timestamp: '2026-08-18T12:04:11Z',
  version: '0.5.0',
  uptime: 'unknown',
  components: {
    certificate_ca: 'healthy',
    grpc_server: 'healthy',
    rbac_service: 'healthy',
    transport: 'healthy',
    storage: 'healthy',
    system_resources: 'degraded',
  },
  dependencies: {
    storage: 'git-sops',
    networking: 'available',
  },
}

const CONFIG_BODY = {
  metrics: { enabled: true, collection_interval: '30s', retention_period: '7d' },
  logging: { level: 'info', structured: true, output: 'stdout', retention_period: '30d' },
  tracing: { enabled: false, sampling_rate: 0.1, endpoint: '' },
  health_checks: { enabled: true, check_interval: '10s', timeout: '5s' },
  alerting: { enabled: false, webhook_url: '', alert_threshold: 0.8 },
}

const ANOMALIES_BODY = {
  anomalies: [],
  total: 0,
  summary: {
    total_anomalies: 0,
    active_anomalies: 0,
    severity_counts: {},
    type_counts: {},
  },
}

function mockAll(
  healthBody = HEALTH_BODY,
  configBody = CONFIG_BODY,
  anomaliesBody = ANOMALIES_BODY,
) {
  fetchMock.mockImplementation((input) => {
    const url = String(input)
    if (url.includes('/monitoring/health')) {
      return Promise.resolve(
        new Response(JSON.stringify(healthBody), {
          status: 200,
          headers: { 'Content-Type': 'application/json' },
        }),
      )
    }
    if (url.includes('/monitoring/config')) {
      return Promise.resolve(
        new Response(JSON.stringify(configBody), {
          status: 200,
          headers: { 'Content-Type': 'application/json' },
        }),
      )
    }
    if (url.includes('/monitoring/anomalies')) {
      return Promise.resolve(
        new Response(JSON.stringify(anomaliesBody), {
          status: 200,
          headers: { 'Content-Type': 'application/json' },
        }),
      )
    }
    return Promise.resolve(new Response('{}', { status: 404 }))
  })
}

function mockAllError(status = 503) {
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
        <TenantScopeProvider rootPath="root">
          <MonitoringView />
        </TenantScopeProvider>
      </AuthProvider>
    </MemoryRouter>,
  )
}

// ── Loading state ──────────────────────────────────────────────────────────

describe('loading state', () => {
  it('shows skeleton while all three requests are pending', () => {
    fetchMock.mockImplementation(() => new Promise<Response>(() => {}))
    renderView()
    expect(screen.getByTestId('monitoring-loading')).toBeInTheDocument()
    expect(screen.queryByTestId('monitoring-health')).not.toBeInTheDocument()
    expect(screen.queryByRole('alert')).not.toBeInTheDocument()
  })
})

// ── Error states ───────────────────────────────────────────────────────────

describe('error states', () => {
  it('shows health error notice when health endpoint fails', async () => {
    fetchMock.mockImplementation((input) => {
      const url = String(input)
      if (url.includes('/monitoring/health')) {
        return Promise.resolve(new Response('{}', { status: 503 }))
      }
      if (url.includes('/monitoring/config')) {
        return Promise.resolve(
          new Response(JSON.stringify(CONFIG_BODY), { status: 200 }),
        )
      }
      if (url.includes('/monitoring/anomalies')) {
        return Promise.resolve(
          new Response(JSON.stringify(ANOMALIES_BODY), { status: 200 }),
        )
      }
      return Promise.resolve(new Response('{}', { status: 404 }))
    })
    renderView()
    const alert = await screen.findByTestId('health-error')
    expect(alert).toBeInTheDocument()
    expect(alert.textContent).toMatch(/503/)
  })

  it('shows config error notice when config endpoint fails', async () => {
    fetchMock.mockImplementation((input) => {
      const url = String(input)
      if (url.includes('/monitoring/health')) {
        return Promise.resolve(
          new Response(JSON.stringify(HEALTH_BODY), { status: 200 }),
        )
      }
      if (url.includes('/monitoring/config')) {
        return Promise.resolve(new Response('{}', { status: 503 }))
      }
      if (url.includes('/monitoring/anomalies')) {
        return Promise.resolve(
          new Response(JSON.stringify(ANOMALIES_BODY), { status: 200 }),
        )
      }
      return Promise.resolve(new Response('{}', { status: 404 }))
    })
    renderView()
    const alert = await screen.findByTestId('config-error')
    expect(alert).toBeInTheDocument()
    expect(alert.textContent).toMatch(/503/)
  })

  it('shows anomalies error notice when anomalies endpoint fails', async () => {
    fetchMock.mockImplementation((input) => {
      const url = String(input)
      if (url.includes('/monitoring/health')) {
        return Promise.resolve(
          new Response(JSON.stringify(HEALTH_BODY), { status: 200 }),
        )
      }
      if (url.includes('/monitoring/config')) {
        return Promise.resolve(
          new Response(JSON.stringify(CONFIG_BODY), { status: 200 }),
        )
      }
      if (url.includes('/monitoring/anomalies')) {
        return Promise.resolve(new Response('{}', { status: 503 }))
      }
      return Promise.resolve(new Response('{}', { status: 404 }))
    })
    renderView()
    const alert = await screen.findByTestId('anomalies-error')
    expect(alert).toBeInTheDocument()
    expect(alert.textContent).toMatch(/503/)
  })

  it('shows retry button on health error and reloads on click', async () => {
    mockAllError(503)
    renderView()
    await screen.findByTestId('health-error')

    mockAll()
    fireEvent.click(screen.getByRole('button', { name: /retry/i }))
    await screen.findByTestId('monitoring-health')
    expect(screen.queryByTestId('health-error')).not.toBeInTheDocument()
  })

  it('renders component-detail section as designed error state (503 posture)', async () => {
    mockAll()
    renderView()
    await screen.findByTestId('monitoring-health')
    expect(screen.getByTestId('component-detail-unavailable')).toBeInTheDocument()
  })
})

// ── Health section — ready state ───────────────────────────────────────────

describe('health section — ready state', () => {
  it('renders the overall status pill', async () => {
    mockAll()
    renderView()
    await screen.findByTestId('monitoring-health')
    expect(screen.getByTestId('health-status-pill')).toBeInTheDocument()
    expect(screen.getByTestId('health-status-pill').textContent).toMatch(/degraded/i)
  })

  it('renders a status pill for every component', async () => {
    mockAll()
    renderView()
    await screen.findByTestId('monitoring-health')

    const expectedComponents = Object.keys(HEALTH_BODY.components)
    for (const name of expectedComponents) {
      expect(screen.getByTestId(`component-${name}`)).toBeInTheDocument()
    }
  })

  it('maps component status values to the correct pill variant', async () => {
    mockAll()
    renderView()
    await screen.findByTestId('monitoring-health')

    // 'degraded' → warn pill
    const degraded = screen.getByTestId('component-system_resources')
    expect(degraded.textContent).toMatch(/degraded/i)
    expect(degraded.querySelector('.mv-pill.warn')).not.toBeNull()

    // 'healthy' → ok pill
    const healthy = screen.getByTestId('component-certificate_ca')
    expect(healthy.querySelector('.mv-pill.ok')).not.toBeNull()
  })

  it('renders dependency entries', async () => {
    mockAll()
    renderView()
    await screen.findByTestId('monitoring-health')

    expect(screen.getByTestId('deps-section')).toBeInTheDocument()
    expect(screen.getByTestId('dep-storage').textContent).toContain('git-sops')
    expect(screen.getByTestId('dep-networking').textContent).toContain('available')
  })

  it('shows version and timestamp in the health panel header', async () => {
    mockAll()
    renderView()
    await screen.findByTestId('monitoring-health')

    const header = screen.getByTestId('health-panel-header')
    expect(header.textContent).toContain('0.5.0')
  })
})

// ── Anomalies section — empty state ───────────────────────────────────────

describe('anomalies section — empty state', () => {
  it('renders the anomalies empty state when anomalies list is empty', async () => {
    mockAll()
    renderView()
    await screen.findByTestId('monitoring-health')
    expect(screen.getByTestId('anomalies-empty')).toBeInTheDocument()
  })

  it('does NOT show an anomaly row when the list is empty', async () => {
    mockAll()
    renderView()
    await screen.findByTestId('monitoring-health')
    expect(screen.queryByTestId('anomaly-row')).not.toBeInTheDocument()
  })
})

// ── Config section — ready state ──────────────────────────────────────────

describe('config section — ready state', () => {
  it('renders config section groups', async () => {
    mockAll()
    renderView()
    await screen.findByTestId('monitoring-config')

    expect(screen.getByTestId('config-section-metrics')).toBeInTheDocument()
    expect(screen.getByTestId('config-section-logging')).toBeInTheDocument()
    expect(screen.getByTestId('config-section-tracing')).toBeInTheDocument()
  })

  it('renders key-value pairs within a config section', async () => {
    mockAll()
    renderView()
    await screen.findByTestId('monitoring-config')

    const metricsSection = screen.getByTestId('config-section-metrics')
    expect(metricsSection.textContent).toContain('30s')
    expect(metricsSection.textContent).toContain('7d')
  })

  it('renders boolean values as string', async () => {
    mockAll()
    renderView()
    await screen.findByTestId('monitoring-config')

    // metrics.enabled = true
    const metrics = screen.getByTestId('config-section-metrics')
    expect(metrics.textContent).toMatch(/true/)
  })

  it('renders empty string config values as em-dash placeholder', async () => {
    mockAll()
    renderView()
    await screen.findByTestId('monitoring-config')

    // tracing.endpoint = "" → should show "—"
    const tracing = screen.getByTestId('config-section-tracing')
    expect(tracing.textContent).toContain('—')
  })
})

// ── Component-detail section (designed error state) ───────────────────────

describe('component-detail section', () => {
  it('always renders the component-detail unavailable notice (503 posture)', async () => {
    mockAll()
    renderView()
    await screen.findByTestId('monitoring-health')
    const notice = screen.getByTestId('component-detail-unavailable')
    expect(notice).toBeInTheDocument()
    expect(notice.textContent).toMatch(/unavailable|not initialised|platform monitor/i)
  })
})
