// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz

/*
 * ComplianceSummaryView suite (Story #3272): all four data states, per-tenant
 * table row coverage, and tenant_id pass-through. Fetch mocking follows the
 * established vi.stubGlobal + per-URL dispatch pattern from
 * ReportsDashboardView.test.tsx.
 */
import { beforeEach, afterEach, describe, expect, it, vi } from 'vitest'
import { cleanup, fireEvent, render, screen } from '@testing-library/react'
import { MemoryRouter } from 'react-router'
import { useEffect } from 'react'
import { AuthProvider } from '../auth/AuthContext.tsx'
import { TenantScopeProvider, useTenantScope } from '../shell/TenantScopeContext.tsx'
import ComplianceSummaryView from './ComplianceSummaryView.tsx'

const fetchMock = vi.fn<typeof fetch>()

beforeEach(() => {
  fetchMock.mockReset()
  vi.stubGlobal('fetch', fetchMock)
})

afterEach(() => {
  vi.unstubAllGlobals()
  cleanup()
})

const SUMMARY_BODY = {
  total_devices: 1284,
  compliant_devices: 1102,
  warning_devices: 118,
  critical_devices: 57,
  breached_devices: 7,
  by_tenant: [
    {
      tenant_id: 'root/msp-a/acme-corp',
      tenant_name: 'root/msp-a/acme-corp',
      total_devices: 612,
      compliant_devices: 551,
      warning_devices: 41,
      critical_devices: 17,
      breached_devices: 3,
    },
    {
      tenant_id: 'root/msp-a/vendor-a',
      tenant_name: 'root/msp-a/vendor-a',
      total_devices: 381,
      compliant_devices: 329,
      warning_devices: 35,
      critical_devices: 15,
      breached_devices: 2,
    },
    {
      tenant_id: 'root/msp-b/globex',
      tenant_name: 'root/msp-b/globex',
      total_devices: 206,
      compliant_devices: 167,
      warning_devices: 27,
      critical_devices: 10,
      breached_devices: 2,
    },
  ],
  generated_at: '2026-08-18T12:04:11Z',
}

function mockSummary(body = SUMMARY_BODY) {
  fetchMock.mockImplementation(() =>
    Promise.resolve(
      new Response(JSON.stringify(body), {
        status: 200,
        headers: { 'Content-Type': 'application/json' },
      }),
    ),
  )
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

/** Sets the tenant scope once on mount (for testing scope pass-through). */
function ScopeForcer({ scope, children }: { scope: string; children: React.ReactNode }) {
  const { setScope } = useTenantScope()
  useEffect(() => {
    setScope(scope)
  }, [scope, setScope])
  return <>{children}</>
}

function renderView(rootPath = 'root') {
  return render(
    <MemoryRouter>
      <AuthProvider>
        <TenantScopeProvider rootPath={rootPath}>
          <ComplianceSummaryView />
        </TenantScopeProvider>
      </AuthProvider>
    </MemoryRouter>,
  )
}

function renderViewWithScope(rootPath: string, scope: string) {
  return render(
    <MemoryRouter>
      <AuthProvider>
        <TenantScopeProvider rootPath={rootPath}>
          <ScopeForcer scope={scope}>
            <ComplianceSummaryView />
          </ScopeForcer>
        </TenantScopeProvider>
      </AuthProvider>
    </MemoryRouter>,
  )
}

describe('loading state', () => {
  it('shows skeleton tiles while request is pending', () => {
    fetchMock.mockImplementation(() => new Promise<Response>(() => {}))
    renderView()
    expect(screen.getByTestId('compliance-loading')).toBeInTheDocument()
    expect(screen.queryByTestId('compliance-ready')).not.toBeInTheDocument()
    expect(screen.queryByRole('alert')).not.toBeInTheDocument()
    expect(screen.queryByTestId('compliance-empty')).not.toBeInTheDocument()
  })
})

describe('error state', () => {
  it('shows error notice with retry when request fails', async () => {
    mockError(503)
    renderView()
    await screen.findByRole('alert')
    expect(screen.getByText(/Could not load the compliance summary/i)).toBeInTheDocument()
    expect(screen.getByText(/503/)).toBeInTheDocument()
    expect(screen.queryByTestId('compliance-ready')).not.toBeInTheDocument()
  })

  it('retries on clicking Retry and shows ready state on success', async () => {
    mockError(503)
    renderView()
    await screen.findByRole('alert')

    mockSummary()
    fireEvent.click(screen.getByRole('button', { name: /retry/i }))
    await screen.findByTestId('compliance-ready')
    expect(screen.queryByRole('alert')).not.toBeInTheDocument()
  })
})

describe('empty state', () => {
  it('shows empty notice when total_devices is 0', async () => {
    mockSummary({ ...SUMMARY_BODY, total_devices: 0, by_tenant: [] })
    renderView()
    await screen.findByTestId('compliance-empty')
    expect(screen.getByText(/No devices in scope/i)).toBeInTheDocument()
    expect(screen.queryByTestId('compliance-ready')).not.toBeInTheDocument()
    expect(screen.queryByTestId('compliance-kpi-tiles')).not.toBeInTheDocument()
  })
})

describe('ready state', () => {
  it('renders stat tile values from the summary', async () => {
    mockSummary()
    renderView()
    await screen.findByTestId('compliance-ready')

    expect(screen.getByTestId('kpi-total').textContent).toContain('1,284')
    expect(screen.getByTestId('kpi-compliant').textContent).toContain('1,102')
    expect(screen.getByTestId('kpi-warning').textContent).toContain('118')
    expect(screen.getByTestId('kpi-critical').textContent).toContain('57')
    expect(screen.getByTestId('kpi-breached').textContent).toContain('7')
  })

  it('renders hero percentage computed from compliant / total', async () => {
    mockSummary()
    renderView()
    await screen.findByTestId('compliance-ready')
    const hero = screen.getByTestId('compliance-hero-pct')
    expect(hero.textContent).toContain('85.8')
  })

  it('renders every by_tenant row in the table', async () => {
    mockSummary()
    renderView()
    await screen.findByTestId('tenant-table')
    const rows = screen.getAllByTestId('tenant-row')
    expect(rows).toHaveLength(3)
    expect(rows.some((r) => r.textContent?.includes('acme-corp'))).toBe(true)
    expect(rows.some((r) => r.textContent?.includes('vendor-a'))).toBe(true)
    expect(rows.some((r) => r.textContent?.includes('globex'))).toBe(true)
  })

  it('shows per-row device counts', async () => {
    mockSummary()
    renderView()
    await screen.findByTestId('tenant-table')
    const rows = screen.getAllByTestId('tenant-row')
    const acme = rows.find((r) => r.textContent?.includes('acme-corp'))
    expect(acme?.textContent).toContain('612')
    expect(acme?.textContent).toContain('551')
  })

  it('allows sorting the table by clicking a column header', async () => {
    mockSummary()
    renderView()
    await screen.findByTestId('tenant-table')

    // Default sort: total_devices descending → acme-corp (612), vendor-a (381), globex (206)
    // Click once for ascending → globex (206), vendor-a (381), acme-corp (612)
    fireEvent.click(screen.getByTestId('sort-total_devices'))
    const rows = screen.getAllByTestId('tenant-row')
    expect(rows).toHaveLength(3)
    expect(rows[0]?.textContent).toContain('globex')
    expect(rows[1]?.textContent).toContain('vendor-a')
    expect(rows[2]?.textContent).toContain('acme-corp')
  })

  it('reverses sort direction on second click of the same column', async () => {
    mockSummary()
    renderView()
    await screen.findByTestId('tenant-table')

    fireEvent.click(screen.getByTestId('sort-total_devices'))
    fireEvent.click(screen.getByTestId('sort-total_devices'))
    const rows = screen.getAllByTestId('tenant-row')
    expect(rows).toHaveLength(3)
    expect(rows[0]?.textContent).toContain('acme-corp')
  })

  it('shows empty table notice when by_tenant is empty but total_devices > 0', async () => {
    mockSummary({ ...SUMMARY_BODY, by_tenant: [] })
    renderView()
    await screen.findByTestId('compliance-ready')
    expect(screen.getByTestId('tenant-table-empty')).toBeInTheDocument()
  })
})

describe('tenant scope pass-through', () => {
  it('omits tenant_id param when at root scope', async () => {
    mockSummary()
    renderView('root')
    await screen.findByTestId('compliance-ready')
    const calls = fetchMock.mock.calls.map(([url]) => String(url))
    expect(calls.some((u) => u.includes('tenant_id'))).toBe(false)
    expect(calls.some((u) => u.includes('/compliance/summary'))).toBe(true)
  })

  it('passes tenant_id when scope is narrowed', async () => {
    mockSummary()
    renderViewWithScope('root', 'root/msp-a')
    await screen.findByTestId('compliance-ready')
    const calls = fetchMock.mock.calls.map(([url]) => String(url))
    expect(calls.some((u) => u.includes('tenant_id=root%2Fmsp-a'))).toBe(true)
  })
})
