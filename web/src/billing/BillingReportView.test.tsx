// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz

/*
 * Billing report screen suite (Issue #4650). Fetch is stubbed with fresh
 * Response objects per call, following ReportsDashboardView.test.tsx; the
 * stub also serves a tenant list carrying client names so the root view can be
 * shown never to read it.
 */
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'
import { cleanup, fireEvent, render, screen, waitFor } from '@testing-library/react'
import { MemoryRouter } from 'react-router'
import { TenantScopeProvider } from '../shell/TenantScopeContext.tsx'
import BillingReportView from './BillingReportView.tsx'

const fetchMock = vi.fn<typeof fetch>()

const METRICS = {
  endpoints_online: 11,
  endpoints_offline: 3,
  endpoints_pending: 2,
  endpoints_by_platform: { windows: 9, linux: 5, darwin: 1, other: 1 },
  endpoints_by_version: { '1.4.0': 12, '1.3.2': 4 },
}

const ROOT_BODY = {
  data: {
    msps: [
      {
        id: 'msp-a',
        name: 'MSP Alpha',
        tech_count: 4,
        endpoint_count: 16,
        client_count: 2,
        metrics: METRICS,
        msp_own: { tech_count: 4, endpoint_count: 1 },
        clients: [
          { label: 'K7Q2', endpoint_count: 10, tech_count: 2 },
          { label: 'M3ZD', endpoint_count: 5, tech_count: 1 },
        ],
      },
      {
        id: 'msp-b',
        name: 'MSP Beta',
        tech_count: 2,
        endpoint_count: 4,
        client_count: 0,
        metrics: METRICS,
        msp_own: { tech_count: 2, endpoint_count: 4 },
        clients: [],
      },
    ],
  },
}

const TENANT_BODY = {
  data: {
    id: 'msp-a',
    name: 'MSP Alpha',
    tech_count: 4,
    endpoint_count: 16,
    client_count: 2,
    metrics: METRICS,
    msp_own: { tech_count: 4, endpoint_count: 1 },
    clients: [
      { id: 'client-1', name: 'Acme Corp', endpoint_count: 10, tech_count: 2 },
      { id: 'client-2', name: 'Globex Ltd', endpoint_count: 5, tech_count: 1 },
    ],
  },
}

const TENANT_LIST = {
  data: [
    { id: 'client-1', name: 'Acme Corp', parent_id: 'msp-a' },
    { id: 'client-2', name: 'Globex Ltd', parent_id: 'msp-a' },
  ],
}

function json(status: number, body: unknown) {
  return new Response(JSON.stringify(body), {
    status,
    headers: { 'Content-Type': 'application/json' },
  })
}

function urlOf(input: Parameters<typeof fetch>[0]): string {
  if (typeof input === 'string') return input
  if (input instanceof URL) return input.toString()
  return input.url
}

function requested(): string[] {
  return fetchMock.mock.calls.map((c) => urlOf(c[0]))
}

function serve(routes: Record<string, () => Response>) {
  fetchMock.mockImplementation((input) => {
    const handler = routes[urlOf(input)]
    return Promise.resolve(handler ? handler() : json(404, {}))
  })
}

function renderView(rootPath: string) {
  return render(
    <MemoryRouter>
      <TenantScopeProvider rootPath={rootPath}>
        <BillingReportView />
      </TenantScopeProvider>
    </MemoryRouter>,
  )
}

async function expandAll() {
  for (const b of await screen.findAllByRole('button', { expanded: false })) {
    fireEvent.click(b)
  }
}

beforeEach(() => {
  fetchMock.mockReset()
  vi.stubGlobal('fetch', fetchMock)
})

afterEach(() => {
  cleanup()
  vi.unstubAllGlobals()
  vi.restoreAllMocks()
})

describe('root view', () => {
  beforeEach(() => {
    serve({
      '/api/v1/billing/report': () => json(200, ROOT_BODY),
      '/api/v1/tenants': () => json(200, TENANT_LIST),
    })
  })

  it('shows tiles, each MSP, and each client label with its counts', async () => {
    renderView('')
    await screen.findByText('MSP Alpha')
    expect(screen.getByText('MSP Beta')).toBeInTheDocument()
    const tiles = screen.getByTestId('billing-root').querySelector('.rdb-kpis')!
    expect(tiles).toHaveTextContent('MSPs2')
    expect(tiles).toHaveTextContent('Total endpoints20')
    expect(tiles).toHaveTextContent('Total techs6')

    await expandAll()
    const k7 = screen.getByText('Client K7Q2').closest('tr')!
    expect(k7).toHaveTextContent('2')
    expect(k7).toHaveTextContent('10')
    const m3 = screen.getByText('Client M3ZD').closest('tr')!
    expect(m3).toHaveTextContent('1')
    expect(m3).toHaveTextContent('5')
  })

  it('never renders a client name or tenant id, even with a tenant list available', async () => {
    renderView('')
    await screen.findByText('MSP Alpha')
    await expandAll()
    const text = document.body.textContent ?? ''
    for (const forbidden of ['Acme Corp', 'Globex Ltd', 'client-1', 'client-2']) {
      expect(text).not.toContain(forbidden)
    }
  })

  it('types a client as label-only: unexpected name or id fields render nothing', async () => {
    const body = structuredClone(ROOT_BODY)
    Object.assign(body.data.msps[0]!.clients[0]!, { name: 'Leaky Client Inc', id: 'tenant-leak-9' })
    serve({ '/api/v1/billing/report': () => json(200, body) })
    renderView('')
    await screen.findByText('MSP Alpha')
    await expandAll()
    expect(screen.getByText('Client K7Q2')).toBeInTheDocument()
    expect(document.body.textContent).not.toContain('Leaky Client Inc')
    expect(document.body.textContent).not.toContain('tenant-leak-9')
  })

  it('renders online, offline, pending, platform mix and version mix', async () => {
    renderView('')
    await screen.findByText('MSP Alpha')
    await expandAll()
    const metrics = screen.getAllByRole('region', { name: 'Metrics' })[0]
    for (const expected of [
      'Online: 11',
      'Offline: 3',
      'Pending: 2',
      'Windows: 9',
      'Linux: 5',
      'macOS: 1',
      'Other: 1',
      '1.4.0: 12',
      '1.3.2: 4',
    ]) {
      expect(metrics).toHaveTextContent(expected)
    }
  })

  it('requests only /api/v1/billing/report', async () => {
    renderView('')
    await screen.findByText('MSP Alpha')
    expect(requested()).toEqual(['/api/v1/billing/report'])
  })

  it('renders a label as plain text: no link, no href, data-* or storage write', async () => {
    const setItem = vi.spyOn(Storage.prototype, 'setItem')
    renderView('')
    await screen.findByText('MSP Alpha')
    await expandAll()
    const cell = screen.getByText('Client K7Q2')
    expect(cell.closest('a')).toBeNull()
    expect(cell.closest('button')).toBeNull()
    expect(screen.queryByRole('link')).toBeNull()
    for (const el of document.body.querySelectorAll('*')) {
      expect(el.getAttribute('href')).toBeNull()
      for (const attr of Array.from(el.attributes)) {
        if (attr.name.startsWith('data-')) {
          expect(attr.value).not.toMatch(/K7Q2|M3ZD/)
        }
      }
    }
    expect(setItem).not.toHaveBeenCalled()
    expect(window.localStorage.length).toBe(0)
    expect(window.sessionStorage.length).toBe(0)
  })

  it('shows the Error state with the server message on a 403', async () => {
    serve({
      '/api/v1/billing/report': () =>
        json(403, { error: { code: 'BILLING_ROOT_ONLY', message: 'root operator only' } }),
    })
    renderView('')
    expect(await screen.findByRole('alert')).toHaveTextContent('root operator only')
  })

  it('shows the Empty state when there are no MSPs', async () => {
    serve({ '/api/v1/billing/report': () => json(200, { data: { msps: [] } }) })
    renderView('')
    expect(await screen.findByTestId('billing-empty')).toBeInTheDocument()
  })

  it('shows the Loading state while the request is pending', () => {
    fetchMock.mockImplementation(() => new Promise<Response>(() => {}))
    renderView('')
    expect(screen.getByTestId('billing-loading')).toBeInTheDocument()
  })
})

describe('MSP view', () => {
  it('shows the subtree with real client names and the standing disclosure', async () => {
    serve({ '/api/v1/tenants/msp-a/billing-report': () => json(200, TENANT_BODY) })
    renderView('msp-a')
    await screen.findByText('Acme Corp')
    expect(screen.getByText('Globex Ltd')).toBeInTheDocument()
    expect(screen.getByTestId('billing-disclosure')).toHaveTextContent(
      'Root can see these same figures for your organization.',
    )
    expect(screen.getByText('Acme Corp').closest('tr')).toHaveTextContent('10')
    expect(screen.getByRole('region', { name: 'Metrics' })).toHaveTextContent('Online: 11')
  })

  it('requests only /api/v1/tenants/{id}/billing-report', async () => {
    serve({ '/api/v1/tenants/msp-a/billing-report': () => json(200, TENANT_BODY) })
    renderView('msp-a')
    await screen.findByText('Acme Corp')
    expect(requested()).toEqual(['/api/v1/tenants/msp-a/billing-report'])
  })

  it('shows the Empty state for an MSP with no clients', async () => {
    const body = { data: { ...TENANT_BODY.data, client_count: 0, clients: [] } }
    serve({ '/api/v1/tenants/msp-a/billing-report': () => json(200, body) })
    renderView('msp-a')
    expect(await screen.findByTestId('billing-empty')).toBeInTheDocument()
  })

  it('shows the Error state and retries', async () => {
    let calls = 0
    serve({
      '/api/v1/tenants/msp-a/billing-report': () =>
        ++calls === 1 ? json(500, {}) : json(200, TENANT_BODY),
    })
    renderView('msp-a')
    const alert = await screen.findByRole('alert')
    expect(alert).toHaveTextContent('500')
    fireEvent.click(screen.getByRole('button', { name: 'Retry' }))
    await waitFor(() => expect(screen.getByText('Acme Corp')).toBeInTheDocument())
  })
})
