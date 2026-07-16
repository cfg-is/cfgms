// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz

/*
 * Fleet overview suite (Story #2497): pagination param generation + total
 * rendering, live-filter narrowing, sort ordering, column add/remove +
 * persistence, health mapping (incl. staleness), the loading/error/empty
 * states, tenant-scope narrowing, and the hostile-DNA text-node guarantee
 * (security A9.1).
 */
import { beforeEach, afterEach, describe, expect, it, vi } from 'vitest'
import {
  cleanup,
  fireEvent,
  render,
  screen,
  waitFor,
  within,
} from '@testing-library/react'
import { AuthProvider } from '../auth/AuthContext.tsx'
import {
  TenantScopeProvider,
  useTenantScope,
} from '../shell/TenantScopeContext.tsx'
import FleetOverview from './FleetOverview.tsx'
import { STALE_AFTER_MS } from './health.ts'
import type { Steward } from './columns.ts'

const fetchMock = vi.fn<typeof fetch>()

beforeEach(() => {
  fetchMock.mockReset()
  vi.stubGlobal('fetch', fetchMock)
  localStorage.clear()
})

afterEach(() => {
  vi.unstubAllGlobals()
})

interface StewardSpec {
  id: string
  hostname?: string
  status?: string
  lastSeenMsAgo?: number | null
  attributes?: Record<string, string>
  version?: string
}

function makeSteward(spec: StewardSpec): Steward {
  const lastSeen =
    spec.lastSeenMsAgo === null
      ? '0001-01-01T00:00:00Z'
      : new Date(Date.now() - (spec.lastSeenMsAgo ?? 10_000)).toISOString()
  return {
    id: spec.id,
    status: spec.status ?? 'active',
    last_seen: lastSeen,
    version: spec.version ?? 'v0.42',
    dna: {
      hostname: spec.hostname ?? spec.id,
      os: 'linux',
      architecture: 'amd64',
      attributes: spec.attributes ?? {},
    },
  }
}

/** Serve a fleet: each request slices [offset, offset+limit) of `stewards`. */
function mockFleet(stewards: Steward[]) {
  fetchMock.mockImplementation((input) => {
    const url = new URL(String(input), 'https://controller.test')
    const limit = Number(url.searchParams.get('limit'))
    const offset = Number(url.searchParams.get('offset'))
    const body = {
      data: {
        stewards: stewards.slice(offset, offset + limit),
        total: stewards.length,
        limit,
        offset,
      },
      timestamp: new Date().toISOString(),
    }
    return Promise.resolve(
      new Response(JSON.stringify(body), {
        status: 200,
        headers: { 'Content-Type': 'application/json' },
      }),
    )
  })
}

function renderFleet(search = '') {
  return render(
    <AuthProvider>
      <TenantScopeProvider rootPath="root">
        <FleetOverview search={search} onSearchChange={() => {}} />
      </TenantScopeProvider>
    </AuthProvider>,
  )
}

function dataRows(): HTMLElement[] {
  return within(screen.getByRole('table')).getAllByRole('row').slice(1)
}

function firstCellText(row: HTMLElement): string | null {
  return within(row).getAllByRole('cell')[0]?.textContent ?? null
}

describe('pagination', () => {
  const fleet = Array.from({ length: 120 }, (_, i) =>
    makeSteward({ id: `s${String(i + 1).padStart(3, '0')}` }),
  )

  it('requests limit/offset pages and renders the server total, never the full fleet', async () => {
    mockFleet(fleet)
    renderFleet()
    await screen.findByRole('table')

    const firstUrl = String(fetchMock.mock.calls[0]?.[0])
    expect(firstUrl).toContain('/api/v1/stewards?')
    expect(firstUrl).toContain('limit=50')
    expect(firstUrl).toContain('offset=0')

    expect(screen.getByTestId('fleet-count').textContent).toBe('120 stewards')
    expect(screen.getByTestId('fleet-pager').textContent).toContain(
      'Showing 1–50 of 120 stewards',
    )
    // Only the page is rendered, not the fleet.
    expect(dataRows()).toHaveLength(50)
  })

  it('next page requests the next server window', async () => {
    mockFleet(fleet)
    renderFleet()
    await screen.findByRole('table')

    fireEvent.click(screen.getByRole('button', { name: 'Next page' }))
    await waitFor(() =>
      expect(screen.getByTestId('fleet-pager').textContent).toContain(
        'Showing 51–100 of 120 stewards',
      ),
    )
    const lastUrl = String(fetchMock.mock.calls.at(-1)?.[0])
    expect(lastUrl).toContain('limit=50')
    expect(lastUrl).toContain('offset=50')
  })

  it('page-size change refetches from offset 0 with the new limit', async () => {
    mockFleet(fleet)
    renderFleet()
    await screen.findByRole('table')

    fireEvent.change(screen.getByLabelText('Stewards per page'), {
      target: { value: '25' },
    })
    await waitFor(() =>
      expect(screen.getByTestId('fleet-pager').textContent).toContain(
        'Showing 1–25 of 120 stewards',
      ),
    )
    const lastUrl = String(fetchMock.mock.calls.at(-1)?.[0])
    expect(lastUrl).toContain('limit=25')
    expect(lastUrl).toContain('offset=0')
  })
})

describe('live filter', () => {
  const fleet = [
    makeSteward({ id: 's1', hostname: 'web-ingest-04', attributes: { current_user: 'svc_deploy' } }),
    makeSteward({ id: 's2', hostname: 'dc-01', attributes: { current_user: 'administrator' } }),
    makeSteward({ id: 's3', hostname: 'kiosk-lobby', attributes: { current_user: 'kiosk' } }),
  ]

  it('narrows displayed rows as the search value changes and reports match count', async () => {
    mockFleet(fleet)
    const { rerender } = renderFleet()
    await screen.findByRole('table')
    expect(dataRows()).toHaveLength(3)

    rerender(
      <AuthProvider>
        <TenantScopeProvider rootPath="root">
          <FleetOverview search="web-ingest" onSearchChange={() => {}} />
        </TenantScopeProvider>
      </AuthProvider>,
    )
    expect(dataRows()).toHaveLength(1)
    expect(screen.getByText('web-ingest-04')).toBeInTheDocument()
    expect(screen.getByTestId('fleet-count').textContent).toBe('1 of 3 match')
  })

  it('matches values from hidden columns too (mockup behavior)', async () => {
    mockFleet(fleet)
    const { rerender } = renderFleet()
    await screen.findByRole('table')
    // Agent version is not a default column but is part of the haystack.
    rerender(
      <AuthProvider>
        <TenantScopeProvider rootPath="root">
          <FleetOverview search="v0.42" onSearchChange={() => {}} />
        </TenantScopeProvider>
      </AuthProvider>,
    )
    expect(dataRows()).toHaveLength(3)
  })

  it('shows the filter no-match empty state, distinct from no-stewards', async () => {
    mockFleet(fleet)
    renderFleet('no-such-host')
    await screen.findByText('No stewards match your filter')
    expect(screen.queryByText('No stewards enrolled yet')).not.toBeInTheDocument()
  })
})

describe('sort', () => {
  const fleet = [
    makeSteward({ id: 's1', hostname: 'charlie' }),
    makeSteward({ id: 's2', hostname: 'alpha' }),
    makeSteward({ id: 's3', hostname: 'bravo' }),
  ]

  it('orders displayed rows by the clicked header and flips on re-click', async () => {
    mockFleet(fleet)
    renderFleet()
    await screen.findByRole('table')

    const nameHeader = screen.getByRole('columnheader', { name: /name/i })
    fireEvent.click(nameHeader)
    let names = dataRows().map(firstCellText)
    expect(names).toEqual(['alpha', 'bravo', 'charlie'])
    expect(nameHeader).toHaveAttribute('aria-sort', 'ascending')

    fireEvent.click(nameHeader)
    names = dataRows().map(firstCellText)
    expect(names).toEqual(['charlie', 'bravo', 'alpha'])
    expect(nameHeader).toHaveAttribute('aria-sort', 'descending')
  })

  it('sorts Last check-in chronologically, not lexically', async () => {
    mockFleet([
      makeSteward({ id: 's1', hostname: 'old', lastSeenMsAgo: 2 * 3_600_000 }),
      makeSteward({ id: 's2', hostname: 'newest', lastSeenMsAgo: 5_000 }),
      makeSteward({ id: 's3', hostname: 'never', lastSeenMsAgo: null, status: 'registered' }),
    ])
    renderFleet()
    await screen.findByRole('table')
    fireEvent.click(screen.getByRole('columnheader', { name: /last check-in/i }))
    const names = dataRows().map(firstCellText)
    // Ascending: never-seen first, then oldest, then newest.
    expect(names).toEqual(['never', 'old', 'newest'])
  })
})

describe('columns', () => {
  const fleet = [
    makeSteward({
      id: 's1',
      hostname: 'host-a',
      attributes: {
        deployment_ring: 'canary',
        system_serial_number: 'SER-77',
        primary_mac: 'aa:bb:cc:dd:ee:ff',
      },
    }),
  ]

  it('shows the default column set with opt-ins hidden', async () => {
    mockFleet(fleet)
    renderFleet()
    await screen.findByRole('table')
    for (const label of ['Name', 'Company', 'Last user', 'IP', 'Health', 'Last check-in']) {
      expect(screen.getByRole('columnheader', { name: label })).toBeInTheDocument()
    }
    expect(screen.queryByRole('columnheader', { name: /ring/i })).not.toBeInTheDocument()
    expect(screen.queryByRole('columnheader', { name: /serial/i })).not.toBeInTheDocument()
  })

  it('adds and removes columns via the picker; Name is locked on', async () => {
    mockFleet(fleet)
    renderFleet()
    await screen.findByRole('table')

    fireEvent.click(screen.getByRole('button', { name: /columns/i }))
    fireEvent.click(screen.getByRole('checkbox', { name: 'Ring' }))
    expect(screen.getByRole('columnheader', { name: /ring/i })).toBeInTheDocument()
    expect(screen.getByText('canary')).toBeInTheDocument()

    fireEvent.click(screen.getByRole('checkbox', { name: 'Company' }))
    expect(screen.queryByRole('columnheader', { name: /company/i })).not.toBeInTheDocument()

    expect(screen.getByRole('checkbox', { name: 'Name' })).toBeDisabled()
  })

  it('persists the selection across a reload under the allowlisted key', async () => {
    mockFleet(fleet)
    renderFleet()
    await screen.findByRole('table')
    fireEvent.click(screen.getByRole('button', { name: /columns/i }))
    fireEvent.click(screen.getByRole('checkbox', { name: 'Ring' }))

    const stored = localStorage.getItem('cfgms.fleet.columns')
    expect(stored).not.toBeNull()
    expect(JSON.parse(stored as string)).toContain('ring')

    cleanup()
    mockFleet(fleet)
    renderFleet()
    await screen.findByRole('table')
    expect(screen.getByRole('columnheader', { name: /ring/i })).toBeInTheDocument()
  })

  it('ignores a corrupted stored selection (untrusted input) and falls back to defaults', async () => {
    localStorage.setItem('cfgms.fleet.columns', '{"not":"an-array"')
    mockFleet(fleet)
    renderFleet()
    await screen.findByRole('table')
    expect(screen.getByRole('columnheader', { name: /company/i })).toBeInTheDocument()
    expect(screen.queryByRole('columnheader', { name: /ring/i })).not.toBeInTheDocument()
  })

  it('renders an em-dash placeholder for missing DNA attributes', async () => {
    mockFleet([makeSteward({ id: 's-bare', attributes: {} })])
    renderFleet()
    await screen.findByRole('table')
    const [row] = dataRows()
    if (row === undefined) throw new Error('expected a data row')
    // Company, Last user, and IP are unset on this steward.
    expect(within(row).getAllByText('—').length).toBeGreaterThanOrEqual(3)
  })
})

describe('health column', () => {
  it('maps Status + LastSeen staleness onto semantic pills', async () => {
    mockFleet([
      makeSteward({ id: 's1', hostname: 'fresh', status: 'active', lastSeenMsAgo: 10_000 }),
      makeSteward({ id: 's2', hostname: 'stale', status: 'active', lastSeenMsAgo: STALE_AFTER_MS + 60_000 }),
      makeSteward({ id: 's3', hostname: 'degraded', status: 'degraded' }),
      makeSteward({ id: 's4', hostname: 'enrolled', status: 'registered', lastSeenMsAgo: null }),
    ])
    renderFleet()
    await screen.findByRole('table')

    expect(screen.getByText('Healthy')).toBeInTheDocument()
    expect(screen.getByText('Unreachable')).toBeInTheDocument()
    expect(screen.getByText('Degraded')).toBeInTheDocument()
    expect(screen.getByText('Registered')).toBeInTheDocument()

    expect(screen.getByText('Healthy').className).toContain('ok')
    expect(screen.getByText('Unreachable').className).toContain('crit')
    expect(screen.getByText('Degraded').className).toContain('warn')
    expect(screen.getByText('Registered').className).toContain('neutral')
  })
})

describe('data states', () => {
  it('shows skeleton rows while the page is loading', () => {
    fetchMock.mockImplementation(() => new Promise<Response>(() => {}))
    renderFleet()
    expect(screen.getByTestId('fleet-loading')).toBeInTheDocument()
    expect(screen.queryByRole('table')).not.toBeInTheDocument()
  })

  it('surfaces a failed request as the error state with a retry affordance', async () => {
    fetchMock.mockResolvedValue(
      new Response('{}', { status: 503, headers: { 'Content-Type': 'application/json' } }),
    )
    renderFleet()
    await screen.findByRole('alert')
    expect(screen.getByText(/couldn't reach the controller/i)).toBeInTheDocument()
    expect(screen.getByText('GET /api/v1/stewards — 503')).toBeInTheDocument()

    mockFleet([makeSteward({ id: 's1', hostname: 'back-online' })])
    fireEvent.click(screen.getByRole('button', { name: /retry/i }))
    await screen.findByRole('table')
    expect(screen.getByText('back-online')).toBeInTheDocument()
  })

  it('treats an unexpected response shape as an error, never renders garbage', async () => {
    fetchMock.mockResolvedValue(
      new Response(JSON.stringify({ data: { wrong: true } }), {
        status: 200,
        headers: { 'Content-Type': 'application/json' },
      }),
    )
    renderFleet()
    await screen.findByRole('alert')
    expect(screen.getByText('unexpected response shape')).toBeInTheDocument()
  })

  it('shows the enrolled-empty state for a zero-steward fleet', async () => {
    mockFleet([])
    renderFleet()
    await screen.findByText('No stewards enrolled yet')
    expect(screen.queryByRole('table')).not.toBeInTheDocument()
  })
})

describe('tenant scope', () => {
  function ScopeHarness() {
    const { setScope, observedPaths } = useTenantScope()
    return (
      <div>
        <button type="button" onClick={() => setScope('root/msp-a')}>
          narrow-scope
        </button>
        <span data-testid="observed">{observedPaths.join(',')}</span>
        <FleetOverview search="" onSearchChange={() => {}} />
      </div>
    )
  }

  const fleet = [
    makeSteward({ id: 's1', hostname: 'in-scope', attributes: { tenant: 'root/msp-a' } }),
    makeSteward({ id: 's2', hostname: 'descendant', attributes: { tenant: 'root/msp-a/client-1' } }),
    makeSteward({ id: 's3', hostname: 'other-tenant', attributes: { tenant: 'root/msp-b' } }),
    makeSteward({ id: 's4', hostname: 'no-tenant-data' }),
  ]

  it('registers observed tenant paths and narrows displayed rows to the scope', async () => {
    mockFleet(fleet)
    render(
      <AuthProvider>
        <TenantScopeProvider rootPath="root">
          <ScopeHarness />
        </TenantScopeProvider>
      </AuthProvider>,
    )
    await screen.findByRole('table')

    // Paths observed in the page data are offered to the switcher.
    expect(screen.getByTestId('observed').textContent).toContain('root/msp-a')
    expect(screen.getByTestId('observed').textContent).toContain('root/msp-b')

    fireEvent.click(screen.getByRole('button', { name: 'narrow-scope' }))
    const names = dataRows().map(firstCellText)
    expect(names).toEqual(['in-scope', 'descendant'])
    expect(screen.getByTestId('fleet-count').textContent).toBe('2 of 4 match')
  })

  it('shows the scope no-match state when the scope holds no rows on this page', async () => {
    mockFleet([makeSteward({ id: 's3', hostname: 'other-tenant', attributes: { tenant: 'root/msp-b' } })])
    function NarrowToEmpty() {
      const { setScope } = useTenantScope()
      return (
        <div>
          <button type="button" onClick={() => setScope('root/msp-a')}>
            narrow-scope
          </button>
          <FleetOverview search="" onSearchChange={() => {}} />
        </div>
      )
    }
    render(
      <AuthProvider>
        <TenantScopeProvider rootPath="root">
          <NarrowToEmpty />
        </TenantScopeProvider>
      </AuthProvider>,
    )
    await screen.findByRole('table')
    fireEvent.click(screen.getByRole('button', { name: 'narrow-scope' }))
    expect(screen.getByText('No stewards in this scope')).toBeInTheDocument()
    expect(screen.queryByText(/match your filter/i)).not.toBeInTheDocument()
  })
})

describe('hostile steward values (security A9.1)', () => {
  it('renders a hostile hostname as inert text, never as markup', async () => {
    const hostile = '<img src=x onerror="document.title=\'pwned\'">'
    mockFleet([
      makeSteward({
        id: 's-evil',
        hostname: hostile,
        attributes: {
          current_user: '<script>document.title="pwned"</script>',
          primary_ip: '"><svg onload=alert(1)>',
        },
      }),
    ])
    renderFleet()
    await screen.findByRole('table')

    // The literal strings are visible as text…
    expect(screen.getByText(hostile)).toBeInTheDocument()
    // …and no element was ever created from them.
    expect(document.querySelector('img')).toBeNull()
    expect(document.querySelector('script')).toBeNull()
    expect(document.title).not.toBe('pwned')
  })
})
