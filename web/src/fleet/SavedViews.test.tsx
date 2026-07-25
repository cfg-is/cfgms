// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz

/*
 * Saved views suite (Story #2498): save/apply/rename/delete round-trip with
 * localStorage persistence, exact view-state restoration (filter, sort,
 * column set, page size — NOT tenant scope), per-principal keying, and
 * validation of configs read back from localStorage as untrusted input
 * (security A10.2).
 */
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'
import { useEffect, useState } from 'react'
import {
  cleanup,
  fireEvent,
  render,
  screen,
  waitFor,
} from '@testing-library/react'
import { MemoryRouter, Outlet, Route, Routes } from 'react-router'
import { AuthProvider, useAuth } from '../auth/AuthContext.tsx'
import {
  TenantScopeProvider,
  useTenantScope,
} from '../shell/TenantScopeContext.tsx'
import FleetOverview from './FleetOverview.tsx'
import {
  DEFAULT_PAGE_SIZE,
  MAX_SAVED_VIEWS,
  loadViews,
  saveViews,
  type SavedView,
  type ViewConfig,
} from './SavedViews.tsx'
import type { Steward } from './columns.ts'

const STORAGE_KEY = 'cfgms.fleet.views'

const fetchMock = vi.fn<typeof fetch>()

beforeEach(() => {
  fetchMock.mockReset()
  vi.stubGlobal('fetch', fetchMock)
  localStorage.clear()
})

afterEach(() => {
  cleanup()
  vi.unstubAllGlobals()
})

function makeSteward(id: string, hostname: string): Steward {
  return {
    id,
    status: 'active',
    last_seen: new Date().toISOString(),
    version: 'v0.42',
    dna: {
      hostname,
      os: 'linux',
      architecture: 'amd64',
      // In-scope tenant so narrowing the scope in the harness never empties
      // the table (the restoration test asserts against column headers).
      attributes: { tenant: 'root/msp-a' },
    },
  }
}

const FLEET = [
  makeSteward('s1', 'acme-web-01'),
  makeSteward('s2', 'globex-db-01'),
]

/** Serve login endpoints plus a steward page for the FleetOverview harness. */
function mockBackend() {
  fetchMock.mockImplementation((input, init) => {
    const url = new URL(String(input), 'https://controller.test')
    if (url.pathname === '/api/v1/web/csrf') {
      return Promise.resolve(new Response('{}', { status: 200 }))
    }
    if (url.pathname === '/api/v1/web/login') {
      return Promise.resolve(new Response('{}', { status: 200 }))
    }
    if (url.pathname.endsWith('/dna')) {
      const body = {
        data: {
          hostname: 'acme-web-01',
          os: 'linux',
          architecture: 'amd64',
          attributes: {},
        },
      }
      return Promise.resolve(new Response(JSON.stringify(body), { status: 200 }))
    }
    if (url.pathname === '/api/v1/stewards') {
      const limit = Number(url.searchParams.get('limit'))
      const offset = Number(url.searchParams.get('offset'))
      const body = {
        data: {
          stewards: FLEET.slice(offset, offset + limit),
          total: FLEET.length,
          limit,
          offset,
        },
      }
      return Promise.resolve(new Response(JSON.stringify(body), { status: 200 }))
    }
    void init
    return Promise.resolve(new Response('{}', { status: 404 }))
  })
}

/*
 * Harness playing AppShell's role: owns the search state (the shell's global
 * search box) and exposes the tenant scope so tests can prove it is neither
 * captured nor restored by views. Signs in through the real AuthProvider so
 * views key off the actual principal.
 */
function Harness({ user }: { user: string }) {
  const { status, login } = useAuth()
  useEffect(() => {
    if (status === 'signedOut') void login(user, 'pw')
  }, [status, login, user])
  if (status !== 'signedIn') return null
  return (
    <TenantScopeProvider rootPath="root">
      <HarnessBody />
    </TenantScopeProvider>
  )
}

function HarnessBody() {
  const [search, setSearch] = useState('')
  const { scope, setScope } = useTenantScope()
  return (
    <>
      <input
        aria-label="Global filter"
        value={search}
        onChange={(event) => setSearch(event.target.value)}
      />
      <span data-testid="scope-probe">{scope}</span>
      <button type="button" onClick={() => setScope('root/msp-a')}>
        narrow scope
      </button>
      <Routes>
        <Route element={<Outlet context={{ search, onSearchChange: setSearch }} />}>
          <Route index element={<FleetOverview />} />
          <Route path="/stewards/:id" element={<div data-testid="nav-asset-page">asset</div>} />
        </Route>
      </Routes>
    </>
  )
}

function renderHarness(user = 'alice') {
  mockBackend()
  return render(
    <MemoryRouter initialEntries={['/']}>
      <AuthProvider>
        <Harness user={user} />
      </AuthProvider>
    </MemoryRouter>,
  )
}

async function openViewsMenu() {
  // Idempotent: saving leaves the panel open; a second toggle would close it.
  if (screen.queryByRole('group', { name: 'Saved views' }) === null) {
    fireEvent.click(await screen.findByRole('button', { name: /^View:/ }))
  }
}

async function saveCurrentViewAs(name: string) {
  await openViewsMenu()
  fireEvent.click(screen.getByText('Save current view…'))
  fireEvent.change(screen.getByLabelText('View name'), {
    target: { value: name },
  })
  fireEvent.click(screen.getByRole('button', { name: 'Save' }))
}

const validConfig: ViewConfig = {
  filter: 'acme',
  sort: { key: 'name', direction: -1 },
  columns: ['name', 'os', 'health'],
  pageSize: 100,
}

describe('localStorage round-trip and per-principal keying (pure functions)', () => {
  it('save/load round-trips a view for its principal only', () => {
    const view: SavedView = { name: 'Servers', config: validConfig }
    saveViews('alice', [view])
    expect(loadViews('alice')).toEqual([view])
    expect(loadViews('bob')).toEqual([])
  })

  it('saving for one principal preserves the other principals in the record', () => {
    saveViews('alice', [{ name: 'A', config: validConfig }])
    saveViews('bob', [{ name: 'B', config: validConfig }])
    expect(loadViews('alice').map((v) => v.name)).toEqual(['A'])
    expect(loadViews('bob').map((v) => v.name)).toEqual(['B'])
  })

  it('caps the number of stored views per principal', () => {
    const views = Array.from({ length: MAX_SAVED_VIEWS + 10 }, (_, i) => ({
      name: `v${i}`,
      config: validConfig,
    }))
    saveViews('alice', views)
    expect(loadViews('alice').length).toBe(MAX_SAVED_VIEWS)
  })
})

describe('untrusted localStorage validation (security A10.2)', () => {
  function seed(raw: string) {
    localStorage.setItem(STORAGE_KEY, raw)
  }

  it('falls back to empty on malformed JSON or a non-record top level', () => {
    seed('{not json')
    expect(loadViews('alice')).toEqual([])
    seed('[1,2,3]')
    expect(loadViews('alice')).toEqual([])
    seed('"string"')
    expect(loadViews('alice')).toEqual([])
  })

  it('drops views that fail shape or type validation, keeping valid siblings', () => {
    const good = { name: 'Good', config: validConfig }
    const cases: unknown[] = [
      'not an object',
      { name: 42, config: validConfig },
      { name: '', config: validConfig },
      { name: 'x'.repeat(200), config: validConfig },
      { name: 'NoConfig' },
      { name: 'BadFilter', config: { ...validConfig, filter: 7 } },
      { name: 'BadSortKey', config: { ...validConfig, sort: { key: 'evil', direction: 1 } } },
      { name: 'BadSortDir', config: { ...validConfig, sort: { key: 'name', direction: 0 } } },
      { name: 'BadColumns', config: { ...validConfig, columns: ['name', 'not-a-column'] } },
      { name: 'ColumnsNotArray', config: { ...validConfig, columns: 'name' } },
      { name: 'BadPageSize', config: { ...validConfig, pageSize: 9999 } },
      good,
    ]
    seed(JSON.stringify({ alice: cases }))
    expect(loadViews('alice')).toEqual([good])
  })

  it('a principal entry that is not an array yields no views', () => {
    seed(JSON.stringify({ alice: { sneaky: true } }))
    expect(loadViews('alice')).toEqual([])
  })
})

describe('saved views in the fleet overview', () => {
  it('saves the current configuration, applies it exactly, and does not capture tenant scope', async () => {
    renderHarness()
    await screen.findByRole('table')

    // Build a non-default view state: filter, sort desc, extra column, page size.
    fireEvent.change(screen.getByLabelText('Global filter'), {
      target: { value: 'acme' },
    })
    // Search change triggers a new server fetch; wait for the table to return.
    await screen.findByRole('table')
    const nameHeader = () => screen.getByRole('columnheader', { name: /^Name/ })
    fireEvent.click(nameHeader())
    fireEvent.click(nameHeader()) // descending
    fireEvent.click(screen.getByRole('button', { name: 'Columns' }))
    fireEvent.click(screen.getByLabelText('OS / platform'))
    fireEvent.keyDown(document, { key: 'Escape' })
    fireEvent.change(screen.getByLabelText('Stewards per page'), {
      target: { value: '100' },
    })
    // Narrow the tenant scope — this must NOT be captured by the view.
    fireEvent.click(screen.getByRole('button', { name: 'narrow scope' }))

    await saveCurrentViewAs('My view')

    // The stored config captures exactly the four view fields — no scope.
    const stored = JSON.parse(localStorage.getItem(STORAGE_KEY) ?? '{}') as Record<
      string,
      { name: string; config: Record<string, unknown> }[]
    >
    const aliceViews = stored.alice ?? []
    expect(aliceViews.map((v) => v.name)).toEqual(['My view'])
    expect(Object.keys(aliceViews[0]?.config ?? {}).sort()).toEqual([
      'columns',
      'filter',
      'pageSize',
      'sort',
    ])

    // Reset everything via the built-in default view. The page-size change
    // refetches, so wait for the pager to return.
    await openViewsMenu()
    fireEvent.click(screen.getByRole('button', { name: 'All stewards' }))
    expect((screen.getByLabelText('Global filter') as HTMLInputElement).value).toBe('')
    expect(
      ((await screen.findByLabelText('Stewards per page')) as HTMLSelectElement)
        .value,
    ).toBe(String(DEFAULT_PAGE_SIZE))
    expect(screen.queryByRole('columnheader', { name: /^OS/ })).toBeNull()

    // Apply the saved view: all four fields restore exactly.
    await openViewsMenu()
    fireEvent.click(screen.getByRole('button', { name: 'My view' }))
    expect((screen.getByLabelText('Global filter') as HTMLInputElement).value).toBe(
      'acme',
    )
    expect(
      ((await screen.findByLabelText('Stewards per page')) as HTMLSelectElement)
        .value,
    ).toBe('100')
    expect(screen.getByRole('columnheader', { name: /^OS/ })).toBeTruthy()
    await waitFor(() =>
      expect(
        screen
          .getByRole('columnheader', { name: /^Name/ })
          .getAttribute('aria-sort'),
      ).toBe('descending'),
    )
    // Tenant scope was untouched by the apply.
    expect(screen.getByTestId('scope-probe').textContent).toBe('root/msp-a')
  })

  it('views survive reload (fresh mount reads them back from localStorage)', async () => {
    const first = renderHarness()
    await screen.findByRole('table')
    await saveCurrentViewAs('Persisted')
    first.unmount()

    renderHarness()
    await screen.findByRole('table')
    await openViewsMenu()
    expect(screen.getByRole('button', { name: 'Persisted' })).toBeTruthy()
  })

  it('is keyed per principal — another user does not see the views', async () => {
    const first = renderHarness('alice')
    await screen.findByRole('table')
    await saveCurrentViewAs('Alice only')
    first.unmount()

    renderHarness('bob')
    await screen.findByRole('table')
    await openViewsMenu()
    expect(screen.queryByRole('button', { name: 'Alice only' })).toBeNull()
  })

  it('renames a view and the rename persists', async () => {
    renderHarness()
    await screen.findByRole('table')
    await saveCurrentViewAs('Old name')

    await openViewsMenu()
    fireEvent.click(screen.getByRole('button', { name: 'Rename Old name' }))
    fireEvent.change(screen.getByLabelText('View name'), {
      target: { value: 'New name' },
    })
    fireEvent.click(screen.getByRole('button', { name: 'Save' }))

    expect(loadViews('alice').map((v) => v.name)).toEqual(['New name'])
    await openViewsMenu()
    expect(screen.getByRole('button', { name: 'New name' })).toBeTruthy()
    expect(screen.queryByRole('button', { name: 'Old name' })).toBeNull()
  })

  it('deletes a view and the deletion persists', async () => {
    renderHarness()
    await screen.findByRole('table')
    await saveCurrentViewAs('Doomed')

    await openViewsMenu()
    fireEvent.click(screen.getByRole('button', { name: 'Delete Doomed' }))
    expect(loadViews('alice')).toEqual([])
    expect(screen.queryByRole('button', { name: 'Doomed' })).toBeNull()
  })

  it('the views menu closes on Escape (shell overlay conventions)', async () => {
    renderHarness()
    await screen.findByRole('table')
    await openViewsMenu()
    expect(screen.getByText('Save current view…')).toBeTruthy()
    fireEvent.keyDown(document, { key: 'Escape' })
    await waitFor(() =>
      expect(screen.queryByText('Save current view…')).toBeNull(),
    )
  })
})

describe('row drill-in wiring', () => {
  it('clicking a fleet row opens the overlay drawer (Story #2917)', async () => {
    renderHarness()
    await screen.findByRole('table')
    // The name cell now renders as an anchor; clicking it opens the drawer.
    const anchor = screen.getByRole('link', { name: 'acme-web-01' })
    fireEvent.click(anchor)
    expect(await screen.findByTestId('steward-drawer')).toBeInTheDocument()
    // The fleet table stays visible — the drawer overlays it.
    expect(screen.getByRole('table')).toBeInTheDocument()
  })
})
