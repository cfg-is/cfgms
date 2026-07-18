// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz

/*
 * Fleet overview (Story #2497) — the first real occupant of the app shell's
 * content area. Renders one server page of stewards (pagination + total are
 * the server's, per the #2489 contract) with client-side live filter, column
 * sort, and a selectable device-DNA column set — fixed epic semantics: the
 * filter and sort operate on the displayed page's rows, not the whole fleet.
 *
 * The live-filter input is the shell's global search box (#2496 chrome);
 * its value and setter arrive via useOutletContext from AppShell (Story
 * #2723). Tenant scope (#2496 context) is a display convenience narrowing
 * displayed rows — server-side tenant scoping on the API is the only
 * enforcement (security A8.1); it is session chrome, never captured by a
 * saved view.
 *
 * Story #2498 adds saved views (SavedViews.tsx) and the row drill-in
 * asset-DNA drawer (DnaDrawer.tsx). Story #2723 converts the row drill-in
 * from component state to a real route: clicking a row navigates to
 * /stewards/:id (StewardAssetPage).
 */
import { useEffect, useMemo, useState } from 'react'
import { useNavigate, useOutletContext } from 'react-router-dom'
import { isScopeMatch, useTenantScope } from '../shell/TenantScopeContext.tsx'
import {
  COLUMNS,
  DEFAULT_VISIBLE,
  loadColumnPrefs,
  saveColumnPrefs,
  type ColumnKey,
  type Steward,
} from './columns.ts'
import { deriveHealth, fetchFleetHealth, parseLastSeen, type FleetHealth } from './health.ts'
import ColumnPicker from './ColumnPicker.tsx'
import FleetTable, { type SortState } from './FleetTable.tsx'
import { ErrorNotice, FleetEmpty, LoadingRows, NoMatch } from './FleetStates.tsx'
import SavedViews, {
  DEFAULT_PAGE_SIZE,
  PAGE_SIZES,
  type ViewConfig,
} from './SavedViews.tsx'
import { useStewards } from './useStewards.ts'
import './FleetOverview.css'

const formatCount = new Intl.NumberFormat('en-US')

/** Page-number strip: current ±1, first, last, with ellipsis gaps. */
export function buildPageList(current: number, pages: number): (number | '…')[] {
  const wanted = new Set<number>([1, current - 1, current, current + 1, pages])
  const ordered = [...wanted]
    .filter((n) => n >= 1 && n <= pages)
    .sort((a, b) => a - b)
  const result: (number | '…')[] = []
  let previous = 0
  for (const n of ordered) {
    if (previous !== 0 && n - previous > 1) result.push('…')
    result.push(n)
    previous = n
  }
  return result
}

function sortValue(key: ColumnKey, steward: Steward, nowMs: number): string | number {
  if (key === 'seen') return parseLastSeen(steward.last_seen) ?? Number.NEGATIVE_INFINITY
  if (key === 'health') return deriveHealth(steward.status, steward.last_seen, nowMs).label
  const column = COLUMNS.find((c) => c.key === key)
  return column ? column.value(steward).toLowerCase() : ''
}


export default function FleetOverview() {
  const { search, onSearchChange } = useOutletContext<{
    search: string
    onSearchChange: (value: string) => void
  }>()
  const navigate = useNavigate()
  const { scope, rootPath } = useTenantScope()
  const [pageSize, setPageSize] = useState<number>(DEFAULT_PAGE_SIZE)
  const [pageIndex, setPageIndex] = useState(0)
  const [sort, setSort] = useState<SortState | null>(null)
  const [visible, setVisible] = useState<ReadonlySet<ColumnKey>>(
    () => new Set(loadColumnPrefs() ?? DEFAULT_VISIBLE),
  )

  const [fleetHealth, setFleetHealth] = useState<FleetHealth | null>(null)

  useEffect(() => {
    let cancelled = false
    fetchFleetHealth()
      .then((h) => { if (!cancelled) setFleetHealth(h) })
      .catch(() => { /* tiles are best-effort; errors are non-blocking */ })
    return () => { cancelled = true }
  }, [])

  // Reset to page 0 whenever the selector changes so stale pages are not shown.
  // Adjusted during render rather than in an effect: this way the first render
  // after a selector change already requests offset 0, instead of fetching a
  // stale page and refetching once the effect lands.
  const [prevSearch, setPrevSearch] = useState(search)
  if (search !== prevSearch) {
    setPrevSearch(search)
    setPageIndex(0)
  }

  const { page, loading, error, fetchedAtMs, retry } = useStewards(
    pageSize,
    pageIndex * pageSize,
    search,
  )

  // Relative times and staleness anchor at fetch time — the moment the data
  // was true — so the render itself stays pure.
  const nowMs = fetchedAtMs
  const scoped = scope !== rootPath

  const displayRows = useMemo(() => {
    if (page === null) return []
    let rows = page.stewards
    // Tenant scope is a client-side display filter (security is server-enforced).
    // Text search is handled server-side via the selector param — no client filtering.
    if (scoped) {
      rows = rows.filter((steward) => {
        const tenantPath = steward.dna?.attributes?.['tenant']
        return tenantPath !== undefined && isScopeMatch(tenantPath, scope)
      })
    }
    if (sort !== null) {
      const key = sort.key as ColumnKey
      rows = [...rows].sort((a, b) => {
        const av = sortValue(key, a, nowMs)
        const bv = sortValue(key, b, nowMs)
        if (typeof av === 'number' && typeof bv === 'number') {
          return (av - bv) * sort.direction
        }
        return String(av).localeCompare(String(bv)) * sort.direction
      })
    }
    return rows
  }, [page, scoped, scope, sort, nowMs])

  function onSort(key: string) {
    setSort((was) =>
      was?.key === key
        ? { key, direction: was.direction === 1 ? -1 : 1 }
        : { key, direction: 1 },
    )
  }

  function onToggleColumn(key: ColumnKey) {
    setVisible((was) => {
      const next = new Set(was)
      if (next.has(key)) next.delete(key)
      else next.add(key)
      next.add('name')
      saveColumnPrefs([...next])
      return next
    })
  }

  function onPageSize(next: number) {
    setPageSize(next)
    setPageIndex(0)
  }

  /* The saved-view contract: exactly filter text, sort, visible column set,
   * and page size — tenant scope is deliberately absent. */
  const currentConfig = useMemo<ViewConfig>(
    () => ({
      filter: search,
      sort:
        sort === null
          ? null
          : { key: sort.key as ColumnKey, direction: sort.direction },
      columns: COLUMNS.filter((c) => visible.has(c.key)).map((c) => c.key),
      pageSize,
    }),
    [search, sort, visible, pageSize],
  )

  function applyView(config: ViewConfig) {
    onSearchChange(config.filter)
    setSort(config.sort)
    setVisible(new Set(config.columns))
    setPageSize(config.pageSize)
    setPageIndex(0)
  }

  const columns = COLUMNS.filter((column) => visible.has(column.key))
  const total = page?.total ?? 0
  const pages = Math.max(1, Math.ceil(total / pageSize))
  const current = pageIndex + 1
  // narrowed: only tenant scope creates a "X of total" count display.
  // Search is server-side — total already reflects the selector filter.
  const narrowed = scoped
  const pageRowCount = page?.stewards.length ?? 0
  const from = total === 0 ? 0 : pageIndex * pageSize + 1
  const to = pageIndex * pageSize + pageRowCount

  const countText = narrowed
    ? `${formatCount.format(displayRows.length)} of ${formatCount.format(total)} match`
    : `${formatCount.format(total)} stewards`

  return (
    <>
      <div className="htitle">
        <h1>Fleet</h1>
        <p>Stewards enrolled to this controller, with the device DNA you choose.</p>
      </div>

      {fleetHealth !== null && (
        <div className="health-tiles" data-testid="fleet-health-tiles">
          <div className="ht ok" data-testid="health-tile-healthy">
            <span className="ht-count">{formatCount.format(fleetHealth.healthy)}</span>
            <span className="ht-label">Healthy</span>
          </div>
          <div className="ht warn" data-testid="health-tile-degraded">
            <span className="ht-count">{formatCount.format(fleetHealth.degraded)}</span>
            <span className="ht-label">Degraded</span>
          </div>
          <div className="ht crit" data-testid="health-tile-unreachable">
            <span className="ht-count">{formatCount.format(fleetHealth.unreachable)}</span>
            <span className="ht-label">Unreachable</span>
          </div>
        </div>
      )}

      <section className="panel">
        <div className="ptool">
          <SavedViews current={currentConfig} onApply={applyView} />
          <ColumnPicker visible={visible} onToggle={onToggleColumn} />
          <span className="cnt" data-testid="fleet-count">
            {page === null ? '' : countText}
          </span>
        </div>

        {loading ? (
          <LoadingRows />
        ) : error !== null ? (
          <ErrorNotice detail={error} onRetry={retry} />
        ) : page === null || (total === 0 && search.trim() === '') ? (
          <FleetEmpty />
        ) : total === 0 ? (
          <NoMatch scopeOnly={false} />
        ) : displayRows.length === 0 ? (
          <NoMatch scopeOnly={true} />
        ) : (
          <FleetTable
            stewards={displayRows}
            columns={columns}
            sort={sort}
            onSort={onSort}
            nowMs={nowMs}
            onRowSelect={(steward) =>
              navigate(`/stewards/${encodeURIComponent(steward.id)}`)
            }
          />
        )}

        {page !== null && error === null && total > 0 && (
          <div className="pager" data-testid="fleet-pager">
            <span>
              Showing <b>{formatCount.format(from)}</b>–<b>{formatCount.format(to)}</b> of{' '}
              <b>{formatCount.format(total)}</b> stewards
            </span>
            <label className="sz">
              <select
                aria-label="Stewards per page"
                value={pageSize}
                onChange={(event) => onPageSize(Number(event.target.value))}
              >
                {PAGE_SIZES.map((size) => (
                  <option key={size} value={size}>
                    {size} / page
                  </option>
                ))}
              </select>
            </label>
            <div className="pg">
              <button
                type="button"
                aria-label="Previous page"
                disabled={current <= 1}
                onClick={() => setPageIndex((i) => Math.max(0, i - 1))}
              >
                ‹
              </button>
              {buildPageList(current, pages).map((entry, index) =>
                entry === '…' ? (
                  <button type="button" key={`gap-${index}`} disabled>
                    …
                  </button>
                ) : (
                  <button
                    type="button"
                    key={entry}
                    className={entry === current ? 'on' : ''}
                    aria-current={entry === current ? 'page' : undefined}
                    onClick={() => setPageIndex(entry - 1)}
                  >
                    {formatCount.format(entry)}
                  </button>
                ),
              )}
              <button
                type="button"
                aria-label="Next page"
                disabled={current >= pages}
                onClick={() => setPageIndex((i) => Math.min(pages - 1, i + 1))}
              >
                ›
              </button>
            </div>
          </div>
        )}
      </section>
    </>
  )
}
