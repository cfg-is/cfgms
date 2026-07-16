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
 * its value arrives via the `search` prop and changes propagate up via the
 * `onSearchChange` callback (used when applying a saved view).  Tenant scope
 * (#2496 context) is a display convenience narrowing displayed rows —
 * server-side tenant scoping on the API is the only enforcement (A8.1).
 *
 * Story #2498 additions:
 *   - SavedViews panel: save/apply/delete named view configs in localStorage,
 *     keyed per principal (username prop).
 *   - DnaDrawer: row-click opens the asset-DNA detail panel fetched from
 *     GET /api/v1/stewards/{id}/dna.
 */
import { useCallback, useMemo, useState } from 'react'
import { isScopeMatch, useTenantScope } from '../shell/TenantScopeContext.tsx'
import {
  COLUMNS,
  DEFAULT_VISIBLE,
  loadColumnPrefs,
  saveColumnPrefs,
  type ColumnKey,
  type Steward,
} from './columns.ts'
import { deriveHealth, formatLastSeen, parseLastSeen } from './health.ts'
import ColumnPicker from './ColumnPicker.tsx'
import FleetTable, { type SortState } from './FleetTable.tsx'
import { ErrorNotice, FleetEmpty, LoadingRows, NoMatch } from './FleetStates.tsx'
import { useStewards } from './useStewards.ts'
import SavedViews, { type SavedViewConfig } from './SavedViews.tsx'
import DnaDrawer from './DnaDrawer.tsx'
import './FleetOverview.css'

const PAGE_SIZES = [25, 50, 100, 250] as const
const DEFAULT_PAGE_SIZE = 50

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

/* Filter haystack spans every mapped DNA value plus the derived health and
 * check-in text, whether or not the column is currently shown (mockup
 * behavior: hiding a column doesn't stop it matching). */
function matchesFilter(steward: Steward, needle: string, nowMs: number): boolean {
  const haystack = [
    ...COLUMNS.map((column) => column.value(steward)),
    deriveHealth(steward.status, steward.last_seen, nowMs).label,
    formatLastSeen(steward.last_seen, nowMs),
  ]
    .join(' ')
    .toLowerCase()
  return haystack.includes(needle)
}

export default function FleetOverview({
  search,
  onSearchChange,
  username = '',
}: {
  search: string
  onSearchChange?: (value: string) => void
  username?: string
}) {
  const { scope, rootPath } = useTenantScope()
  const [pageSize, setPageSize] = useState<number>(DEFAULT_PAGE_SIZE)
  const [pageIndex, setPageIndex] = useState(0)
  const [sort, setSort] = useState<SortState | null>(null)
  const [visible, setVisible] = useState<ReadonlySet<ColumnKey>>(
    () => new Set(loadColumnPrefs() ?? DEFAULT_VISIBLE),
  )
  const [selectedSteward, setSelectedSteward] = useState<Steward | null>(null)
  const [activeViewName, setActiveViewName] = useState<string | null>(null)

  const { page, loading, error, fetchedAtMs, retry } = useStewards(
    pageSize,
    pageIndex * pageSize,
  )

  // Relative times and staleness anchor at fetch time — the moment the data
  // was true — so the render itself stays pure.
  const nowMs = fetchedAtMs
  const needle = search.trim().toLowerCase()
  const scoped = scope !== rootPath

  const displayRows = useMemo(() => {
    if (page === null) return []
    let rows = page.stewards
    if (scoped) {
      rows = rows.filter((steward) => {
        const tenantPath = Object.entries(steward.dna?.attributes ?? {}).find(([k]) => k === 'tenant')?.[1]
        return tenantPath !== undefined && isScopeMatch(tenantPath, scope)
      })
    }
    if (needle !== '') {
      rows = rows.filter((steward) => matchesFilter(steward, needle, nowMs))
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
  }, [page, scoped, scope, needle, sort, nowMs])

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

  const onApplyView = useCallback(
    (config: SavedViewConfig) => {
      onSearchChange?.(config.filter)
      setSort(config.sort)
      setVisible(new Set(config.columns))
      setPageSize(config.pageSize)
      setPageIndex(0)
      setActiveViewName(config.name)
    },
    [onSearchChange],
  )

  const onRenameView = useCallback(
    (oldName: string, newName: string) => {
      setActiveViewName((current) => (current === oldName ? newName : current))
    },
    [],
  )

  const columns = COLUMNS.filter((column) => visible.has(column.key))
  const total = page?.total ?? 0
  const pages = Math.max(1, Math.ceil(total / pageSize))
  const current = pageIndex + 1
  const narrowed = needle !== '' || scoped
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
      <section className="panel">
        <div className="ptool">
          <SavedViews
            username={username}
            currentFilter={search}
            currentSort={sort}
            currentColumns={[...visible]}
            currentPageSize={pageSize}
            activeName={activeViewName}
            onApply={onApplyView}
            onRename={onRenameView}
          />
          <ColumnPicker visible={visible} onToggle={onToggleColumn} />
          <span className="cnt" data-testid="fleet-count">
            {page === null ? '' : countText}
          </span>
        </div>

        {loading ? (
          <LoadingRows />
        ) : error !== null ? (
          <ErrorNotice detail={error} onRetry={retry} />
        ) : page === null || total === 0 ? (
          <FleetEmpty />
        ) : displayRows.length === 0 ? (
          <NoMatch scopeOnly={needle === ''} />
        ) : (
          <FleetTable
            stewards={displayRows}
            columns={columns}
            sort={sort}
            onSort={onSort}
            nowMs={nowMs}
            onRowSelect={setSelectedSteward}
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

      <DnaDrawer steward={selectedSteward} onClose={() => setSelectedSteward(null)} nowMs={nowMs} />
    </>
  )
}
