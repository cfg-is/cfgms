// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz

/*
 * Fleet table (Story #2497) — mockup `table.tbl`. Sortable headers, mono
 * machine data, semantic Health pill, em-dash for missing DNA attributes.
 *
 * Security A9.1: every steward-supplied value lands in the DOM through JSX
 * text interpolation — text nodes only, never markup. Do not introduce
 * dangerouslySetInnerHTML here.
 *
 * Row drill-in (Story #2498): rows are selectable via click or Enter/Space;
 * the parent opens the asset-DNA drawer for the selected steward.
 */
import { deriveHealth, formatLastSeen } from './health.ts'
import type { ColumnDef, Steward } from './columns.ts'
import RowActionMenu from './RowActionMenu.tsx'

export interface SortState {
  key: string
  direction: 1 | -1
}

const CELL_CLASS: Record<string, string> = {
  name: 'nm',
  muted: 'mut',
  mono: 'mono2',
}

function Cell({
  column,
  steward,
  nowMs,
  rowHref,
  onRowSelect,
}: {
  column: ColumnDef
  steward: Steward
  nowMs: number
  rowHref?: string
  onRowSelect?: () => void
}) {
  /* The name cell hosts the row anchor so native modifier-key / middle-click /
   * context-menu "Open in new tab" works. Plain left-click opens the drawer
   * instead of navigating; modified clicks fall through to native anchor behavior. */
  if (column.key === 'name' && rowHref !== undefined) {
    const value = column.value(steward)
    return (
      <td className="c-name">
        <a
          href={rowHref}
          className="nm row-link"
          onClick={(e) => {
            if (e.button === 0 && !e.metaKey && !e.ctrlKey && !e.shiftKey) {
              e.preventDefault()
              onRowSelect?.()
            }
          }}
        >
          {value || '—'}
        </a>
      </td>
    )
  }
  if (column.kind === 'health') {
    const health = deriveHealth(steward.status, steward.last_seen, nowMs)
    return (
      <td className={`c-${column.key}`} onClick={onRowSelect}>
        <span className={`pill ${health.tone}`}>
          <span className="dot" />
          {health.label}
        </span>
      </td>
    )
  }
  if (column.kind === 'seen') {
    return (
      <td className={`c-${column.key}`} onClick={onRowSelect}>
        <span className="seen">{formatLastSeen(steward.last_seen, nowMs)}</span>
      </td>
    )
  }
  const value = column.value(steward)
  return (
    <td className={`c-${column.key}`} onClick={onRowSelect}>
      <span className={CELL_CLASS[column.kind]}>{value || '—'}</span>
    </td>
  )
}

export default function FleetTable({
  stewards,
  columns,
  sort,
  onSort,
  nowMs,
  onRowSelect,
}: {
  stewards: Steward[]
  columns: ColumnDef[]
  sort: SortState | null
  onSort: (key: string) => void
  nowMs: number
  onRowSelect?: (steward: Steward) => void
}) {
  return (
    <table className="tbl">
      <thead>
        <tr>
          {columns.map((column) => {
            const active = sort?.key === column.key
            return (
              <th
                key={column.key}
                className={`c-${column.key}${active ? ' sort' : ''}`}
                aria-sort={
                  active
                    ? sort.direction > 0
                      ? 'ascending'
                      : 'descending'
                    : undefined
                }
                onClick={() => onSort(column.key)}
              >
                {column.label}
                <span className="ar" aria-hidden="true">
                  {active && sort.direction < 0 ? '▲' : '▼'}
                </span>
              </th>
            )
          })}
          {onRowSelect !== undefined && <th className="c-act" aria-hidden="true" />}
          <th className="c-spacer" aria-hidden="true" />
        </tr>
      </thead>
      <tbody>
        {stewards.map((steward) => {
          const href = `/stewards/${encodeURIComponent(steward.id)}`
          return (
            <tr
              key={steward.id}
              className={onRowSelect ? 'sel' : undefined}
              onKeyDown={
                onRowSelect
                  ? (event) => {
                      if (event.key === 'Enter' || event.key === ' ') {
                        event.preventDefault()
                        onRowSelect(steward)
                      }
                    }
                  : undefined
              }
            >
              {columns.map((column) => (
                <Cell
                  key={column.key}
                  column={column}
                  steward={steward}
                  nowMs={nowMs}
                  rowHref={onRowSelect ? href : undefined}
                  onRowSelect={onRowSelect ? () => onRowSelect(steward) : undefined}
                />
              ))}
              {onRowSelect !== undefined && (
                <td className="c-act">
                  <RowActionMenu stewardId={steward.id} />
                </td>
              )}
              <td className="c-spacer" />
            </tr>
          )
        })}
      </tbody>
    </table>
  )
}
