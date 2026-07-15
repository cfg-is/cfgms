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
 * Row drill-in (asset-DNA drawer) is Story #2498; it will attach through an
 * onRowSelect seam on this component.
 */
import { deriveHealth, formatLastSeen } from './health.ts'
import type { ColumnDef, Steward } from './columns.ts'

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
}: {
  column: ColumnDef
  steward: Steward
  nowMs: number
}) {
  if (column.kind === 'health') {
    const health = deriveHealth(steward.status, steward.last_seen, nowMs)
    return (
      <td className={`c-${column.key}`}>
        <span className={`pill ${health.tone}`}>
          <span className="dot" />
          {health.label}
        </span>
      </td>
    )
  }
  if (column.kind === 'seen') {
    return (
      <td className={`c-${column.key}`}>
        <span className="seen">{formatLastSeen(steward.last_seen, nowMs)}</span>
      </td>
    )
  }
  const value = column.value(steward)
  return (
    <td className={`c-${column.key}`}>
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
}: {
  stewards: Steward[]
  columns: ColumnDef[]
  sort: SortState | null
  onSort: (key: string) => void
  nowMs: number
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
          <th className="c-spacer" aria-hidden="true" />
        </tr>
      </thead>
      <tbody>
        {stewards.map((steward) => (
          <tr key={steward.id}>
            {columns.map((column) => (
              <Cell
                key={column.key}
                column={column}
                steward={steward}
                nowMs={nowMs}
              />
            ))}
            <td className="c-spacer" />
          </tr>
        ))}
      </tbody>
    </table>
  )
}
