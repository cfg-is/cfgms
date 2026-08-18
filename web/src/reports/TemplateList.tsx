// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz

/*
 * TemplateList (Story #3271) — lists available report templates from
 * GET /api/v1/reports/templates ({templates, count}).
 *
 * Four states: Loading (skeleton rows), Error (notice + retry),
 * Empty (no templates), Ready (sortable table).
 *
 * Reuses rdb-* CSS tokens from ReportsDashboardView.css and the sortable
 * column header convention from FleetTable.tsx.
 */
import { useCallback, useEffect, useState } from 'react'
import { apiFetch } from '../api/client.ts'
import './ReportsDashboardView.css'

export interface TemplateInfo {
  name: string
  type: string
  description: string
  parameters: Array<{
    name: string
    type: string
    required: boolean
    default?: unknown
  }>
  supported_formats: string[]
}

type SortKey = 'name' | 'type'
type SortDir = 1 | -1

interface SortState {
  key: SortKey
  dir: SortDir
}

function parseTemplates(body: unknown): TemplateInfo[] {
  if (typeof body !== 'object' || body === null) return []
  const r = body as Record<string, unknown>
  if (!Array.isArray(r.templates)) return []
  return r.templates.flatMap((t: unknown): TemplateInfo[] => {
    if (typeof t !== 'object' || t === null) return []
    const ti = t as Record<string, unknown>
    if (typeof ti.name !== 'string' || typeof ti.type !== 'string') return []
    return [
      {
        name: ti.name,
        type: ti.type,
        description: typeof ti.description === 'string' ? ti.description : '',
        parameters: Array.isArray(ti.parameters)
          ? (ti.parameters as TemplateInfo['parameters'])
          : [],
        supported_formats: Array.isArray(ti.supported_formats)
          ? (ti.supported_formats as string[])
          : [],
      },
    ]
  })
}

function CritIcon() {
  return (
    <svg
      width="16"
      height="16"
      viewBox="0 0 16 16"
      fill="none"
      stroke="currentColor"
      strokeWidth="2.1"
      strokeLinecap="round"
      aria-hidden="true"
    >
      <circle cx="8" cy="8" r="6.2" />
      <path d="M8 4.8v4" />
      <path d="M8 11.2v.05" />
    </svg>
  )
}

interface FetchState {
  key: number
  templates?: TemplateInfo[]
  error?: string
}

export default function TemplateList({
  onSelectTemplate,
}: {
  onSelectTemplate: (name: string) => void
}) {
  const [attempt, setAttempt] = useState(0)
  const [state, setState] = useState<FetchState | null>(null)
  const [sort, setSort] = useState<SortState>({ key: 'name', dir: 1 })

  const retry = useCallback(() => setAttempt((n) => n + 1), [])

  useEffect(() => {
    let cancelled = false
    apiFetch('/api/v1/reports/templates')
      .then(async (r) => {
        if (!r.ok) {
          throw new Error(`GET /api/v1/reports/templates — ${r.status}`)
        }
        return parseTemplates(await r.json() as unknown)
      })
      .then((rows) => {
        if (cancelled) return
        setState({ key: attempt, templates: rows })
      })
      .catch((cause: unknown) => {
        if (cancelled) return
        setState({
          key: attempt,
          error:
            cause instanceof Error && cause.message
              ? cause.message
              : 'GET /api/v1/reports/templates failed',
        })
      })
    return () => {
      cancelled = true
    }
  }, [attempt])

  const current = state?.key === attempt ? state : null
  const loading = current === null
  const error = current?.error ?? null
  const templates = current?.templates ?? null

  function handleSort(key: SortKey) {
    setSort((prev) =>
      prev.key === key ? { key, dir: (prev.dir * -1) as SortDir } : { key, dir: 1 },
    )
  }

  if (loading) {
    return (
      <div data-testid="template-list-loading" aria-busy="true">
        {[0, 1, 2].map((i) => (
          <div key={i} className="rdb-panel" style={{ marginBottom: 'var(--space-2)' }}>
            <span className="rdb-skel" style={{ height: '13px', width: '40%', display: 'block' }} />
            <span
              className="rdb-skel"
              style={{ height: '11px', width: '65%', marginTop: '6px', display: 'block' }}
            />
          </div>
        ))}
      </div>
    )
  }

  if (error !== null) {
    return (
      <div className="rdb-notice err" role="alert">
        <CritIcon />
        <div className="rdb-notice-body">
          <b>Could not load report templates.</b>
          <p className="rdb-notice-sub">{error}</p>
          <button type="button" className="rdb-btn" onClick={retry}>
            Retry
          </button>
        </div>
      </div>
    )
  }

  if (templates !== null && templates.length === 0) {
    return (
      <div className="rdb-notice" data-testid="template-list-empty">
        <p>No report templates available.</p>
        <p className="rdb-notice-np">
          Report templates are registered server-side. Contact your administrator.
        </p>
      </div>
    )
  }

  const sorted = templates !== null
    ? [...templates].sort((a, b) => {
        const av = a[sort.key]
        const bv = b[sort.key]
        return av < bv ? -sort.dir : av > bv ? sort.dir : 0
      })
    : []

  return (
    <table className="tbl" data-testid="template-list-table">
      <thead>
        <tr>
          <th
            className={`c-name${sort.key === 'name' ? ' sort' : ''}`}
            aria-sort={sort.key === 'name' ? (sort.dir > 0 ? 'ascending' : 'descending') : undefined}
            onClick={() => handleSort('name')}
          >
            Name
            <span className="ar" aria-hidden="true">
              {sort.key === 'name' && sort.dir < 0 ? '▲' : '▼'}
            </span>
          </th>
          <th
            className={`c-type${sort.key === 'type' ? ' sort' : ''}`}
            aria-sort={sort.key === 'type' ? (sort.dir > 0 ? 'ascending' : 'descending') : undefined}
            onClick={() => handleSort('type')}
          >
            Type
            <span className="ar" aria-hidden="true">
              {sort.key === 'type' && sort.dir < 0 ? '▲' : '▼'}
            </span>
          </th>
          <th className="c-desc">Description</th>
          <th className="c-spacer" aria-hidden="true" />
        </tr>
      </thead>
      <tbody>
        {sorted.map((tmpl) => (
          <tr
            key={tmpl.name}
            className="sel"
            onClick={() => onSelectTemplate(tmpl.name)}
            onKeyDown={(e) => {
              if (e.key === 'Enter' || e.key === ' ') {
                e.preventDefault()
                onSelectTemplate(tmpl.name)
              }
            }}
            tabIndex={0}
            role="button"
            aria-label={`Select template ${tmpl.name}`}
          >
            <td className="c-name">
              <span className="nm">{tmpl.name}</span>
            </td>
            <td className="c-type">
              <span className="mono2">{tmpl.type}</span>
            </td>
            <td className="c-desc">
              <span className="mut">{tmpl.description}</span>
            </td>
            <td className="c-spacer" />
          </tr>
        ))}
      </tbody>
    </table>
  )
}
