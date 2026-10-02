// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz

/*
 * Audit log view (Story #2727, #2989). Filterable, paginated table backed by
 * GET /api/v1/audit/entries — the filter form exposes every query parameter
 * handleListAuditEntries reads (since, until, severity, action, event_type,
 * user_id, result, module).
 *
 * Security A9.1: audit-entry field values may originate from user/steward-
 * supplied data and are untrusted. Every value reaches the DOM through JSX
 * text interpolation — text nodes only, never dangerouslySetInnerHTML. Audit
 * logs are a high-value XSS target because they faithfully record
 * attacker-controlled input. details/changes are rendered via JSON.stringify
 * into JSX text nodes; CSV cells are formula-injection-escaped (A9.1).
 */
import { useState } from 'react'
import { useAuditEntries } from './useAuditEntries.ts'
import type { AuditEntry, AuditFilters } from './useAuditEntries.ts'
import './AuditView.css'

const PAGE_SIZE = 50

const EVENT_TYPES = [
  'authentication',
  'authorization',
  'configuration',
  'user_management',
  'system_access',
  'data_access',
  'data_modification',
  'security_event',
  'system_event',
  'compliance',
] as const

const SEVERITIES = ['low', 'medium', 'high', 'critical'] as const
const RESULTS = ['success', 'failure', 'error', 'denied'] as const

const CSV_HEADERS = [
  'id', 'timestamp', 'event_type', 'action', 'user_id', 'user_type',
  'resource_type', 'resource_id', 'resource_name', 'result', 'severity',
  'source', 'ip_address', 'method', 'path', 'error_code', 'error_message',
]

interface FormState {
  since: string
  until: string
  severity: string
  action: string
  event_type: string
  user_id: string
  result: string
  module: string
}

const EMPTY_FORM: FormState = {
  since: '',
  until: '',
  severity: '',
  action: '',
  event_type: '',
  user_id: '',
  result: '',
  module: '',
}

/** Convert a datetime-local input value to RFC3339 UTC. */
function toRFC3339(datetimeLocal: string): string {
  if (!datetimeLocal) return ''
  // datetime-local format: "YYYY-MM-DDTHH:MM" or "YYYY-MM-DDTHH:MM:SS"
  return /T\d{2}:\d{2}$/.test(datetimeLocal)
    ? datetimeLocal + ':00Z'
    : datetimeLocal + 'Z'
}

function severityTone(severity: string): string {
  switch (severity) {
    case 'critical':
    case 'high':
      return 'crit'
    case 'medium':
      return 'warn'
    case 'low':
      return 'neutral'
    default:
      return 'neutral'
  }
}

function resultTone(result: string): string {
  switch (result) {
    case 'success':
      return 'ok'
    case 'denied':
      return 'warn'
    case 'failure':
    case 'error':
      return 'crit'
    default:
      return 'neutral'
  }
}

/**
 * Escape a single CSV cell value.
 * - Prefixes cells starting with =, +, -, @ with ' to prevent spreadsheet
 *   formula injection (security A9.1).
 * - Wraps cells containing commas, double-quotes, or newlines in double quotes
 *   and escapes embedded double-quotes by doubling them (RFC 4180).
 */
export function escapeCsvCell(value: string): string {
  let v = value
  if (v.length > 0 && /^[=+\-@]/.test(v)) v = "'" + v
  if (/[,"\n\r]/.test(v)) v = '"' + v.replace(/"/g, '""') + '"'
  return v
}

/** Serialise the currently-loaded entries to a CSV string. */
export function buildAuditCSV(entries: AuditEntry[]): string {
  const rows = entries.map((e) =>
    [
      e.id, e.timestamp, e.event_type, e.action, e.user_id, e.user_type,
      e.resource_type, e.resource_id, e.resource_name, e.result, e.severity,
      e.source, e.ip_address, e.method, e.path, e.error_code, e.error_message,
    ].map((v) => escapeCsvCell(v || '')).join(','),
  )
  return [CSV_HEADERS.join(','), ...rows].join('\n')
}

function triggerCSVDownload(entries: AuditEntry[]): void {
  const csv = buildAuditCSV(entries)
  const blob = new Blob([csv], { type: 'text/csv;charset=utf-8;' })
  const url = URL.createObjectURL(blob)
  const a = document.createElement('a')
  a.href = url
  a.download = 'audit-export.csv'
  document.body.appendChild(a)
  a.click()
  document.body.removeChild(a)
  URL.revokeObjectURL(url)
}

function LoadingRows() {
  return (
    <div data-testid="audit-loading" aria-label="Loading audit entries">
      {Array.from({ length: 6 }, (_, i) => (
        <div className="skrow" key={i}>
          <span className="skel" style={{ width: '80%' }} />
          <span className="skel" style={{ width: '55%' }} />
          <span className="skel" style={{ width: '65%' }} />
          <span className="skel" style={{ width: '70%' }} />
          <span className="skel" style={{ width: '60%' }} />
          <span className="skel" style={{ width: '50%' }} />
        </div>
      ))}
    </div>
  )
}

function ErrorNotice({ detail, onRetry }: { detail: string; onRetry: () => void }) {
  return (
    <div className="notice err" role="alert">
      <div className="ic">!</div>
      <h3>Couldn&apos;t load audit entries</h3>
      <p>The audit query failed. Check your connection and try again.</p>
      <span className="mono2 detail">{detail}</span>
      <button type="button" className="btn" onClick={onRetry}>
        Retry
      </button>
    </div>
  )
}

function AuditEmpty() {
  return (
    <div className="notice empty" data-testid="audit-empty">
      <div className="ic">◍</div>
      <h3>No audit entries found</h3>
      <p>No entries match the current filters, or no audit events have been recorded yet.</p>
    </div>
  )
}

function AuditRow({
  entry,
  expanded,
  onToggle,
}: {
  entry: AuditEntry
  expanded: boolean
  onToggle: () => void
}) {
  const hasDetails =
    entry.details !== undefined && Object.keys(entry.details).length > 0
  const hasChanges = entry.changes !== undefined
  const hasPayload = hasDetails || hasChanges

  return (
    <>
      <tr
        className={hasPayload ? 'expandable' : undefined}
        onClick={hasPayload ? onToggle : undefined}
        aria-expanded={hasPayload ? expanded : undefined}
        data-testid={`audit-row-${entry.id}`}
      >
        <td className="c-timestamp">
          <span className="mono2">{entry.timestamp}</span>
        </td>
        <td className="c-severity">
          {entry.severity ? (
            <span className={`pill ${severityTone(entry.severity)}`}>
              <span className="dot" />
              {entry.severity}
            </span>
          ) : (
            <span className="mut">—</span>
          )}
        </td>
        <td className="c-event-type">
          <span className="mut">{entry.event_type || '—'}</span>
        </td>
        <td className="c-action">
          <span className="mono2">{entry.action || '—'}</span>
        </td>
        <td className="c-user">
          <span className="mono2">{entry.user_id || '—'}</span>
        </td>
        <td className="c-resource">
          <span className="mut">{entry.resource_type || '—'}</span>
          {entry.resource_id && (
            <>
              {' '}
              <span className="mono2">{entry.resource_id}</span>
            </>
          )}
        </td>
        <td className="c-result">
          {entry.result ? (
            <span className={`pill ${resultTone(entry.result)}`}>
              <span className="dot" />
              {entry.result}
            </span>
          ) : (
            <span className="mut">—</span>
          )}
        </td>
        <td className="c-spacer" />
      </tr>
      {expanded && hasPayload && (
        <tr
          className="audit-detail-row"
          data-testid={`audit-detail-${entry.id}`}
        >
          <td colSpan={8} className="audit-detail-cell">
            {hasDetails && (
              <div className="audit-detail-section">
                <span className="audit-detail-label">Details</span>
                {/* JSON.stringify renders as text node — safe per A9.1 */}
                <pre className="audit-detail-pre">
                  {JSON.stringify(entry.details, null, 2)}
                </pre>
              </div>
            )}
            {hasChanges && (
              <div className="audit-detail-section">
                <span className="audit-detail-label">Changes</span>
                <pre className="audit-detail-pre">
                  {JSON.stringify(entry.changes, null, 2)}
                </pre>
              </div>
            )}
          </td>
        </tr>
      )}
    </>
  )
}

export default function AuditView() {
  const [form, setForm] = useState<FormState>(EMPTY_FORM)
  const [applied, setApplied] = useState<FormState>(EMPTY_FORM)
  const [offset, setOffset] = useState(0)
  const [expandedId, setExpandedId] = useState<string | null>(null)

  const filters: AuditFilters = {
    since: toRFC3339(applied.since),
    until: toRFC3339(applied.until),
    severity: applied.severity,
    action: applied.action,
    event_type: applied.event_type,
    user_id: applied.user_id,
    result: applied.result,
    module: applied.module,
    limit: PAGE_SIZE,
    offset,
  }

  const { entries, loading, error, hasMore, retry } = useAuditEntries(filters)

  const hasPrev = offset > 0
  const from = offset + 1
  const to = offset + entries.length

  function applyFilters(e: React.FormEvent) {
    e.preventDefault()
    setApplied({ ...form })
    setOffset(0)
    setExpandedId(null)
  }

  function clearFilters() {
    setForm(EMPTY_FORM)
    setApplied(EMPTY_FORM)
    setOffset(0)
    setExpandedId(null)
  }

  function field(name: keyof FormState, value: string) {
    setForm((f) => ({ ...f, [name]: value }))
  }

  function toggleExpand(id: string) {
    setExpandedId((prev) => (prev === id ? null : id))
  }

  return (
    <>
      <div className="htitle">
        <h1>Audit Log</h1>
        <p>Browse and filter audit events recorded on this controller.</p>
      </div>
      <section className="panel">
        <form className="audit-filters" onSubmit={applyFilters}>
          <div className="audit-filter-row">
            <label className="audit-filter-field">
              <span className="audit-filter-label">Since</span>
              <input
                type="datetime-local"
                aria-label="Since"
                value={form.since}
                onChange={(e) => field('since', e.target.value)}
              />
            </label>
            <label className="audit-filter-field">
              <span className="audit-filter-label">Until</span>
              <input
                type="datetime-local"
                aria-label="Until"
                value={form.until}
                onChange={(e) => field('until', e.target.value)}
              />
            </label>
            <label className="audit-filter-field">
              <span className="audit-filter-label">Severity</span>
              <select
                aria-label="Severity"
                value={form.severity}
                onChange={(e) => field('severity', e.target.value)}
              >
                <option value="">All</option>
                {SEVERITIES.map((s) => (
                  <option key={s} value={s}>
                    {s}
                  </option>
                ))}
              </select>
            </label>
            <label className="audit-filter-field">
              <span className="audit-filter-label">Event type</span>
              <select
                aria-label="Event type"
                value={form.event_type}
                onChange={(e) => field('event_type', e.target.value)}
              >
                <option value="">All</option>
                {EVENT_TYPES.map((t) => (
                  <option key={t} value={t}>
                    {t}
                  </option>
                ))}
              </select>
            </label>
            <label className="audit-filter-field">
              <span className="audit-filter-label">Result</span>
              <select
                aria-label="Result"
                value={form.result}
                onChange={(e) => field('result', e.target.value)}
              >
                <option value="">All</option>
                {RESULTS.map((r) => (
                  <option key={r} value={r}>
                    {r}
                  </option>
                ))}
              </select>
            </label>
            <label className="audit-filter-field">
              <span className="audit-filter-label">User ID</span>
              <input
                type="text"
                aria-label="User ID"
                value={form.user_id}
                onChange={(e) => field('user_id', e.target.value)}
              />
            </label>
            <label className="audit-filter-field">
              <span className="audit-filter-label">Action</span>
              <input
                type="text"
                aria-label="Action"
                value={form.action}
                onChange={(e) => field('action', e.target.value)}
              />
            </label>
            <label className="audit-filter-field">
              <span className="audit-filter-label">Module</span>
              <input
                type="text"
                aria-label="Module"
                value={form.module}
                onChange={(e) => field('module', e.target.value)}
              />
            </label>
          </div>
          <div className="audit-filter-actions">
            <button type="submit" className="audit-apply-btn">
              Apply
            </button>
            <button type="button" className="audit-clear-btn" onClick={clearFilters}>
              Clear
            </button>
            {entries.length > 0 && !loading && (
              <button
                type="button"
                className="audit-clear-btn"
                onClick={() => triggerCSVDownload(entries)}
                data-testid="audit-export-btn"
              >
                Export CSV
              </button>
            )}
          </div>
        </form>

        {loading ? (
          <LoadingRows />
        ) : error !== null ? (
          <ErrorNotice detail={error} onRetry={retry} />
        ) : entries.length === 0 ? (
          <AuditEmpty />
        ) : (
          <table className="tbl" data-testid="audit-table">
            <thead>
              <tr>
                <th className="c-timestamp">Timestamp</th>
                <th className="c-severity">Severity</th>
                <th className="c-event-type">Event type</th>
                <th className="c-action">Action</th>
                <th className="c-user">User</th>
                <th className="c-resource">Resource</th>
                <th className="c-result">Result</th>
                <th className="c-spacer" aria-hidden="true" />
              </tr>
            </thead>
            <tbody>
              {entries.map((entry) => (
                <AuditRow
                  key={entry.id}
                  entry={entry}
                  expanded={expandedId === entry.id}
                  onToggle={() => toggleExpand(entry.id)}
                />
              ))}
            </tbody>
          </table>
        )}

        {!loading && error === null && (hasPrev || hasMore) && (
          <div className="pager" data-testid="audit-pager">
            <span>
              Showing{' '}
              <b>{from}</b>–<b>{to}</b>
            </span>
            <div className="pg">
              <button
                type="button"
                aria-label="Previous page"
                disabled={!hasPrev}
                onClick={() => setOffset((o) => Math.max(0, o - PAGE_SIZE))}
              >
                ‹
              </button>
              <button
                type="button"
                aria-label="Next page"
                disabled={!hasMore}
                onClick={() => setOffset((o) => o + PAGE_SIZE)}
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
