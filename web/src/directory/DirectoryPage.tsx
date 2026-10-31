// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz

/*
 * Directory list page (Issue #5565) shared by the Users and Groups routes: a
 * tenant-scoped table of directory objects (#5557) with search (`q`), source
 * and managed filters, server-side cursor pagination (`page_token`), and a row
 * drill-in drawer (DirectoryDrawer). Chrome, states, pills, pager and drawer
 * styles come from the fleet view (FleetStates, FleetOverview.css).
 *
 * Every directory value is rendered through JSX text interpolation — text
 * nodes only. Never inject raw HTML anywhere under
 * web/src/directory.
 */
import { useCallback, useEffect, useState } from 'react'
import { ErrorNotice, LoadingRows } from '../fleet/FleetStates.tsx'
import '../fleet/FleetOverview.css'
import DirectoryDrawer from './DirectoryDrawer.tsx'
import {
  listDirectory,
  type DirectoryKind,
  type DirectoryObject,
  type DirectorySource,
} from './directoryApi.ts'

const PAGE_LIMIT = 50
const SEARCH_DEBOUNCE_MS = 250

interface Outcome {
  key: string
  rows?: DirectoryObject[]
  next?: string
  notFound?: boolean
  error?: string
}

/** Compact UTC timestamp for a last-observed value; the raw text if unparseable. */
function formatObserved(value: string): string {
  if (value === '') return '—'
  const ms = Date.parse(value)
  if (Number.isNaN(ms)) return value
  return new Date(ms).toISOString().replace('T', ' ').slice(0, 16) + 'Z'
}

function rowName(row: DirectoryObject): string {
  return row.displayName || row.samAccountName || row.id
}

function NotAvailable({ noun }: { noun: string }) {
  return (
    <div className="notice empty" data-testid="directory-not-available">
      <div className="ic">◍</div>
      <h3>No {noun} available</h3>
      <p>The directory has nothing to show for this scope.</p>
    </div>
  )
}

function EmptyState({ noun, filtered }: { noun: string; filtered: boolean }) {
  return (
    <div className="notice empty" data-testid="directory-empty">
      <div className="ic">◍</div>
      {filtered ? (
        <>
          <h3>No {noun} match your filters</h3>
          <p>Clear the search or filters to see every {noun.replace(/s$/, '')} in scope.</p>
        </>
      ) : (
        <>
          <h3>No {noun} synced yet</h3>
          <p>
            Once a directory source is synced for this tenant, its {noun} will appear here.
          </p>
        </>
      )}
    </div>
  )
}

export default function DirectoryPage({ kind }: { kind: DirectoryKind }) {
  const isUsers = kind === 'users'
  const noun = isUsers ? 'users' : 'groups'
  const [qInput, setQInput] = useState('')
  const [q, setQ] = useState('')
  const [source, setSource] = useState<DirectorySource | ''>('')
  const [managed, setManaged] = useState<'true' | 'false' | ''>('')
  // Cursor stack: tokens[i] is the token that fetches page i ('' = first page).
  const [tokens, setTokens] = useState<string[]>([''])
  const [attempt, setAttempt] = useState(0)
  const [outcome, setOutcome] = useState<Outcome | null>(null)
  const [selected, setSelected] = useState<DirectoryObject | null>(null)

  useEffect(() => {
    const timer = setTimeout(() => {
      setQ(qInput)
      setTokens(['']) // a new query restarts at the first page
    }, SEARCH_DEBOUNCE_MS)
    return () => clearTimeout(timer)
  }, [qInput])

  const pageToken = tokens[tokens.length - 1] ?? ''
  const key = `${kind}|${q}|${source}|${managed}|${pageToken}|${attempt}`

  useEffect(() => {
    let cancelled = false
    listDirectory(kind, { q, source, managed, limit: PAGE_LIMIT, pageToken })
      .then((result) => {
        if (cancelled) return
        if (result.status === 'notFound') setOutcome({ key, notFound: true })
        else setOutcome({ key, rows: result.value.items, next: result.value.nextPageToken })
      })
      .catch((cause: unknown) => {
        if (cancelled) return
        setOutcome({
          key,
          error:
            cause instanceof Error && cause.message
              ? cause.message
              : `GET /api/v1/directory/${kind} — request failed`,
        })
      })
    return () => {
      cancelled = true
    }
  }, [key, kind, q, source, managed, pageToken])

  const retry = useCallback(() => setAttempt((n) => n + 1), [])
  const current = outcome?.key === key ? outcome : null
  const filtered = q.trim() !== '' || source !== '' || managed !== ''
  const rows = current?.rows ?? []
  const pageNo = tokens.length
  // A page can come back empty with a cursor when filters scanned a long stretch.
  const hasNext = (current?.next ?? '') !== ''

  function resetPaging() {
    setTokens([''])
  }

  return (
    <>
      <div className="htitle">
        <h1>{isUsers ? 'Users' : 'Groups'}</h1>
        <p>
          {isUsers
            ? 'Directory users synced from Active Directory and Microsoft 365, read only.'
            : 'Directory groups synced from Active Directory and Microsoft 365, read only.'}
        </p>
      </div>

      <section className="panel">
        <div className="ptool">
          <input
            type="search"
            aria-label={`Search ${noun}`}
            placeholder={`Search ${noun}…`}
            value={qInput}
            maxLength={256}
            onChange={(e) => setQInput(e.target.value)}
          />
          <select
            aria-label="Source"
            value={source}
            onChange={(e) => {
              setSource(e.target.value as DirectorySource | '')
              resetPaging()
            }}
          >
            <option value="">All sources</option>
            <option value="ad">Active Directory</option>
            <option value="m365">Microsoft 365</option>
          </select>
          <select
            aria-label="Managed"
            value={managed}
            onChange={(e) => {
              setManaged(e.target.value as 'true' | 'false' | '')
              resetPaging()
            }}
          >
            <option value="">Managed and unmanaged</option>
            <option value="true">Managed</option>
            <option value="false">Unmanaged</option>
          </select>
        </div>

        {current === null ? (
          <LoadingRows label={`Loading ${noun}`} />
        ) : current.error !== undefined ? (
          <ErrorNotice
            detail={current.error}
            onRetry={retry}
            message={`The ${noun} request failed. Check your connection and try again.`}
          />
        ) : current.notFound ? (
          <NotAvailable noun={noun} />
        ) : rows.length === 0 && !hasNext ? (
          <EmptyState noun={noun} filtered={filtered} />
        ) : (
          <table className="tbl" data-testid="directory-table">
            <thead>
              <tr>
                <th>Source</th>
                <th>Display name</th>
                <th>Account name</th>
                {isUsers && <th>Enabled</th>}
                <th>Managed</th>
                <th>Last observed</th>
                <th>Status</th>
              </tr>
            </thead>
            <tbody>
              {rows.map((row) => (
                <tr
                  key={`${row.source}/${row.authority}/${row.id}`}
                  className="sel"
                  tabIndex={0}
                  onClick={() => setSelected(row)}
                  onKeyDown={(event) => {
                    if (event.key === 'Enter' || event.key === ' ') {
                      event.preventDefault()
                      setSelected(row)
                    }
                  }}
                >
                  <td className="mono2">{row.source || '—'}</td>
                  <td className="nm">{rowName(row)}</td>
                  <td className="mono2">{row.samAccountName || row.userPrincipalName || '—'}</td>
                  {isUsers && (
                    <td>
                      {row.enabled === null ? (
                        '—'
                      ) : (
                        <span className={`pill ${row.enabled ? 'ok' : 'neutral'}`}>
                          <span className="dot" />
                          {row.enabled ? 'Enabled' : 'Disabled'}
                        </span>
                      )}
                    </td>
                  )}
                  <td>
                    <span className={`pill ${row.managed ? 'ok' : 'neutral'}`}>
                      <span className="dot" />
                      {row.managed ? 'Managed' : 'Unmanaged'}
                    </span>
                  </td>
                  <td className="seen">{formatObserved(row.lastObserved)}</td>
                  <td>
                    {row.stale ? (
                      <span className="pill warn" data-testid="stale-marker">
                        <span className="dot" />
                        Stale
                      </span>
                    ) : (
                      <span className="mut">—</span>
                    )}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        )}

        {current !== null && current.error === undefined && !current.notFound && (pageNo > 1 || hasNext) && (
          <div className="pager" data-testid="directory-pager">
            <span>Page {pageNo}</span>
            <div className="pg">
              <button
                type="button"
                aria-label="Previous page"
                disabled={pageNo <= 1}
                onClick={() => setTokens((t) => t.slice(0, -1))}
              >
                ‹
              </button>
              <button
                type="button"
                aria-label="Next page"
                disabled={!hasNext}
                onClick={() => setTokens((t) => [...t, current.next ?? ''])}
              >
                ›
              </button>
            </div>
          </div>
        )}
      </section>

      {selected !== null && (
        <DirectoryDrawer kind={kind} object={selected} onClose={() => setSelected(null)} />
      )}
    </>
  )
}
