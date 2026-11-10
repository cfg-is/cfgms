// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz

/*
 * Fleet query page (Issue #5460, Epic #5300) — the /osquery route, built to
 * docs/design/mockups/osquery-query.html. The admin picks a catalog query
 * (GET /api/v1/osquery/catalog), fills the parameter inputs built from that
 * entry's schema, enters a fleet selector and runs POST /api/v1/osquery/query.
 * The route is catalog-only: there is no free-text catalog id and no SQL input.
 *
 * osquery:execute needs a passkey presence tap. The apiFetch interceptor and
 * StepUpModal perform the tap and retry the request with X-Presence-Token, so
 * this view never builds that header. A cancelled tap comes back as the
 * 'cancelled' failure: nothing was sent to any steward.
 *
 * Results render one card per steward, identified by steward_id only (the API
 * returns no hostname). Error results and ran-but-empty results are visually
 * distinct cards; the tally pills and filters are derived client-side.
 *
 * Security A9.1: every cell value, steward id and error string renders as JSX
 * text, never as HTML.
 */
import { useState } from 'react'
import { useNavigate, useOutletContext } from 'react-router'
import SelectorInput from '../shell/SelectorInput.tsx'
import type { AppShellContext } from '../shell/AppShell.tsx'
import {
  resultKind,
  tallyResults,
  useOsqueryCatalog,
  useOsqueryRun,
  type OsqueryCatalogEntry,
  type OsqueryParam,
  type OsqueryRequest,
  type OsqueryResultKind,
  type OsqueryRow,
  type OsqueryStewardResult,
} from './useOsquery.ts'

/** Rows shown per steward before "Show all". */
const previewRows = 5

/** Values longer than this wrap in the table; shorter ones never split. */
const longValue = 24

type Filter = 'all' | OsqueryResultKind

const filters: { key: Filter; label: string }[] = [
  { key: 'all', label: 'All' },
  { key: 'rows', label: 'With rows' },
  { key: 'none', label: 'No rows' },
  { key: 'err', label: 'Errors' },
]

// Page-specific styles on the design tokens (docs/design/web-ui-design-tokens.css),
// mirrored from the mockup. Emitted as a <style> element, which the SPA CSP allows
// (style-src-elem), so the route carries its own layout.
const osqueryStyles = `
.osq-qform{display:grid;grid-template-columns:minmax(0,260px) minmax(0,1fr);gap:14px 16px;align-items:start;padding:var(--space-4);}
.osq-qform .full{grid-column:1 / -1;}
.osq-field{display:flex;flex-direction:column;gap:5px;min-width:0;}
.osq-lbl{font-size:10.5px;font-weight:600;letter-spacing:.05em;text-transform:uppercase;color:var(--text-faint);}
.osq-ptype{font-family:var(--font-mono);font-size:10px;letter-spacing:0;text-transform:none;color:var(--text-faint);font-weight:500;margin-left:6px;}
.osq-field select,.osq-field input[type=text]{font:inherit;font-family:var(--font-mono);font-size:13px;color:var(--text-primary);background:var(--bg-surface);border:1px solid var(--border);border-radius:var(--radius);padding:8px 11px;min-width:0;}
.osq-field select:focus-visible,.osq-field input:focus-visible{outline:2px solid var(--accent);outline-offset:2px;}
.osq-params{display:flex;flex-wrap:wrap;gap:12px 16px;min-width:0;}
.osq-params .osq-field{flex:1 1 200px;max-width:320px;}
.osq-none{font-size:var(--text-sm);color:var(--text-faint);padding:8px 0;}
.osq-hint{font-size:var(--text-sm);color:var(--text-faint);}
.osq-selbox{display:flex;align-items:center;gap:9px;border:1px solid var(--border);background:var(--bg-surface);border-radius:var(--radius);padding:0 11px;}
.osq-selbox input{flex:1;border:0;padding:8px 0;background:transparent;color:var(--text-primary);font-family:var(--font-mono);font-size:13px;min-width:0;}
.osq-selbox input:focus-visible{outline:none;}
.osq-selbox:focus-within{outline:2px solid var(--accent);outline-offset:2px;}
.osq-field.bad .osq-selbox{border-color:var(--state-crit);}
.osq-fmsg{font-size:var(--text-sm);color:var(--state-crit);font-weight:600;}
.osq-msg{font-size:var(--text-sm);color:var(--state-crit);padding:9px 12px;border:1px solid var(--state-crit);background:var(--state-crit-bg);border-radius:var(--radius-sm);}
.osq-runbar{display:flex;align-items:center;gap:12px;flex-wrap:wrap;padding:12px var(--space-4);border-top:1px solid var(--border);}
.osq-runbar .osq-hint{flex:1;min-width:220px;}
.osq-ran{display:flex;flex-wrap:wrap;gap:4px 10px;align-items:center;font-size:var(--text-sm);color:var(--text-faint);}
.osq-ran .mono2{color:var(--text-secondary);font-size:11.5px;}
.osq-tally{display:flex;flex-wrap:wrap;gap:6px;align-items:center;font-size:var(--text-sm);}
.osq-resbar{display:flex;flex-wrap:wrap;gap:8px 14px;align-items:center;padding:12px 16px 0;}
.osq-filt{display:inline-flex;gap:4px;flex-wrap:wrap;}
.osq-filt button{appearance:none;font:inherit;border:1px solid var(--border);background:transparent;color:var(--text-secondary);font-size:11px;font-weight:600;padding:4px 10px;border-radius:var(--radius-pill);cursor:pointer;}
.osq-filt button[aria-pressed="true"]{background:var(--tint-blue);color:var(--accent);border-color:var(--accent);}
.osq-list{display:flex;flex-direction:column;gap:10px;padding:14px 16px;}
.osq-card{border:1px solid var(--border);border-radius:var(--radius);overflow:hidden;background:var(--bg-surface);}
.osq-head{display:flex;align-items:center;gap:10px;padding:9px 12px;flex-wrap:wrap;background:var(--bg-primary);}
.osq-sid{font-family:var(--font-mono);font-size:12.5px;font-weight:600;color:var(--text-primary);overflow-wrap:anywhere;min-width:0;flex:1 1 260px;}
.osq-card.is-err{border-color:var(--state-crit);}
.osq-card.is-err .osq-head{background:var(--tint-red);}
.osq-errtext{margin:0;padding:10px 12px;border-top:1px solid var(--state-crit);background:var(--state-crit-bg);color:var(--state-crit);font-family:var(--font-mono);font-size:12px;line-height:1.5;white-space:pre-wrap;overflow-wrap:anywhere;}
.osq-errtext .osq-errlbl{display:block;margin-bottom:2px;font-family:var(--font-sans);}
.osq-nonetext{margin:0;padding:10px 12px;border-top:1px dashed var(--border);color:var(--text-secondary);font-size:12.5px;}
.osq-twrap{overflow-x:auto;border-top:1px solid var(--border);}
.osq-tbl{width:100%;border-collapse:collapse;font-size:12px;}
.osq-tbl th{padding:7px 12px;text-align:left;background:var(--bg-surface);font-family:var(--font-mono);font-size:11px;font-weight:600;color:var(--text-secondary);border-bottom:1px solid var(--border);}
.osq-tbl td{padding:7px 12px;font-family:var(--font-mono);white-space:nowrap;color:var(--text-primary);}
.osq-tbl td.long{white-space:normal;min-width:200px;max-width:320px;overflow-wrap:anywhere;}
.osq-tbl td.nil{color:var(--text-faint);}
.osq-tbl tbody tr:nth-child(even) > td{background:var(--bg-primary);}
.osq-more{display:flex;align-items:center;gap:10px;padding:7px 12px;border-top:1px solid var(--border);font-size:var(--text-sm);color:var(--text-faint);}
.osq-link{appearance:none;font:inherit;border:0;background:transparent;color:var(--accent);font-size:var(--text-sm);font-weight:600;cursor:pointer;padding:2px 4px;border-radius:var(--radius-sm);}
.osq-caret{appearance:none;border:1px solid transparent;background:transparent;color:var(--text-faint);width:26px;height:26px;border-radius:var(--radius-sm);display:grid;place-items:center;cursor:pointer;flex:none;}
.osq-caret:hover{border-color:var(--border);}
.osq-caret.closed svg{transform:rotate(-90deg);}
.osq-errcard{display:flex;align-items:center;gap:12px;padding:16px;flex-wrap:wrap;}
.osq-errcard .t{flex:1;min-width:200px;}
.osq-errcard .t b{display:block;color:var(--state-crit);}
.osq-errcard .t span{color:var(--text-secondary);font-size:12.5px;}
.osq-wait{padding:14px 16px 0;color:var(--text-secondary);font-size:12.5px;}
.osq-skcard{border:1px solid var(--border);border-radius:var(--radius);padding:12px;display:flex;gap:12px;align-items:center;}
@media (max-width:780px){
  .osq-qform{grid-template-columns:1fr;}
  .osq-params .osq-field{max-width:none;}
  .osq-runbar .wf-btn-primary{width:100%;}
}
`

function Caret({ open }: { open: boolean }) {
  return (
    <svg width="14" height="14" viewBox="0 0 24 24" fill="none" aria-hidden="true" className={open ? '' : 'closed'}>
      <path d="m6 9 6 6 6-6" stroke="currentColor" strokeWidth="2.2" strokeLinecap="round" strokeLinejoin="round" />
    </svg>
  )
}

function ParamInput({
  param,
  value,
  onChange,
}: {
  param: OsqueryParam
  value: string
  onChange: (value: string) => void
}) {
  const id = `osq-param-${param.name}`
  return (
    <div className="osq-field">
      <label htmlFor={id}>
        {param.name}
        <span className="osq-ptype">
          {param.type === 'enum' ? `one of ${param.allowedValues.length}` : 'text'}
        </span>
      </label>
      {param.type === 'enum' ? (
        <select id={id} data-testid={id} value={value} onChange={(e) => onChange(e.target.value)}>
          {param.allowedValues.map((v) => (
            <option key={v} value={v}>
              {v}
            </option>
          ))}
        </select>
      ) : (
        <>
          <input
            id={id}
            type="text"
            data-testid={id}
            spellCheck={false}
            value={value}
            onChange={(e) => onChange(e.target.value)}
          />
          <span className="osq-hint">Checked by the controller before it runs.</span>
        </>
      )}
    </div>
  )
}

/** Column set of a card: every key any row carries, sorted. */
function columnsOf(rows: OsqueryRow[]): string[] {
  const keys = new Set<string>()
  for (const row of rows) for (const key of Object.keys(row)) keys.add(key)
  return Array.from(keys).sort()
}

function Cell({ value }: { value: string }) {
  if (value === '') {
    return (
      <td className="nil" title="empty value" data-testid="osq-cell-empty">
        —
      </td>
    )
  }
  return (
    <td className={value.length > longValue ? 'long' : undefined} data-testid="osq-cell">
      {value}
    </td>
  )
}

function ResultCard({ result }: { result: OsqueryStewardResult }) {
  const [expanded, setExpanded] = useState(false)
  const [collapsed, setCollapsed] = useState(false)
  const kind = resultKind(result)

  if (kind === 'err') {
    return (
      <section className="osq-card is-err" data-testid="osq-card" data-kind="err">
        <div className="osq-head">
          <span className="pill crit">
            <span className="dot" />
            Error
          </span>
          <span className="osq-sid" data-testid="osq-steward-id">
            {result.stewardId}
          </span>
        </div>
        <p className="osq-errtext" data-testid="osq-error-text">
          <span className="osq-errlbl">Steward error</span>
          {result.error}
        </p>
      </section>
    )
  }

  if (kind === 'none') {
    return (
      <section className="osq-card is-none" data-testid="osq-card" data-kind="none">
        <div className="osq-head">
          <span className="pill neutral">
            <span className="dot" />
            No rows
          </span>
          <span className="osq-sid" data-testid="osq-steward-id">
            {result.stewardId}
          </span>
        </div>
        <p className="osq-nonetext" data-testid="osq-none-text">
          The query ran on this steward and returned nothing.
        </p>
      </section>
    )
  }

  const columns = columnsOf(result.rows)
  const shown = expanded ? result.rows : result.rows.slice(0, previewRows)
  const count = result.rows.length
  return (
    <section className="osq-card" data-testid="osq-card" data-kind="rows">
      <div className="osq-head">
        <button
          type="button"
          className={collapsed ? 'osq-caret closed' : 'osq-caret'}
          aria-label={collapsed ? 'Expand' : 'Collapse'}
          aria-expanded={!collapsed}
          onClick={() => setCollapsed((c) => !c)}
          data-testid="osq-collapse"
        >
          <Caret open={!collapsed} />
        </button>
        <span className="pill ok">
          <span className="dot" />
          {count} {count === 1 ? 'row' : 'rows'}
        </span>
        <span className="osq-sid" data-testid="osq-steward-id">
          {result.stewardId}
        </span>
      </div>
      {!collapsed && (
        <>
          <div className="osq-twrap">
            <table className="osq-tbl">
              <thead>
                <tr>
                  {columns.map((c) => (
                    <th key={c}>{c}</th>
                  ))}
                </tr>
              </thead>
              <tbody>
                {shown.map((row, i) => {
                  const cells = new Map(Object.entries(row))
                  return (
                    <tr key={i}>
                      {columns.map((c) => (
                        <Cell key={c} value={cells.get(c) ?? ''} />
                      ))}
                    </tr>
                  )
                })}
              </tbody>
            </table>
          </div>
          {count > previewRows && (
            <div className="osq-more" data-testid="osq-more">
              <span>{expanded ? `Showing all ${count} rows` : `Showing ${previewRows} of ${count} rows`}</span>
              <button
                type="button"
                className="osq-link"
                onClick={() => setExpanded((e) => !e)}
                data-testid="osq-show-all"
              >
                {expanded ? 'Show fewer' : 'Show all'}
              </button>
            </div>
          )}
        </>
      )}
    </section>
  )
}

function Results({ results, ranAt }: { results: OsqueryStewardResult[]; ranAt: number }) {
  const [filter, setFilter] = useState<Filter>('all')
  const tally = tallyResults(results)
  const visible = filter === 'all' ? results : results.filter((r) => resultKind(r) === filter)
  return (
    <>
      <div className="osq-resbar">
        <div className="osq-tally" data-testid="osq-tally">
          <span>{tally.total} {tally.total === 1 ? 'steward' : 'stewards'} ·</span>
          <span className="pill ok">{tally.rows} with rows</span>
          <span className="pill neutral">{tally.none} no rows</span>
          <span className="pill crit">{tally.err} {tally.err === 1 ? 'error' : 'errors'}</span>
        </div>
        <div className="osq-filt" role="group" aria-label="Filter results">
          {filters.map((f) => (
            <button
              key={f.key}
              type="button"
              aria-pressed={filter === f.key}
              onClick={() => setFilter(f.key)}
              data-testid={`osq-filter-${f.key}`}
            >
              {f.label}
            </button>
          ))}
        </div>
      </div>
      <div className="osq-list">
        {visible.length === 0 ? (
          <p className="osq-nonetext" style={{ border: 0 }}>
            No stewards in this group.
          </p>
        ) : (
          visible.map((r, i) => <ResultCard key={`${ranAt}:${r.stewardId}:${i}`} result={r} />)
        )}
      </div>
    </>
  )
}

function ResultsNotice({ icon, title, children }: { icon: string; title: string; children: React.ReactNode }) {
  return (
    <div className="notice">
      <div className="ic">{icon}</div>
      <h3>{title}</h3>
      {children}
    </div>
  )
}

function describeRequest(request: OsqueryRequest): string {
  const params = Object.entries(request.params)
  return params.length === 0 ? request.catalogId : `${request.catalogId} ${params.map(([k, v]) => `${k}=${v}`).join(' ')}`
}

export default function OsqueryView() {
  const { catalog, loading, error: catalogError, retry: retryCatalog } = useOsqueryCatalog()
  const { state, run } = useOsqueryRun()
  const outlet = useOutletContext<AppShellContext | undefined>()
  const navigate = useNavigate()
  const [chosen, setChosen] = useState('')
  const [values, setValues] = useState<Record<string, string>>({})
  const [selector, setSelector] = useState('')
  const [selectorError, setSelectorError] = useState<string | null>(null)

  const entry: OsqueryCatalogEntry | undefined = catalog.find((e) => e.id === chosen) ?? catalog[0]
  const catalogReady = !loading && catalogError === null && entry !== undefined
  const running = state.phase === 'running'

  function paramValue(p: OsqueryParam): string {
    return values[p.name] ?? (p.type === 'enum' ? (p.allowedValues[0] ?? '') : '')
  }

  function submit() {
    if (entry === undefined) return
    const trimmed = selector.trim()
    if (trimmed === '') {
      setSelectorError('A selector is required')
      return
    }
    setSelectorError(null)
    const params: Record<string, string> = {}
    for (const p of entry.params) params[p.name] = paramValue(p)
    void run({ catalogId: entry.id, params, selector: trimmed })
  }

  function openInFleet(value: string) {
    outlet?.onSearchChange(value)
    navigate('/')
  }

  const rejected = state.phase === 'rejected'
  const idleResults =
    state.phase === 'idle' ||
    state.phase === 'cancelled' ||
    state.phase === 'rejected' ||
    state.phase === 'forbidden'

  return (
    <>
      <style>{osqueryStyles}</style>
      <div className="htitle">
        <h1>Fleet query</h1>
        <p>
          Run a query from the controller&apos;s catalog on the stewards a selector matches, and read what each one
          returns. Queries are read-only. Each run needs your passkey and is audited.
        </p>
      </div>

      <section className="panel">
        {catalogError !== null && (
          <div className="osq-errcard" data-testid="osq-catalog-error">
            <div className="t">
              <b>Could not load the query catalog.</b>
              <span>Nothing can run until the catalog loads.</span>
            </div>
            <button type="button" className="wf-btn-sm" onClick={retryCatalog} data-testid="osq-catalog-retry">
              Try again
            </button>
          </div>
        )}
        <div className="osq-qform">
          <div className="osq-field">
            <label htmlFor="osq-catalog">Catalog query</label>
            {loading ? (
              <div className="skel" data-testid="osq-catalog-loading" style={{ height: 36, width: '100%' }} />
            ) : catalogError !== null ? (
              <select id="osq-catalog" disabled>
                <option>Catalog not loaded</option>
              </select>
            ) : (
              <select
                id="osq-catalog"
                data-testid="osq-catalog"
                value={entry?.id ?? ''}
                onChange={(e) => {
                  setChosen(e.target.value)
                  setValues({})
                }}
              >
                {catalog.map((c) => (
                  <option key={c.id} value={c.id}>
                    {c.id}
                  </option>
                ))}
              </select>
            )}
          </div>
          <div className="osq-field">
            <span className="osq-lbl">Parameters</span>
            <div className="osq-params">
              {catalogReady && entry.params.length === 0 && (
                <span className="osq-none" data-testid="osq-no-params">
                  This query takes no parameters.
                </span>
              )}
              {catalogReady &&
                entry.params.map((p) => (
                  <ParamInput
                    key={`${entry.id}:${p.name}`}
                    param={p}
                    value={paramValue(p)}
                    onChange={(v) => setValues((prev) => ({ ...prev, [p.name]: v }))}
                  />
                ))}
              {!catalogReady && <span className="osq-none">—</span>}
            </div>
          </div>

          <div className={rejected || selectorError !== null ? 'osq-field full bad' : 'osq-field full'}>
            <span className="osq-lbl">Stewards</span>
            <div className="osq-selbox">
              <SelectorInput
                value={selector}
                onChange={(v) => {
                  setSelector(v)
                  setSelectorError(null)
                }}
                hintId="osq-sel-hint"
                placeholder="Selector, e.g. tag:edge os:linux"
                ariaLabel="Stewards"
              />
            </div>
            {selectorError !== null && (
              <span className="osq-fmsg" role="alert" data-testid="osq-selector-error">
                {selectorError}
              </span>
            )}
            {rejected && (
              <span className="osq-fmsg" role="alert" data-testid="osq-state-rejected">
                The controller rejected this query. Check the selector syntax and the parameter values, then try
                again.
              </span>
            )}
          </div>

          {state.phase === 'cancelled' && (
            <div className="full osq-msg" role="alert" data-testid="osq-state-cancelled">
              <b>Not run.</b> The passkey check was cancelled. Nothing was sent to any steward.
            </div>
          )}
          {state.phase === 'forbidden' && (
            <div className="full osq-msg" role="alert" data-testid="osq-state-forbidden">
              <b>Not run.</b> Target tenant is outside your authorized tenants. Remove the tenant prefix to query
              your whole tenant.
            </div>
          )}
        </div>
        <div className="osq-runbar">
          <span className="osq-hint">Runs on every steward the selector matches. You confirm with your passkey.</span>
          <button
            type="button"
            className="wf-btn-primary"
            disabled={!catalogReady || running}
            onClick={submit}
            data-testid="osq-run-btn"
          >
            {running ? 'Running…' : 'Run query'}
          </button>
        </div>
      </section>

      <section className="panel" aria-label="Results">
        <div className="phead" style={{ padding: '12px 16px', display: 'flex', gap: 12, alignItems: 'center', flexWrap: 'wrap' }}>
          <h2 style={{ margin: 0, fontSize: 'var(--text-lg)' }}>Results</h2>
          {state.phase === 'done' && (
            <span className="osq-ran" data-testid="osq-ran">
              <span className="mono2">{describeRequest(state.request)}</span>
              <span className="mono2">{state.request.selector}</span>
              <span>· ran {new Date(state.ranAt).toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' })}</span>
            </span>
          )}
        </div>

        {state.phase === 'done' && state.results.length > 0 && (
          <Results results={state.results} ranAt={state.ranAt} />
        )}

        {state.phase === 'running' && (
          <div data-testid="osq-running">
            <div className="osq-wait">
              Waiting for every matched steward to answer. Results show together when the last one replies or times
              out.
            </div>
            <div className="osq-list" aria-hidden="true">
              {[60, 52, 56].map((w) => (
                <div className="osq-skcard" key={w}>
                  <div className="skel" style={{ width: 60 }} />
                  <div className="skel" style={{ width: `${w * 5}px`, maxWidth: '70%' }} />
                </div>
              ))}
            </div>
          </div>
        )}

        {idleResults && (
          <div data-testid="osq-results-idle">
            <ResultsNotice icon="◍" title="No results yet">
              <p>Pick a catalog query, enter a selector and run it. Each matched steward gets its own result.</p>
            </ResultsNotice>
          </div>
        )}

        {state.phase === 'done' && state.results.length === 0 && (
          <div data-testid="osq-state-empty">
            <ResultsNotice icon="⌕" title="No stewards matched">
              <p>
                <span className="mono2">{state.request.selector}</span> matched no stewards you can see, so nothing
                ran. Try the same selector in Fleet to see what it matches.
              </p>
              <button
                type="button"
                className="wf-btn-sm"
                onClick={() => openInFleet(state.request.selector)}
                data-testid="osq-open-fleet"
              >
                Open in Fleet
              </button>
            </ResultsNotice>
          </div>
        )}

        {state.phase === 'error' && (
          <div className="osq-errcard" data-testid="osq-state-error">
            <div className="t">
              <b>Could not run the query.</b>
              <span>The controller failed to run the query, so results are not available. Try again in a moment.</span>
            </div>
            <button type="button" className="wf-btn-sm" onClick={submit} data-testid="osq-retry">
              Try again
            </button>
          </div>
        )}

        {state.phase === 'unavailable' && (
          <div className="osq-errcard" data-testid="osq-state-unavailable">
            <div className="t">
              <b>Fleet query is not available.</b>
              <span>This controller is not set up to send queries to stewards. Nothing ran.</span>
            </div>
          </div>
        )}
      </section>
    </>
  )
}
