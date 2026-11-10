// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz

/*
 * Assert-relationship drawer (Story #5464, Epic #5300).
 *
 * Opened from the "Assert relationship" action in the case blast-radius card
 * (web/src/cockpit/cards/BlastRadiusCard.tsx); no route of its own. The card's
 * pinned entity is pre-filled and locked as From, with a Swap direction control
 * that moves it to To. The other endpoint comes from a tenant-scoped search:
 *   GET /api/v1/entities?text_query=&kind=&page_size=
 * and the assertion goes through useAssertEdge (POST /api/v1/entities/edges,
 * 201 with no body). `entity:write` asks for no step-up or presence tap.
 *
 * Visual design: docs/design/mockups/entity-edge-assert.html (every state on its
 * state strip, both themes). Colours are tokens only —
 * docs/design/web-ui-design-tokens.css — so both themes follow the token file.
 * The drawer chrome reuses the fleet drawer's `.det` / `.dh` / `.db` classes.
 *
 * Every value is rendered as a text node; entity IDs and names come from the
 * server and are never interpreted as markup.
 */
import { useEffect, useRef, useState, type CSSProperties, type ReactNode } from 'react'
import { createPortal } from 'react-dom'
import { apiFetch } from '../api/client.ts'
import '../fleet/FleetOverview.css'
import {
  containsPipe,
  PIPE_MESSAGE,
  useAssertEdge,
  type AssertEdgeState,
} from './useAssertEdge.ts'

// The standard edge types (egtypes.DefaultTaxonomy, ADR-022 §2) plus the
// related:<name> open subtype.
const STANDARD_EDGE_TYPES = [
  'contains',
  'runs-on',
  'member-of',
  'depends-on',
  'serves',
  'connects-to',
  'manages',
  'managed-by',
  'assigned-to',
  'delegated-access',
  'reports-to',
  'same-as',
] as const
const CUSTOM = 'related'
const KINDS = ['host', 'vm', 'service', 'user', 'group', 'application'] as const
const SEARCH_PAGE_SIZE = 20
const SEARCH_DEBOUNCE_MS = 250
const MAX_ATTRIBUTES = 32

interface EntityRef {
  eid: string
  kind: string
}

interface AttrRow {
  id: number
  key: string
  value: string
}

type SearchState =
  | { kind: 'idle' }
  | { kind: 'loading' }
  | { kind: 'error'; message: string }
  | { kind: 'ready'; results: EntityRef[] }

interface Recorded {
  from: string
  to: string
  edgeType: string
  attributes: Record<string, string>
}

// ── Helpers ───────────────────────────────────────────────────────────────────

// Last path segment of the EID string (the entity's local name).
function entityLabel(eid: string): string {
  const slash = eid.lastIndexOf('/')
  const tail = slash >= 0 ? eid.slice(slash + 1) : eid
  const colon = tail.lastIndexOf(':')
  return colon >= 0 && colon < tail.length - 1 ? tail.slice(colon + 1) : tail
}

// Normalise the GET /api/v1/entities page (Go field names, writeEntityJSON).
function normalizeEntities(raw: unknown): EntityRef[] {
  const page = (typeof raw === 'object' && raw !== null ? raw : {}) as { Entities?: unknown }
  if (!Array.isArray(page.Entities)) return []
  const out: EntityRef[] = []
  for (const view of page.Entities) {
    const entity = (view as { Entity?: { EID?: unknown; Kind?: unknown } } | null)?.Entity
    if (entity && typeof entity.EID === 'string') {
      out.push({ eid: entity.EID, kind: typeof entity.Kind === 'string' ? entity.Kind : '' })
    }
  }
  return out
}

// The outcome is stored against the request it answers; a stale or missing
// outcome reads as "loading", so no state is set synchronously in the effect.
function useEntitySearch(query: string, kind: string, exclude: string): SearchState {
  const [settled, setSettled] = useState<{ key: string; result: SearchState } | null>(null)
  const trimmed = query.trim()
  const key = JSON.stringify([trimmed, kind, exclude])

  useEffect(() => {
    if (trimmed === '') return
    let cancelled = false
    const timer = setTimeout(() => {
      const params = new URLSearchParams({ text_query: trimmed })
      if (kind !== '') params.set('kind', kind)
      params.set('page_size', String(SEARCH_PAGE_SIZE))
      apiFetch(`/api/v1/entities?${params.toString()}`)
        .then(async (res) => {
          if (!res.ok) throw new Error(`${res.status}`)
          return normalizeEntities(await res.json())
        })
        .then(
          (results): SearchState => ({ kind: 'ready', results: results.filter((r) => r.eid !== exclude) }),
          (err: unknown): SearchState => ({
            kind: 'error',
            message: err instanceof Error && err.message ? err.message : 'request failed',
          }),
        )
        .then((result) => {
          if (!cancelled) setSettled({ key, result })
        })
    }, SEARCH_DEBOUNCE_MS)
    return () => {
      cancelled = true
      clearTimeout(timer)
    }
  }, [trimmed, kind, exclude, key])

  if (trimmed === '') return { kind: 'idle' }
  return settled !== null && settled.key === key ? settled.result : { kind: 'loading' }
}

// ── Styles (tokens only) ──────────────────────────────────────────────────────

const S: Record<string, CSSProperties> = {
  body: { flex: 1, overflow: 'auto', padding: 'var(--space-4)', display: 'flex', flexDirection: 'column', gap: 'var(--space-4)' },
  foot: { borderTop: '1px solid var(--border)', padding: '12px var(--space-4)', display: 'flex', flexDirection: 'column', gap: 'var(--space-3)' },
  acts: { display: 'flex', gap: 8, justifyContent: 'flex-end', alignItems: 'center' },
  field: { display: 'flex', flexDirection: 'column', gap: 6, minWidth: 0 },
  lbl: { fontSize: 'var(--text-xs)', letterSpacing: 'var(--tracking-label)', textTransform: 'uppercase', color: 'var(--text-faint)', fontWeight: 600, display: 'flex', alignItems: 'center', gap: 8 },
  lblEnd: { marginLeft: 'auto', textTransform: 'none', letterSpacing: 0, fontWeight: 500 },
  req: { color: 'var(--state-crit)' },
  input: { width: '100%', minWidth: 0, background: 'var(--bg-surface)', color: 'var(--text-primary)', border: '1px solid var(--border)', borderRadius: 'var(--radius)', padding: '8px 11px', font: 'inherit', fontSize: 'var(--text-base)' },
  inputBad: { borderColor: 'var(--state-crit)' },
  hint: { fontSize: 'var(--text-sm)', color: 'var(--text-faint)' },
  ferr: { fontSize: 'var(--text-sm)', color: 'var(--state-crit)', fontWeight: 600 },
  prefixed: { display: 'flex', alignItems: 'stretch', border: '1px solid var(--border)', borderRadius: 'var(--radius)', overflow: 'hidden', background: 'var(--bg-surface)' },
  prefix: { display: 'flex', alignItems: 'center', padding: '0 9px', background: 'var(--bg-sunk)', color: 'var(--text-secondary)', fontFamily: 'var(--font-mono)', fontSize: 12.5, borderRight: '1px solid var(--border)' },
  prefixInput: { border: 0, borderRadius: 0, fontFamily: 'var(--font-mono)', fontSize: 12.5 },
  ent: { display: 'flex', alignItems: 'center', gap: 10, padding: '9px 11px', border: '1px solid var(--border)', borderRadius: 'var(--radius)', background: 'var(--bg-sunk)' },
  entBad: { borderColor: 'var(--state-crit)' },
  entTx: { display: 'flex', flexDirection: 'column', minWidth: 0, flex: 1 },
  eid: { fontFamily: 'var(--font-mono)', fontSize: 11, color: 'var(--text-secondary)', overflowWrap: 'anywhere' },
  picker: { border: '1px solid var(--border)', borderRadius: 'var(--radius)', background: 'var(--bg-surface)', overflow: 'hidden' },
  pickerQ: { display: 'flex', gap: 8, padding: 8, borderBottom: '1px solid var(--border)' },
  pickerMsg: { padding: '14px 12px', fontSize: 'var(--text-sm)', color: 'var(--text-faint)' },
  res: { listStyle: 'none', margin: 0, padding: 0, maxHeight: 220, overflow: 'auto' },
  resItem: { display: 'flex', alignItems: 'center', gap: 10, padding: '8px 12px', cursor: 'pointer', borderTop: '1px solid var(--border)' },
  resOn: { background: 'var(--tint-blue)' },
  preview: { display: 'flex', alignItems: 'center', flexWrap: 'wrap', gap: 8, padding: '10px 12px', border: '1px dashed var(--border)', borderRadius: 'var(--radius)', fontFamily: 'var(--font-mono)', fontSize: 12.5 },
  attrRow: { display: 'grid', gridTemplateColumns: '1fr 1.4fr auto', gap: 6, alignItems: 'center' },
  msg: { display: 'flex', gap: 10, padding: '10px 12px', border: '1px solid var(--border)', borderRadius: 'var(--radius)', background: 'var(--bg-sunk)', fontSize: 'var(--text-sm)' },
  msgCrit: { borderColor: 'var(--state-crit)', background: 'var(--state-crit-bg)' },
  msgWarn: { borderColor: 'var(--state-warn)', background: 'var(--state-warn-bg)' },
  code: { display: 'block', fontFamily: 'var(--font-mono)', fontSize: 11, color: 'var(--text-secondary)', marginTop: 4 },
  swap: { display: 'flex', justifyContent: 'flex-start' },
  done: { display: 'flex', flexDirection: 'column', gap: 'var(--space-4)' },
  edgeviz: { display: 'flex', alignItems: 'center', gap: 12, flexWrap: 'wrap', padding: 12, border: '1px solid var(--border)', borderRadius: 'var(--radius)', background: 'var(--bg-sunk)' },
  linkBtn: { appearance: 'none', border: 0, background: 'transparent', color: 'var(--accent)', font: 'inherit', fontSize: 'var(--text-sm)', cursor: 'pointer' },
  kind: { fontSize: 11, padding: '1px 8px', borderRadius: 20, background: 'var(--bg-sunk)', border: '1px solid var(--border)', color: 'var(--text-secondary)' },
}

const BTN: CSSProperties = {
  font: 'inherit',
  fontSize: 'var(--text-sm)',
  fontWeight: 600,
  padding: '7px 14px',
  borderRadius: 'var(--radius)',
  cursor: 'pointer',
  border: '1px solid var(--border)',
  background: 'var(--bg-surface)',
  color: 'var(--text-primary)',
}
const BTN_PRIMARY: CSSProperties = { ...BTN, background: 'var(--accent)', borderColor: 'var(--accent)', color: 'var(--accent-ink)' }

function Btn({
  primary,
  disabled,
  onClick,
  children,
  small,
}: {
  primary?: boolean
  disabled?: boolean
  onClick?: () => void
  children: ReactNode
  small?: boolean
}) {
  const style: CSSProperties = {
    ...(primary ? BTN_PRIMARY : BTN),
    ...(small ? { padding: '4px 10px' } : {}),
    ...(disabled ? { opacity: 0.55, cursor: 'not-allowed' } : {}),
  }
  return (
    <button type="button" style={style} disabled={disabled} onClick={onClick}>
      {children}
    </button>
  )
}

function EntityCard({ eid, kind, bad, right }: { eid: string; kind?: string; bad?: boolean; right?: ReactNode }) {
  return (
    <div style={{ ...S.ent, ...(bad ? S.entBad : {}) }}>
      <span style={S.entTx}>
        <b>
          {entityLabel(eid)}
          {kind ? (
            <>
              {' '}
              <span style={S.kind}>{kind}</span>
            </>
          ) : null}
        </b>
        <span style={S.eid}>{eid}</span>
      </span>
      {right}
    </div>
  )
}

// ── Failure message (cross-tenant 404, crossing 401, validation, server) ──────

function Failure({
  state,
  onChooseAnother,
  onRetry,
}: {
  state: AssertEdgeState
  onChooseAnother: () => void
  onRetry: () => void
}) {
  if (state.kind === 'not-found') {
    return (
      <div role="alert" style={{ ...S.msg, ...S.msgCrit }}>
        <span>
          <b>One of these entities isn’t in a tenant you can reach.</b>
          <p style={{ margin: '4px 0 0' }}>
            It may have been removed, or it belongs to a tenant outside yours. The controller doesn’t say which
            entity or why, so it never reveals another tenant’s entities. Nothing was recorded.
          </p>
          <span style={S.code}>404 · not found</span>
          <span style={{ display: 'block', marginTop: 8 }}>
            <Btn small onClick={onChooseAnother}>
              Choose another entity
            </Btn>
          </span>
        </span>
      </div>
    )
  }
  if (state.kind === 'crossing') {
    return (
      <div role="alert" style={{ ...S.msg, ...S.msgWarn }}>
        <span>
          <b>{state.tenantId ? `This link reaches into ${state.tenantId}.` : 'This link reaches into another tenant.'}</b>
          <p style={{ margin: '4px 0 0' }}>
            Linking an entity under that tenant needs support access from its MSP, or break-glass. Nothing was
            recorded.
          </p>
          <span style={S.code}>401 · tenant_crossing_required</span>
          <span style={{ display: 'block', marginTop: 8 }}>
            <Btn small onClick={onRetry}>
              Request access…
            </Btn>
          </span>
        </span>
      </div>
    )
  }
  if (state.kind === 'invalid') {
    return (
      <div role="alert" style={{ ...S.msg, ...S.msgCrit }}>
        <span>
          <b>The relationship wasn’t recorded.</b>
          <p style={{ margin: '4px 0 0' }}>{state.message}</p>
          <span style={S.code}>400 · invalid</span>
        </span>
      </div>
    )
  }
  if (state.kind === 'error') {
    return (
      <div role="alert" style={{ ...S.msg, ...S.msgCrit }}>
        <span>
          <b>The relationship wasn’t recorded.</b>
          <p style={{ margin: '4px 0 0' }}>
            The controller couldn’t complete the request. Your entries are kept; try again in a moment.
          </p>
          <span style={S.code}>
            {state.status > 0 ? `${state.status} · ` : ''}
            {state.message}
          </span>
        </span>
      </div>
    )
  }
  return null
}

// ── Form ──────────────────────────────────────────────────────────────────────

export interface AssertEdgeFormProps {
  /** The case's pinned entity, locked as From (To after Swap direction). */
  fromEid: string
  /** Kind of the pinned entity, when the caller knows it. */
  fromKind?: string
  onClose: () => void
  /** Called once the controller has recorded the edge (201). */
  onAsserted: () => void
}

export default function AssertEdgeForm({ fromEid, fromKind, onClose, onAsserted }: AssertEdgeFormProps) {
  const { state, assertEdge, reset } = useAssertEdge()
  const [swapped, setSwapped] = useState(false)
  const [edgeChoice, setEdgeChoice] = useState('')
  const [customName, setCustomName] = useState('')
  const [query, setQuery] = useState('')
  const [kind, setKind] = useState('')
  const [other, setOther] = useState<EntityRef | null>(null)
  const [attrs, setAttrs] = useState<AttrRow[]>([])
  const [nextAttrId, setNextAttrId] = useState(1)
  const [recorded, setRecorded] = useState<Recorded | null>(null)
  const edgeRef = useRef<HTMLSelectElement>(null)

  const submitting = state.kind === 'submitting'
  const search = useEntitySearch(query, kind, fromEid)

  useEffect(() => {
    edgeRef.current?.focus()
  }, [])

  useEffect(() => {
    function onKey(e: KeyboardEvent) {
      if (e.key === 'Escape' && !submitting) onClose()
    }
    document.addEventListener('keydown', onKey)
    return () => document.removeEventListener('keydown', onKey)
  }, [onClose, submitting])

  // A failure message describes the previous entries; any edit clears it.
  function edited() {
    if (state.kind !== 'idle' && state.kind !== 'submitting' && state.kind !== 'success') reset()
  }

  const customTrimmed = customName.trim()
  const edgeType = edgeChoice === CUSTOM ? (customTrimmed === '' ? '' : `related:${customTrimmed}`) : edgeChoice
  const customPipe = edgeChoice === CUSTOM && containsPipe(customName)
  const otherPipe = other !== null && containsPipe(other.eid)
  const attributes: Record<string, string> = {}
  for (const row of attrs) {
    if (row.key.trim() !== '') attributes[row.key.trim()] = row.value
  }

  const complete = edgeType !== '' && other !== null
  // A not-found refusal stays until another entity is chosen (mockup: submit disabled).
  const blocked = state.kind === 'not-found'
  const canSubmit = complete && !customPipe && !otherPipe && !submitting && !blocked

  const fromSide = swapped ? other?.eid ?? '' : fromEid
  const toSide = swapped ? fromEid : other?.eid ?? ''

  // Submit, and retry after a failure: a crossing retry runs the central
  // crossing prompt again inside apiFetch.
  async function submit() {
    if (!canSubmit) return
    const outcome = await assertEdge({ edgeType, fromEid: fromSide, toEid: toSide, attributes })
    if (outcome.kind === 'success') {
      setRecorded({ from: fromSide, to: toSide, edgeType, attributes })
      onAsserted()
    }
  }

  function again() {
    reset()
    setRecorded(null)
    setSwapped(false)
    setEdgeChoice('')
    setCustomName('')
    setQuery('')
    setKind('')
    setOther(null)
    setAttrs([])
  }

  const pinnedSlot = (label: string) => (
    <div style={S.field}>
      <span style={S.lbl}>
        {label}
        <span style={S.lblEnd}>pinned on this case</span>
      </span>
      <EntityCard eid={fromEid} kind={fromKind} />
    </div>
  )

  const otherSlot = (label: string) =>
    other !== null ? (
      <div style={S.field}>
        <span style={S.lbl}>
          {label} <span style={S.req}>*</span>
        </span>
        <EntityCard
          eid={other.eid}
          kind={other.kind}
          bad={otherPipe}
          right={
            submitting ? null : (
              <button
                type="button"
                style={S.linkBtn}
                onClick={() => {
                  edited()
                  setOther(null)
                }}
              >
                Change
              </button>
            )
          }
        />
        {otherPipe && (
          <span role="alert" style={S.ferr}>
            This entity’s ID contains the | character, which the controller reserves, so it can’t be used in a
            relationship.
          </span>
        )}
      </div>
    ) : (
      <div style={S.field}>
        <span style={S.lbl}>
          {label} <span style={S.req}>*</span>
          <span style={S.lblEnd}>entities in your tenants</span>
        </span>
        <div style={S.picker}>
          <div style={S.pickerQ}>
            <input
              type="text"
              style={S.input}
              placeholder="Search by name or paste an entity ID"
              aria-label="Search entities"
              value={query}
              onChange={(e) => setQuery(e.target.value)}
            />
            <select
              style={{ ...S.input, width: 'auto' }}
              aria-label="Kind"
              value={kind}
              onChange={(e) => setKind(e.target.value)}
            >
              <option value="">Any kind</option>
              {KINDS.map((k) => (
                <option key={k} value={k}>
                  {k}
                </option>
              ))}
            </select>
          </div>
          {search.kind === 'idle' && <div style={S.pickerMsg}>Type to search the knowledge graph.</div>}
          {search.kind === 'loading' && <div style={S.pickerMsg}>Searching…</div>}
          {search.kind === 'error' && (
            <div style={{ ...S.pickerMsg, color: 'var(--state-crit)' }}>
              Search failed ({search.message}). Change the search to try again.
            </div>
          )}
          {search.kind === 'ready' && search.results.length === 0 && (
            <div style={S.pickerMsg}>No matching entities.</div>
          )}
          {search.kind === 'ready' && search.results.length > 0 && (
            <ul style={S.res} role="listbox" aria-label="Matching entities">
              {search.results.map((r) => (
                <li
                  key={r.eid}
                  role="option"
                  aria-selected="false"
                  tabIndex={0}
                  style={S.resItem}
                  onClick={() => {
                    edited()
                    setOther(r)
                  }}
                  onKeyDown={(e) => {
                    if (e.key === 'Enter' || e.key === ' ') {
                      e.preventDefault()
                      edited()
                      setOther(r)
                    }
                  }}
                >
                  <span style={S.entTx}>
                    <b>
                      {entityLabel(r.eid)}{' '}
                      {r.kind ? <span style={S.kind}>{r.kind}</span> : null}
                    </b>
                    <span style={S.eid}>{r.eid}</span>
                  </span>
                </li>
              ))}
            </ul>
          )}
        </div>
      </div>
    )

  const heading = (
    <div className="dh">
      <div className="nm" style={{ whiteSpace: 'normal' }}>
        <h2 id="assert-edge-title" style={{ margin: 0, fontSize: 15 }}>
          Assert relationship
        </h2>
        <p style={{ margin: '2px 0 0', fontSize: 'var(--text-sm)', color: 'var(--text-faint)' }}>
          Adds a typed link between two entities in the knowledge graph.
        </p>
      </div>
      <button
        type="button"
        className="icobtn x"
        style={{ width: 30, height: 30, marginLeft: 'auto' }}
        aria-label="Close"
        onClick={onClose}
        disabled={submitting}
      >
        <svg width="15" height="15" viewBox="0 0 24 24" fill="none" aria-hidden="true">
          <path d="M6 6l12 12M18 6L6 18" stroke="currentColor" strokeWidth="1.8" strokeLinecap="round" />
        </svg>
      </button>
    </div>
  )

  let content: ReactNode
  if (recorded !== null) {
    const rows = Object.entries(recorded.attributes)
    content = (
      <>
        <div className="db" style={S.body}>
          <div style={S.done}>
            <div>
              <h3 style={{ margin: 0 }}>Relationship recorded</h3>
              <p style={{ margin: '4px 0 0', color: 'var(--text-secondary)' }}>
                The blast-radius card now shows the new link.
              </p>
            </div>
            <div style={S.edgeviz} data-testid="assert-recorded">
              <span style={S.entTx}>
                <b>{entityLabel(recorded.from)}</b>
                <span style={S.eid}>{recorded.from}</span>
              </span>
              <span style={{ fontFamily: 'var(--font-mono)', color: 'var(--accent)' }}>— {recorded.edgeType} →</span>
              <span style={S.entTx}>
                <b>{entityLabel(recorded.to)}</b>
                <span style={S.eid}>{recorded.to}</span>
              </span>
            </div>
            {rows.length > 0 && (
              <dl style={{ margin: 0, display: 'grid', gridTemplateColumns: 'auto 1fr', gap: '4px 12px' }}>
                {rows.map(([k, v]) => (
                  <div key={k} style={{ display: 'contents' }}>
                    <dt style={{ color: 'var(--text-faint)' }}>{k}</dt>
                    <dd style={{ margin: 0, overflowWrap: 'anywhere' }}>{v}</dd>
                  </div>
                ))}
              </dl>
            )}
          </div>
        </div>
        <div style={S.foot}>
          <div style={S.acts}>
            <Btn onClick={again}>Assert another</Btn>
            <Btn primary onClick={onClose}>
              Done
            </Btn>
          </div>
        </div>
      </>
    )
  } else {
    const dis = submitting
    content = (
      <>
        <div className="db" style={S.body}>
          {swapped ? otherSlot('From') : pinnedSlot('From')}
          <div style={S.swap}>
            <Btn
              small
              disabled={dis}
              onClick={() => {
                edited()
                setSwapped((v) => !v)
              }}
            >
              ⇅ Swap direction
            </Btn>
          </div>
          {swapped ? pinnedSlot('To') : otherSlot('To')}

          <div style={S.field}>
            <label style={S.lbl} htmlFor="assert-edge-type">
              Relationship <span style={S.req}>*</span>
            </label>
            <select
              id="assert-edge-type"
              ref={edgeRef}
              style={S.input}
              value={edgeChoice}
              disabled={dis}
              onChange={(e) => {
                edited()
                setEdgeChoice(e.target.value)
              }}
            >
              <option value="">Choose a relationship…</option>
              {STANDARD_EDGE_TYPES.map((t) => (
                <option key={t} value={t}>
                  {t}
                </option>
              ))}
              <option value={CUSTOM}>related:&lt;name&gt; — your own type</option>
            </select>
            {edgeChoice === CUSTOM && (
              <>
                <div style={{ ...S.prefixed, ...(customPipe ? S.inputBad : {}) }}>
                  <span style={S.prefix}>related:</span>
                  <input
                    type="text"
                    style={{ ...S.input, ...S.prefixInput }}
                    aria-label="Custom relationship name"
                    value={customName}
                    disabled={dis}
                    aria-invalid={customPipe ? true : undefined}
                    aria-describedby={customPipe ? 'assert-edge-pipe' : undefined}
                    onChange={(e) => {
                      edited()
                      setCustomName(e.target.value)
                    }}
                  />
                </div>
                {customPipe ? (
                  <span id="assert-edge-pipe" role="alert" style={S.ferr}>
                    {PIPE_MESSAGE}
                  </span>
                ) : (
                  <span style={S.hint}>
                    Lower-case name for a link the standard types don’t cover, e.g.{' '}
                    <code>related:backs-up</code>.
                  </span>
                )}
              </>
            )}
          </div>

          <div style={S.preview} data-testid="assert-preview">
            <span style={{ ...S.lbl, marginRight: 4 }}>Will record</span>
            {fromSide !== '' ? <b>{entityLabel(fromSide)}</b> : <span style={{ color: 'var(--text-faint)' }}>choose an entity</span>}
            <span style={{ color: 'var(--accent)' }}>— {edgeType || 'relationship'} →</span>
            {toSide !== '' ? <b>{entityLabel(toSide)}</b> : <span style={{ color: 'var(--text-faint)' }}>choose an entity</span>}
          </div>

          <div style={S.field}>
            <span style={S.lbl}>
              Attributes <span style={{ ...S.lblEnd, marginLeft: 0 }}>optional</span>
            </span>
            {attrs.map((row) => (
              <div key={row.id} style={S.attrRow}>
                <input
                  type="text"
                  style={S.input}
                  aria-label="Attribute key"
                  value={row.key}
                  disabled={dis}
                  onChange={(e) => setAttrs((rs) => rs.map((r) => (r.id === row.id ? { ...r, key: e.target.value } : r)))}
                />
                <input
                  type="text"
                  style={S.input}
                  aria-label="Attribute value"
                  value={row.value}
                  disabled={dis}
                  onChange={(e) => setAttrs((rs) => rs.map((r) => (r.id === row.id ? { ...r, value: e.target.value } : r)))}
                />
                <button
                  type="button"
                  className="icobtn"
                  aria-label="Remove attribute"
                  disabled={dis}
                  onClick={() => setAttrs((rs) => rs.filter((r) => r.id !== row.id))}
                >
                  ×
                </button>
              </div>
            ))}
            <div>
              <Btn
                small
                disabled={dis || attrs.length >= MAX_ATTRIBUTES}
                onClick={() => {
                  setAttrs((rs) => [...rs, { id: nextAttrId, key: '', value: '' }])
                  setNextAttrId((n) => n + 1)
                }}
              >
                + Add attribute
              </Btn>
            </div>
            <span style={S.hint}>
              Up to {MAX_ATTRIBUTES}. Keys the controller manages itself, such as <code>tenant_path</code> or{' '}
              <code>hostname</code>, are refused.
            </span>
          </div>

          <div style={S.msg}>
            <span>
              <b>No passkey needed.</b> Recorded as an operator assertion by you, in the audit log of each tenant
              involved. Observations from stewards and directories outrank it.
            </span>
          </div>
        </div>
        <div style={S.foot}>
          <Failure
            state={state}
            onChooseAnother={() => {
              setOther(null)
              reset()
            }}
            onRetry={() => void submit()}
          />
          <div style={S.acts}>
            <Btn disabled={dis} onClick={onClose}>
              Cancel
            </Btn>
            <Btn primary disabled={!canSubmit} onClick={() => void submit()}>
              {dis ? 'Asserting…' : state.kind === 'error' ? 'Try again' : 'Assert relationship'}
            </Btn>
          </div>
        </div>
      </>
    )
  }

  return createPortal(
    <>
      <div className="scrim det-scrim" data-testid="assert-scrim" aria-hidden="true" onClick={() => !submitting && onClose()} />
      <aside
        className="det"
        role="dialog"
        aria-modal="true"
        aria-labelledby="assert-edge-title"
        style={{ width: 460 }}
      >
        {heading}
        {content}
      </aside>
    </>,
    document.body,
  )
}
