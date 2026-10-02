// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz

/*
 * Change-timeline evidence card (Story #3611, Epic #2854).
 *
 * Renders one merged, chronologically sorted event stream for the case's
 * pinned subjects:
 *   - entity-graph events from GET /api/v1/entities/timeline (handleGetTimeline
 *     in features/controller/api/handlers_entities.go) for every EID named by
 *     an `eid` or `subject-time-range` pin.
 *   - case events composed client-side from data already on hand — case
 *     creation (via the `caseCreatedAt` prop, Story #3611's addition to the
 *     shared EvidenceCardProps contract, plumbed from the Case object
 *     CockpitView already fetched in Story #3608) and one "pin added" event
 *     per pin. No new endpoint merges these server-side (Out of Scope).
 *
 * Visual design: docs/design/mockups/troubleshooting-cockpit.html
 * §.card.timeline (.tl/.ev event rows). Colour tokens:
 * docs/design/web-ui-design-tokens.css, consumed via ChangeTimelineCard.css.
 * `drift-detected` events get the `.ev.crit` variant; the chronologically
 * most recent event gets the `.ev.now` variant.
 */
import { useEffect, useState } from 'react'
import type { EvidenceCardProps, Pin } from '../evidenceTypes.ts'
import { apiFetch } from '../../api/client.ts'
import './ChangeTimelineCard.css'

// ── API response shape ────────────────────────────────────────────────────────
// Mirrors TimelineEvent (pkg/entitygraph/interfaces/provider.go), serialised by
// writeEntityJSON with no json tags → PascalCase fields. Subject is an EID
// value with a custom MarshalJSON that encodes it as its canonical string form.

interface TimelineEventResponse {
  Subject: string
  OccurredAt: string
  Kind: string // state-change | drift-detected | apply-outcome
  Detail: Record<string, unknown> | null
}

// ── Merged event model ────────────────────────────────────────────────────────

type MergedEventKind =
  | 'state-change'
  | 'drift-detected'
  | 'apply-outcome'
  | 'case-created'
  | 'pin-added'

interface MergedEvent {
  key: string
  occurredAt: string
  kind: MergedEventKind
  title: string
  detail: string
}

type CardPhase =
  | { kind: 'loading' }
  | { kind: 'error'; message: string }
  | { kind: 'ready'; graphEvents: MergedEvent[] }

// ── Helpers ───────────────────────────────────────────────────────────────────

// Pinned subjects: EIDs named directly, or as the subject of a time-range pin.
function extractEIDs(pins: Pin[]): string[] {
  const eids = new Set<string>()
  for (const p of pins) {
    if (p.ref.kind === 'eid' && p.ref.eid) eids.add(p.ref.eid)
    if (p.ref.kind === 'subject-time-range' && p.ref.subject) eids.add(p.ref.subject)
  }
  return Array.from(eids)
}

// Last path segment of an EID string (the entity's local name).
function entityLabel(eid: string): string {
  const slash = eid.lastIndexOf('/')
  return slash >= 0 ? eid.slice(slash + 1) : eid
}

// Map (not a plain object) so lookup by a server-supplied `kind` string never
// trips the object-injection lint sink (security/detect-object-injection).
const GRAPH_KIND_TITLES = new Map<string, string>([
  ['state-change', 'State change'],
  ['drift-detected', 'Drift detected'],
  ['apply-outcome', 'Apply outcome'],
])

function graphEventKind(kind: string): MergedEventKind {
  return kind === 'state-change' || kind === 'drift-detected' || kind === 'apply-outcome'
    ? kind
    : 'state-change'
}

function graphEventTitle(kind: string, subject: string): string {
  const base = GRAPH_KIND_TITLES.get(kind) ?? kind
  return `${base} on ${entityLabel(subject)}`
}

// Detail is an untyped Go map[string]interface{} — no fixed schema is
// guaranteed, so render it as a sorted "key: value" strip rather than
// assuming specific field names.
function formatGraphDetail(detail: Record<string, unknown> | null): string {
  if (!detail) return ''
  return Object.entries(detail)
    .sort(([a], [b]) => a.localeCompare(b))
    .map(([k, v]) => `${k}: ${String(v)}`)
    .join(' · ')
}

// Coerce one element of the /timeline response array. Elements missing the
// required string fields are dropped by normalizeTimelineEvents rather than
// thrown on, mirroring DriftDiffCard's toDriftField boundary handling.
function toTimelineEvent(raw: unknown): TimelineEventResponse | null {
  if (typeof raw !== 'object' || raw === null) return null
  const e = raw as Partial<TimelineEventResponse>
  if (
    typeof e.Subject !== 'string' ||
    typeof e.OccurredAt !== 'string' ||
    typeof e.Kind !== 'string'
  ) {
    return null
  }
  return {
    Subject: e.Subject,
    OccurredAt: e.OccurredAt,
    Kind: e.Kind,
    Detail: typeof e.Detail === 'object' && e.Detail !== null ? e.Detail : null,
  }
}

// GetTimeline's []*TimelineEvent serialises as `null` for a nil slice — guard
// against a TypeError blanking the cockpit (no ErrorBoundary in this SPA).
function normalizeTimelineEvents(raw: unknown): TimelineEventResponse[] {
  return Array.isArray(raw)
    ? raw.map(toTimelineEvent).filter((e): e is TimelineEventResponse => e !== null)
    : []
}

function buildGraphEvents(raw: TimelineEventResponse[]): MergedEvent[] {
  return raw.map((e, i) => ({
    key: `graph-${i}-${e.Subject}-${e.OccurredAt}`,
    occurredAt: e.OccurredAt,
    kind: graphEventKind(e.Kind),
    title: graphEventTitle(e.Kind, e.Subject),
    detail: formatGraphDetail(e.Detail),
  }))
}

// Describes what a pin anchors, for the "pin added" event detail line.
// Falls back to the pin's own annotation when present.
function pinAddedDetail(pin: Pin): string {
  if (pin.annotation) return pin.annotation
  switch (pin.ref.kind) {
    case 'eid':
      return pin.ref.eid ? entityLabel(pin.ref.eid) : ''
    case 'subject-time-range':
      return pin.ref.subject ? entityLabel(pin.ref.subject) : ''
    case 'drift-record':
      return pin.ref.drift_record ?? ''
    case 'edge-identity':
      return pin.ref.edge_identity ?? ''
    case 'observation-version':
      return pin.ref.observation_version ?? ''
    default:
      return ''
  }
}

function buildCaseEvents(pins: Pin[], caseCreatedAt: string | undefined): MergedEvent[] {
  const events: MergedEvent[] = []
  if (caseCreatedAt) {
    events.push({
      key: 'case-created',
      occurredAt: caseCreatedAt,
      kind: 'case-created',
      title: 'Case created',
      detail: '',
    })
  }
  for (const pin of pins) {
    events.push({
      key: `pin-added-${pin.id}`,
      occurredAt: pin.pinned_at,
      kind: 'pin-added',
      title: 'Pin added',
      detail: pinAddedDetail(pin),
    })
  }
  return events
}

function mergeAndSort(graphEvents: MergedEvent[], caseEvents: MergedEvent[]): MergedEvent[] {
  return [...graphEvents, ...caseEvents].sort(
    (a, b) => new Date(a.occurredAt).getTime() - new Date(b.occurredAt).getTime(),
  )
}

// Earliest known timestamp across the case and its pins — used as the
// GetTimeline query's "from" bound when the case has one.
function earliestTimestamp(pins: Pin[], caseCreatedAt: string | undefined): string {
  const candidates = [caseCreatedAt, ...pins.map((p) => p.pinned_at)].filter(
    (v): v is string => typeof v === 'string' && v !== '',
  )
  if (candidates.length === 0) {
    return new Date(Date.now() - 24 * 60 * 60 * 1000).toISOString()
  }
  return candidates.reduce((min, v) => (new Date(v) < new Date(min) ? v : min))
}

function formatTime(iso: string): string {
  const d = new Date(iso)
  if (Number.isNaN(d.getTime())) return '—'
  return d.toLocaleTimeString(undefined, { hour: '2-digit', minute: '2-digit' })
}

// ── Component ─────────────────────────────────────────────────────────────────

export default function ChangeTimelineCard({ pins, caseCreatedAt }: EvidenceCardProps) {
  const eids = extractEIDs(pins)
  const eidsKey = eids.join(',')
  // Derived primitive (not the `pins` array reference) so the fetch effect
  // only re-triggers when the query's actual inputs change — mirrors
  // DriftDiffCard's pattern of depending on derived values, not raw props.
  const fromParam = earliestTimestamp(pins, caseCreatedAt)

  const hasSubjects = eidsKey !== ''

  // `phase` only matters while `hasSubjects` is true — the render path below
  // never reads it otherwise, so there is no need to synchronize it back to
  // 'ready' when there are no pinned subjects to query.
  const [phase, setPhase] = useState<CardPhase>({ kind: 'loading' })

  useEffect(() => {
    if (!hasSubjects) return

    // Recomputed from eidsKey (an effect dependency) rather than closing over
    // the outer `eids` array, so this effect only depends on primitives.
    const eidsList = eidsKey.split(',')
    let cancelled = false

    const params = new URLSearchParams()
    for (const eid of eidsList) params.append('eid', eid)
    params.set('from', fromParam)
    params.set('to', new Date().toISOString())
    const path = `/api/v1/entities/timeline?${params.toString()}`

    async function fetchData(): Promise<void> {
      try {
        const res = await apiFetch(path)
        if (cancelled) return
        if (!res.ok) {
          throw new Error(`GET ${path} — ${res.status}`)
        }
        const graphEvents = buildGraphEvents(normalizeTimelineEvents(await res.json()))
        if (!cancelled) {
          setPhase({ kind: 'ready', graphEvents })
        }
      } catch (err) {
        if (!cancelled) {
          setPhase({
            kind: 'error',
            message: err instanceof Error ? err.message : 'Failed to load timeline',
          })
        }
      }
    }

    void fetchData()

    return () => {
      cancelled = true
    }
  }, [hasSubjects, eidsKey, fromParam])

  if (hasSubjects && phase.kind === 'error') {
    return (
      <section className="change-timeline-card change-timeline-card--error" aria-label="Change timeline">
        <h3 className="change-timeline-card__header">
          <span>Change timeline</span>
        </h3>
        <p className="change-timeline-card__error">{phase.message}</p>
      </section>
    )
  }

  if (hasSubjects && phase.kind === 'loading') {
    return (
      <section className="change-timeline-card" aria-label="Change timeline">
        <h3 className="change-timeline-card__header">
          <span>Change timeline</span>
        </h3>
        <p className="change-timeline-card__loading" aria-label="Loading timeline">
          Loading…
        </p>
      </section>
    )
  }

  const graphEvents = hasSubjects && phase.kind === 'ready' ? phase.graphEvents : []
  const merged = mergeAndSort(graphEvents, buildCaseEvents(pins, caseCreatedAt))

  if (merged.length === 0) {
    return (
      <section className="change-timeline-card change-timeline-card--empty" aria-label="Change timeline">
        <h3 className="change-timeline-card__header">
          <span>Change timeline</span>
        </h3>
        <p className="change-timeline-card__empty">No timeline events yet.</p>
      </section>
    )
  }

  const lastKey = merged[merged.length - 1]!.key

  return (
    <section className="change-timeline-card" aria-label="Change timeline">
      <h3 className="change-timeline-card__header">
        <span>Change timeline</span>
      </h3>
      <div className="change-timeline-card__list">
        {merged.map((ev) => {
          const classes = ['change-timeline-card__event']
          if (ev.kind === 'drift-detected') classes.push('change-timeline-card__event--crit')
          if (ev.key === lastKey) classes.push('change-timeline-card__event--now')
          return (
            <div key={ev.key} className={classes.join(' ')}>
              <span className="change-timeline-card__time">{formatTime(ev.occurredAt)}</span>
              <span className="change-timeline-card__marker" aria-hidden="true" />
              <p className="change-timeline-card__body">
                <b>{ev.title}</b>
                {ev.detail && (
                  <>
                    <br />
                    <small>{ev.detail}</small>
                  </>
                )}
              </p>
            </div>
          )
        })}
      </div>
    </section>
  )
}
