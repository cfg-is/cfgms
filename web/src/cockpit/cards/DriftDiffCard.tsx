// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz

/*
 * Drift-diff hero evidence card (Story #3609, Epic #2854).
 *
 * Renders desired-vs-actual state for a pinned entity, fetching from:
 *   GET /api/v1/entities/{eid}/drift        — DriftState with per-field comparison
 *   GET /api/v1/entities/{eid}/desired-state — DesiredStateView for the revision label
 *
 * The component looks for a drift-record pin first (direct drift evidence), then
 * falls back to an eid pin (fallback: calls /drift to check whether drift exists
 * and renders nothing if the endpoint returns 404). If neither pin kind is present,
 * or if no EID can be derived, the component renders null.
 *
 * Visual design: docs/design/mockups/troubleshooting-cockpit.html §.card.diff.
 * Colour tokens: docs/design/web-ui-design-tokens.css — bad fields use
 * --state-crit / --state-crit-bg (class "bad"), good fields use --state-ok (class
 * "good"). Tokens are consumed via DriftDiffCard.css.
 */
import { useEffect, useState } from 'react'
import type { EvidenceCardProps, Pin } from '../evidenceTypes.ts'
import { apiFetch } from '../../api/client.ts'
import './DriftDiffCard.css'

// ── API response shapes ───────────────────────────────────────────────────────
// These mirror the Go structs serialised by writeEntityJSON (no json tags →
// PascalCase field names). Source:
//   DriftState    → pkg/entitygraph/interfaces/provider.go
//   DesiredStateView → pkg/entitygraph/types/entity.go

interface DriftField {
  Attribute: string
  Desired: unknown
  Actual: unknown
  Matching: boolean
}

interface DriftResponse {
  EID: string
  DetectedAt: string
  Fields: DriftField[]
  ConfigRevision: string
  LifecycleStatus: string
}

interface DesiredStateResponse {
  EID: string
  State: Record<string, unknown>
  ConfigRevision: string
  ObservedAt: string
}

// ── Internal state machine ────────────────────────────────────────────────────

type CardPhase =
  | { kind: 'loading' }
  | { kind: 'hidden' }
  | { kind: 'error'; message: string }
  | { kind: 'ready'; drift: DriftResponse; desired: DesiredStateResponse | null }

// ── Helpers ───────────────────────────────────────────────────────────────────

function extractEID(pins: Pin[]): string | null {
  const eidPin = pins.find((p) => p.ref.kind === 'eid')
  if (eidPin?.ref.eid) return eidPin.ref.eid
  const subjectPin = pins.find((p) => p.ref.kind === 'subject-time-range')
  if (subjectPin?.ref.subject) return subjectPin.ref.subject
  return null
}

function hasDriftPin(pins: Pin[]): boolean {
  return pins.some((p) => p.ref.kind === 'drift-record')
}

// Last path segment of the EID string (the entity's local name).
function entityLabel(eid: string): string {
  const slash = eid.lastIndexOf('/')
  return slash >= 0 ? eid.slice(slash + 1) : eid
}

function formatValue(v: unknown): string {
  if (v === null || v === undefined) return '—'
  return String(v)
}

// Coerce one element of the wire "Fields" array into a DriftField. Elements that
// are not objects are dropped by normalizeDrift; everything else is coerced so
// that the render path can read Attribute/Matching unconditionally.
function toDriftField(raw: unknown): DriftField | null {
  if (typeof raw !== 'object' || raw === null) return null
  const f = raw as Partial<DriftField>
  return {
    Attribute: typeof f.Attribute === 'string' ? f.Attribute : '',
    Desired: f.Desired,
    Actual: f.Actual,
    Matching: f.Matching === true,
  }
}

/*
 * Normalise the /drift response at the boundary.
 *
 * DriftState.Fields is a Go nil slice in ordinary, non-exceptional cases — the
 * sqlite and database providers' parseDriftFields return (nil, nil) when the
 * stored fields JSON is "", "[]" or "null" — and encoding/json serialises a nil
 * slice as `"Fields": null`. Reading .some/.map off that null throws a
 * TypeError during render; the SPA has no ErrorBoundary and EvidenceCanvas
 * renders every card in one tree, so the throw would blank the whole cockpit.
 * Defaulting Fields to [] (and coercing the scalar fields) keeps a fields-less
 * drift record a renderable, empty card.
 */
function normalizeDrift(raw: unknown): DriftResponse {
  const d = (typeof raw === 'object' && raw !== null ? raw : {}) as Partial<DriftResponse>
  const fields = Array.isArray(d.Fields)
    ? d.Fields.map(toDriftField).filter((f): f is DriftField => f !== null)
    : []
  return {
    EID: typeof d.EID === 'string' ? d.EID : '',
    DetectedAt: typeof d.DetectedAt === 'string' ? d.DetectedAt : '',
    Fields: fields,
    ConfigRevision: typeof d.ConfigRevision === 'string' ? d.ConfigRevision : '',
    LifecycleStatus: typeof d.LifecycleStatus === 'string' ? d.LifecycleStatus : '',
  }
}

// Normalise the /desired-state response; only the revision label is consumed.
function normalizeDesired(raw: unknown): DesiredStateResponse {
  const d = (typeof raw === 'object' && raw !== null ? raw : {}) as Partial<DesiredStateResponse>
  return {
    EID: typeof d.EID === 'string' ? d.EID : '',
    State: typeof d.State === 'object' && d.State !== null ? d.State : {},
    ConfigRevision: typeof d.ConfigRevision === 'string' ? d.ConfigRevision : '',
    ObservedAt: typeof d.ObservedAt === 'string' ? d.ObservedAt : '',
  }
}

function buildRawText(drift: DriftResponse): string {
  const name = entityLabel(drift.EID)
  const lines: string[] = [`$ cfg steward inspect ${name}`]
  for (const field of drift.Fields) {
    lines.push(`  desired.${field.Attribute} = ${formatValue(field.Desired)}`)
    lines.push(`  actual.${field.Attribute}  = ${formatValue(field.Actual)}`)
    if (!field.Matching) {
      lines.push(`    (drifted)`)
    }
  }
  lines.push(`  drift_detected = ${drift.DetectedAt}`)
  lines.push(`  last_revision = ${drift.ConfigRevision}`)
  return lines.join('\n')
}

// ── Component ─────────────────────────────────────────────────────────────────

export default function DriftDiffCard({ pins }: EvidenceCardProps) {
  const eid = extractEID(pins)
  const isDriftPinned = hasDriftPin(pins)
  // True when the pin list contains at least one pin type that can anchor the card.
  const hasEvidencePin =
    isDriftPinned || pins.some((p) => p.ref.kind === 'eid' || p.ref.kind === 'subject-time-range')

  const [phase, setPhase] = useState<CardPhase>({ kind: 'loading' })
  const [showRaw, setShowRaw] = useState(false)

  useEffect(() => {
    // Conditions that should suppress the card are handled in the render return
    // below — no synchronous setState calls here to avoid cascading renders.
    if (!eid || !hasEvidencePin) return

    let cancelled = false

    /*
     * Percent-encode the EID before interpolating it into the request path.
     * Entity local IDs originate from stewards (untrusted under the CFGMS
     * threat model) and ParseEID validates only the authority segment — a
     * localID may legitimately contain '/', and nothing rejects '..', '?' or
     * '#'. Unencoded, such a value would redirect this credentialed
     * same-origin GET to an attacker-chosen controller API path. gorilla/mux
     * URL-decodes the {eid:.+} path variable before matching
     * (features/controller/api/handlers_entities.go), so encoding embedded
     * slashes is transparent to routing.
     */
    const encodedEID = encodeURIComponent(eid)
    const driftPath = `/api/v1/entities/${encodedEID}/drift`
    const desiredPath = `/api/v1/entities/${encodedEID}/desired-state`

    async function fetchData(): Promise<void> {
      try {
        const [driftRes, desiredRes] = await Promise.all([
          apiFetch(driftPath),
          apiFetch(desiredPath).catch(() => null as Response | null),
        ])

        if (cancelled) return

        if (driftRes.status === 404 && !isDriftPinned) {
          // No drift record and no pinned drift evidence — nothing to display.
          setPhase({ kind: 'hidden' })
          return
        }

        if (!driftRes.ok) {
          throw new Error(`GET ${driftPath} — ${driftRes.status}`)
        }

        const drift = normalizeDrift(await driftRes.json())
        let desired: DesiredStateResponse | null = null
        if (desiredRes?.ok) {
          desired = normalizeDesired(await desiredRes.json())
        }

        if (!cancelled) {
          setPhase({ kind: 'ready', drift, desired })
        }
      } catch (err) {
        if (!cancelled) {
          setPhase({
            kind: 'error',
            message: err instanceof Error ? err.message : 'Failed to load drift data',
          })
        }
      }
    }

    void fetchData()

    return () => {
      cancelled = true
    }
  }, [eid, isDriftPinned, hasEvidencePin])

  // No EID or no relevant pin type — nothing this card can show.
  if (!eid || !hasEvidencePin) return null
  if (phase.kind === 'hidden') return null

  if (phase.kind === 'error') {
    return (
      <section className="drift-diff-card drift-diff-card--error" aria-label="Desired vs actual">
        <h3 className="drift-diff-card__header">
          <span>Desired vs actual</span>
        </h3>
        <p className="drift-diff-card__error">{phase.message}</p>
      </section>
    )
  }

  if (phase.kind === 'loading') {
    return (
      <section className="drift-diff-card" aria-label="Desired vs actual">
        <h3 className="drift-diff-card__header">
          <span>Desired vs actual</span>
        </h3>
        <p className="drift-diff-card__loading" aria-label="Loading drift data">
          Loading…
        </p>
      </section>
    )
  }

  const { drift, desired } = phase
  const hasDrift = drift.Fields.some((f) => !f.Matching)
  const name = entityLabel(drift.EID)
  const revision = drift.ConfigRevision || desired?.ConfigRevision || ''
  const detectedAt = new Date(drift.DetectedAt).toLocaleTimeString(undefined, {
    hour: '2-digit',
    minute: '2-digit',
  })
  const rawText = buildRawText(drift)
  const driftAnnotation = pins.find((p) => p.ref.kind === 'drift-record')?.annotation

  return (
    <section
      className={`drift-diff-card${hasDrift ? ' drift-diff-card--drifted' : ''}`}
      aria-label="Desired vs actual"
    >
      <h3 className="drift-diff-card__header">
        <span>
          Desired vs actual · <span className="drift-diff-card__entity-name">{name}</span>
        </span>
        <button
          type="button"
          className="drift-diff-card__raw-toggle"
          onClick={() => setShowRaw((v) => !v)}
          aria-pressed={showRaw}
          aria-label={showRaw ? 'Hide raw view' : 'Show raw view'}
        >
          {showRaw ? '⌃ hide' : '⌄ raw'}
        </button>
      </h3>

      <div className="drift-diff-card__grid">
        <div className="drift-diff-card__col">
          <div className="drift-diff-card__col-label">
            Desired{revision ? ` — intent ${revision}` : ''}
          </div>
          {drift.Fields.map((field) => (
            <div key={field.Attribute} className="drift-kv">
              <span className="drift-kv__key">{field.Attribute}</span>
              <span className="drift-kv__value">{formatValue(field.Desired)}</span>
            </div>
          ))}
        </div>

        <div className="drift-diff-card__col">
          <div className="drift-diff-card__col-label">
            Actual{drift.DetectedAt ? ` — observed ${detectedAt}` : ''}
          </div>
          {drift.Fields.map((field) => (
            <div key={field.Attribute} className={`drift-kv ${field.Matching ? 'good' : 'bad'}`}>
              <span className="drift-kv__key">{field.Attribute}</span>
              <span className="drift-kv__value">
                {formatValue(field.Actual)}
                {field.Matching ? ' ✓' : ' ⚠'}
              </span>
            </div>
          ))}
        </div>
      </div>

      {hasDrift && (
        <div className="drift-diff-card__note">
          <span className="drift-diff-card__note-pill">drift</span>
          {driftAnnotation && (
            <span className="drift-diff-card__note-text">{driftAnnotation}</span>
          )}
        </div>
      )}

      <div
        className={`drift-diff-card__raw${showRaw ? ' drift-diff-card__raw--show' : ''}`}
        aria-hidden={!showRaw}
      >
        <pre className="drift-diff-card__raw-pre">{rawText}</pre>
      </div>
    </section>
  )
}
