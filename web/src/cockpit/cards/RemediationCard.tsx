// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz

/*
 * Remediation evidence card (Story #3612, Epic #2854).
 *
 * Renders a staged fix plan for the pinned entity and lets the technician
 * approve/run it or preview the diff. This card computes no plan of its own —
 * it is a UI surface over two existing endpoints:
 *   POST /api/v1/config/push          — "Approve & run"
 *   POST /api/v1/rollback/preview     — "Preview diff" (RollbackHandler.PreviewRollback)
 * and reads two existing read endpoints (shared with DriftDiffCard) to derive
 * the plan:
 *   GET /api/v1/entities/{eid}        — EntityView, for Kind + OwningTenant
 *   GET /api/v1/entities/{eid}/drift  — DriftState, for active drift + revision
 *
 * EIDRef → rollback.TargetType mapping (Issue #3612 body, explicit and closed):
 * only an entity whose graph Kind is "host" or "device" maps to
 * rollback.TargetTypeDevice, with TargetID = the eid's AuthorityName() (the
 * "authority_name" segment of "authority_type:authority_name[/local_id]").
 * Every other Kind renders the no-remediation-available state without calling
 * either mutating endpoint — this card never guesses a group/client/msp target.
 * The derived TargetID must additionally satisfy SAFE_TARGET_ID before it is
 * used; an authority name carrying a fleet-selector separator falls through to
 * the same no-remediation state (see the constant for why).
 *
 * The five facts row (host count, duration, restart-needed, reversibility,
 * module) is not backed by a risk-assessment engine (out of scope, per the
 * issue body) — module and revision are derived from the pinned drift-record
 * ref and DriftState.ConfigRevision; the other three are fixed properties of
 * "single-device module re-apply via config push", the only remediation shape
 * a Kind-mapped pin ever reaches: exactly one device, no process restart (a
 * config push is a live desired-state apply, not a service restart), and
 * always reversible (rollback is the gate that lets this card show a plan at
 * all).
 *
 * Visual design: docs/design/mockups/troubleshooting-cockpit.html §.card.remedy.
 * Colour tokens: docs/design/web-ui-design-tokens.css, consumed via
 * RemediationCard.css.
 */
import { useEffect, useState } from 'react'
import type { EvidenceCardProps, Pin } from '../evidenceTypes.ts'
import { apiFetch } from '../../api/client.ts'
import './RemediationCard.css'

// ── API response shapes ───────────────────────────────────────────────────────
// Mirrors Go structs serialised without json tags (PascalCase field names):
//   EntityView / Entity → pkg/entitygraph/types/entity.go
//   DriftState          → pkg/entitygraph/interfaces/provider.go

interface EntityResponse {
  Entity: {
    EID: string
    Kind: string
    OwningTenant: string
  }
}

interface DriftField {
  Attribute: string
  Matching: boolean
}

interface DriftResponse {
  EID: string
  Fields: DriftField[]
  ConfigRevision: string
  LifecycleStatus: string
}

// ── Plan derived from the pinned entity + its drift state ─────────────────────

interface RemediationPlan {
  entityLabel: string
  targetId: string
  tenantId: string
  revision: string
  moduleName: string
}

type CardPhase =
  | { kind: 'loading' }
  | { kind: 'no-remediation' }
  | { kind: 'error'; message: string }
  | { kind: 'staged'; plan: RemediationPlan }

type ActionPhase = 'idle' | 'running' | 'applied' | 'failed'
type PreviewPhase = 'idle' | 'loading' | 'shown' | 'failed'

// ── Helpers ───────────────────────────────────────────────────────────────────

// Same extraction order DriftDiffCard uses: a direct eid pin, else the subject
// of a subject-time-range pin.
function extractEID(pins: Pin[]): string | null {
  const eidPin = pins.find((p) => p.ref.kind === 'eid')
  if (eidPin?.ref.eid) return eidPin.ref.eid
  const subjectPin = pins.find((p) => p.ref.kind === 'subject-time-range')
  if (subjectPin?.ref.subject) return subjectPin.ref.subject
  return null
}

// Mirrors pkg/entitygraph/types.EID.AuthorityName(): the string is split at the
// first '/' into an authority segment and an optional local_id, then the
// authority segment is split at its first ':' into type and name. Returns ''
// for a string with no ':' in its authority segment (never a valid EID).
function authorityName(eid: string): string {
  const slash = eid.indexOf('/')
  const authSeg = slash >= 0 ? eid.slice(0, slash) : eid
  const colon = authSeg.indexOf(':')
  return colon >= 0 ? authSeg.slice(colon + 1) : ''
}

// Last path segment of the EID string — used only as a display label.
function entityLabel(eid: string): string {
  const slash = eid.lastIndexOf('/')
  return slash >= 0 ? eid.slice(slash + 1) : eid
}

// Pinned drift-record refs are "drift:<revision>:<entity>:<module>" (see
// DriftDiffCard.test.tsx fixtures). Returns the module segment, or null when
// no drift-record pin is present or its ref does not match that shape.
function moduleFromDriftRecordPin(pins: Pin[]): string | null {
  const pin = pins.find((p) => p.ref.kind === 'drift-record')
  const ref = pin?.ref.drift_record
  if (!ref) return null
  const segments = ref.split(':')
  return segments.length >= 4 ? (segments[3] ?? null) : null
}

const KIND_TO_TARGET_TYPE: Record<string, 'device'> = {
  host: 'device',
  device: 'device',
}

// Charset a target id must satisfy before it may be interpolated into the fleet
// selector expression ("id:<targetId>") or sent as a rollback target_id.
//
// The value originates in the pin ref, and nothing upstream constrains it to a
// separator-free string: egtypes.ParseEID rejects only '/' inside the
// authority-name segment, and pkg/registration places no charset constraint on
// steward/authority ids. The server-side selector DSL treats two of the
// characters that survive as structure, not data —
// pkg/fleet/selector/selector.go:177 splits an `id:` value on ',' into an OR set
// that features/controller/fleet/memory.go matches by any member, and the
// unquoted-value scanner terminates the term at ' ', so the rest of the string
// parses as further selector terms. An authority name of "a,b" or "x tag:prod"
// would therefore turn this card's single-device plan — whose UI contract states
// "1 host" — into a multi-steward mutating fan-out. Tenant scoping is still
// enforced server-side, but under the CFGMS threat model (stewards may be
// compromised) that is the only remaining boundary, so validate here rather than
// rely on it alone.
const SAFE_TARGET_ID = /^[A-Za-z0-9._-]+$/

function isSafeTargetId(targetId: string): boolean {
  return SAFE_TARGET_ID.test(targetId)
}

// ── Component ─────────────────────────────────────────────────────────────────

export default function RemediationCard({ pins }: EvidenceCardProps) {
  const eid = extractEID(pins)

  const [phase, setPhase] = useState<CardPhase>({ kind: 'loading' })
  const [actionPhase, setActionPhase] = useState<ActionPhase>('idle')
  const [actionMessage, setActionMessage] = useState('')
  const [previewPhase, setPreviewPhase] = useState<PreviewPhase>('idle')
  const [previewChanges, setPreviewChanges] = useState<string[]>([])
  const [previewMessage, setPreviewMessage] = useState('')

  useEffect(() => {
    if (!eid) return

    let cancelled = false
    const resolvedEid = eid
    const encodedEID = encodeURIComponent(resolvedEid)

    async function fetchData(): Promise<void> {
      try {
        const entityRes = await apiFetch(`/api/v1/entities/${encodedEID}`)
        if (cancelled) return
        if (!entityRes.ok) {
          if (entityRes.status === 404) {
            setPhase({ kind: 'no-remediation' })
            return
          }
          throw new Error(`GET /api/v1/entities/${encodedEID} — ${entityRes.status}`)
        }
        const entity = (await entityRes.json()) as EntityResponse
        const targetType = KIND_TO_TARGET_TYPE[entity.Entity.Kind]
        if (!targetType) {
          // No TargetType mapping for this Kind — render no-remediation-available
          // without ever calling drift, push, or rollback-preview.
          setPhase({ kind: 'no-remediation' })
          return
        }

        const targetId = authorityName(resolvedEid)
        if (!isSafeTargetId(targetId)) {
          // The authority name carries a selector separator (or is empty) — it
          // can never be turned into a safe single-device selector, so fail
          // closed into the same no-remediation state an unmapped Kind uses,
          // before any further endpoint is touched.
          setPhase({ kind: 'no-remediation' })
          return
        }

        const driftRes = await apiFetch(`/api/v1/entities/${encodedEID}/drift`)
        if (cancelled) return
        if (driftRes.status === 404) {
          setPhase({ kind: 'no-remediation' })
          return
        }
        if (!driftRes.ok) {
          throw new Error(`GET /api/v1/entities/${encodedEID}/drift — ${driftRes.status}`)
        }
        const drift = (await driftRes.json()) as DriftResponse
        const fields = Array.isArray(drift.Fields) ? drift.Fields : []
        const hasActiveDrift = drift.LifecycleStatus !== 'resolved' && fields.some((f) => !f.Matching)
        if (!hasActiveDrift) {
          setPhase({ kind: 'no-remediation' })
          return
        }

        const moduleName =
          moduleFromDriftRecordPin(pins) ?? fields.find((f) => !f.Matching)?.Attribute ?? 'config'

        if (!cancelled) {
          setPhase({
            kind: 'staged',
            plan: {
              entityLabel: entityLabel(entity.Entity.EID || resolvedEid),
              targetId,
              tenantId: entity.Entity.OwningTenant,
              revision: drift.ConfigRevision,
              moduleName,
            },
          })
        }
      } catch (err) {
        if (!cancelled) {
          setPhase({
            kind: 'error',
            message: err instanceof Error ? err.message : 'Failed to load remediation plan',
          })
        }
      }
    }

    void fetchData()

    return () => {
      cancelled = true
    }
    // pins is read synchronously inside fetchData for the drift-record module
    // lookup, but only eid changes should re-trigger the fetch.
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [eid])

  if (!eid) return null

  async function approveAndRun(plan: RemediationPlan): Promise<void> {
    // Re-checked at the mutating boundary: a staged plan can only hold a
    // validated target id, and this keeps that invariant true at the point the
    // value is interpolated into the selector expression.
    if (!isSafeTargetId(plan.targetId)) {
      setActionPhase('failed')
      setActionMessage('Remediation target is not a valid host identifier')
      return
    }
    setActionPhase('running')
    setActionMessage('')
    try {
      const response = await apiFetch('/api/v1/config/push', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          selector: `id:${plan.targetId}`,
          config_id: plan.moduleName,
          version: plan.revision,
          tenant_id: plan.tenantId,
          modules: [plan.moduleName],
        }),
      })
      if (!response.ok) {
        const body = (await response.json().catch(() => null)) as { error?: string } | null
        throw new Error(body?.error ?? `config push failed — ${response.status}`)
      }
      setActionPhase('applied')
    } catch (err) {
      setActionPhase('failed')
      setActionMessage(err instanceof Error ? err.message : 'config push failed')
    }
  }

  async function previewDiff(plan: RemediationPlan): Promise<void> {
    // Same guard as approveAndRun — target_id addresses a device server-side.
    if (!isSafeTargetId(plan.targetId)) {
      setPreviewPhase('failed')
      setPreviewMessage('Remediation target is not a valid host identifier')
      return
    }
    setPreviewPhase('loading')
    setPreviewMessage('')
    try {
      const response = await apiFetch('/api/v1/rollback/preview', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          target_type: 'device',
          target_id: plan.targetId,
          rollback_type: 'module',
          rollback_to: plan.revision,
          modules: [plan.moduleName],
          reason: `Preview remediation for ${plan.entityLabel}`,
        }),
      })
      if (!response.ok) {
        const body = (await response.json().catch(() => null)) as { error?: string } | null
        throw new Error(body?.error ?? `rollback preview failed — ${response.status}`)
      }
      const body = (await response.json()) as {
        preview?: { changes?: Array<{ path: string; diff: string }> }
      }
      const changes = body.preview?.changes ?? []
      setPreviewChanges(changes.map((c) => `${c.path}\n${c.diff}`))
      setPreviewPhase('shown')
    } catch (err) {
      setPreviewPhase('failed')
      setPreviewMessage(err instanceof Error ? err.message : 'rollback preview failed')
    }
  }

  if (phase.kind === 'loading') {
    return (
      <section className="remediation-card" aria-label="Remediation plan">
        <h3 className="remediation-card__header">
          <span>Remediation plan</span>
        </h3>
        <p className="remediation-card__loading">Loading…</p>
      </section>
    )
  }

  if (phase.kind === 'no-remediation') {
    return (
      <section className="remediation-card remediation-card--none" aria-label="Remediation plan">
        <h3 className="remediation-card__header">
          <span>Remediation plan</span>
        </h3>
        <p className="remediation-card__none">No remediation available.</p>
      </section>
    )
  }

  if (phase.kind === 'error') {
    return (
      <section className="remediation-card remediation-card--error" aria-label="Remediation plan">
        <h3 className="remediation-card__header">
          <span>Remediation plan</span>
        </h3>
        <p className="remediation-card__error">{phase.message}</p>
      </section>
    )
  }

  const { plan } = phase
  const statusPillClass =
    actionPhase === 'applied'
      ? 'remediation-card__pill remediation-card__pill--ok'
      : actionPhase === 'failed'
        ? 'remediation-card__pill remediation-card__pill--crit'
        : actionPhase === 'running'
          ? 'remediation-card__pill remediation-card__pill--warn'
          : 'remediation-card__pill remediation-card__pill--ok'
  const statusPillText =
    actionPhase === 'applied'
      ? 'applied'
      : actionPhase === 'failed'
        ? 'failed'
        : actionPhase === 'running'
          ? 'running'
          : 'validated'

  return (
    <section className="remediation-card" aria-label="Remediation plan">
      <h3 className="remediation-card__header">
        <span>Remediation plan</span>
        <span className={statusPillClass}>{statusPillText}</span>
      </h3>

      <div className="remediation-card__body">
        <div className="remediation-card__plan">
          Re-apply the <b className="remediation-card__mono">{plan.moduleName}</b> section of{' '}
          {plan.revision} to <b className="remediation-card__mono">{plan.entityLabel}</b>
        </div>

        <div className="remediation-card__facts">
          <span className="remediation-card__fact">1 host</span>
          <span className="remediation-card__fact">~30s</span>
          <span className="remediation-card__fact">no restart</span>
          <span className="remediation-card__fact">reversible</span>
          <span className="remediation-card__fact remediation-card__mono">
            module: {plan.moduleName}
          </span>
        </div>

        <div className="remediation-card__acts">
          <button
            type="button"
            className="remediation-card__btn remediation-card__btn--primary"
            onClick={() => void approveAndRun(plan)}
            disabled={actionPhase === 'running'}
          >
            Approve &amp; run
          </button>
          <button
            type="button"
            className="remediation-card__btn remediation-card__btn--ghost"
            onClick={() => void previewDiff(plan)}
            disabled={previewPhase === 'loading'}
          >
            Preview diff
          </button>
          <button
            type="button"
            className="remediation-card__btn remediation-card__btn--ghost"
            title="Ticket hand-off is not available in this release"
          >
            Hand to L2
          </button>
        </div>

        {actionPhase === 'failed' && (
          <p className="remediation-card__error">{actionMessage}</p>
        )}

        {previewPhase === 'failed' && (
          <p className="remediation-card__error">{previewMessage}</p>
        )}

        {previewPhase === 'shown' && (
          <div className="remediation-card__preview">
            {previewChanges.length === 0 ? (
              <p className="remediation-card__preview-empty">No changes in preview.</p>
            ) : (
              previewChanges.map((change) => (
                <pre key={change} className="remediation-card__preview-pre">
                  {change}
                </pre>
              ))
            )}
          </div>
        )}
      </div>
    </section>
  )
}
