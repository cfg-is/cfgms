// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz

/*
 * Asset-DNA drawer (Story #2498) — row drill-in panel for the fleet table.
 * Fetches GET /api/v1/stewards/{id}/dna via the #2495 client and renders
 * all returned attributes in two tiers:
 *
 *   1. Known groups (Identity / Network / System / Session & agent) — labels
 *      and group headings are client-side constants, never derived from data
 *      (security A10.1). Values come from dna.attributes by exact key lookup.
 *   2. Other attributes — any key not consumed by the named groups appears
 *      here; both key and value reach the DOM as text nodes only (A9.1).
 *
 * A 404 / permission-denied response or an empty attribute map renders the
 * error (or graceful em-dash) state — never a blank panel.
 *
 * Fetch state follows the derived-state pattern from useStewards.ts: a single
 * `result` object keyed by steward ID; `loading` is derived from key mismatch
 * so no synchronous setState calls are needed inside the effect.
 *
 * SEAM: deep-linkable drawer (steward ID in the route) is left as a marked
 * seam for when this app adopts a client-side router. Steward ID is already
 * a stable prop; add router.params integration here without restructuring.
 *
 * Security A9.1: every steward-supplied value lands in the DOM through JSX
 * text interpolation — text nodes only, never dangerouslySetInnerHTML.
 */
import { useEffect, useState } from 'react'
import { apiFetch } from '../api/client.ts'
import { deriveHealth, formatLastSeen } from './health.ts'
import type { Steward } from './columns.ts'
import './DnaDrawer.css'

interface DNAInfo {
  hostname: string
  os: string
  architecture: string
  attributes: Record<string, string>
}

// Row definition: try attribute keys in order, first non-empty wins.
interface GroupRow {
  label: string
  keys: readonly string[]
}

// Group and row LABELS are compile-time string literals — never from data (A10.1).
const DNA_GROUPS: ReadonlyArray<{ label: string; rows: readonly GroupRow[] }> = [
  {
    label: 'Identity',
    rows: [
      { label: 'Company / tenant', keys: ['tenant'] },
      { label: 'Ring', keys: ['deployment_ring'] },
      { label: 'FQDN', keys: ['fqdn'] },
      { label: 'Enrolled', keys: ['enrolled_at'] },
    ],
  },
  {
    label: 'Network',
    rows: [
      { label: 'IP address', keys: ['primary_ip'] },
      { label: 'MAC', keys: ['primary_mac'] },
    ],
  },
  {
    label: 'System',
    rows: [
      { label: 'OS / platform', keys: ['os_pretty_name'] },
      { label: 'Model', keys: ['system_model', 'hardware_model'] },
      { label: 'Serial', keys: ['system_serial_number', 'motherboard_serial'] },
      { label: 'CPU', keys: ['cpu_count'] },
      { label: 'RAM', keys: ['total_memory'] },
      { label: 'Uptime', keys: ['uptime'] },
    ],
  },
  {
    label: 'Session & agent',
    rows: [
      { label: 'Last logged-in user', keys: ['current_user'] },
      { label: 'Module trust', keys: ['module_trust_mode'] },
      { label: 'Last convergence', keys: ['last_convergence'] },
    ],
  },
] as const

// All attribute keys consumed by the named groups above. Anything not in
// this set goes to the "Other attributes" overflow group.
const KNOWN_ATTR_KEYS = new Set<string>(
  DNA_GROUPS.flatMap((g) => g.rows.flatMap((r) => [...r.keys])),
)

// Safe attribute lookup that avoids bracket-access with variable keys (A9.1).
// Mirrors the columns.ts Object.entries().find() idiom.
function attrValue(attrs: Record<string, string>, keys: readonly string[]): string {
  const entries = Object.entries(attrs)
  for (const key of keys) {
    const found = entries.find(([k]) => k === key)
    if (found?.[1]) return found[1]
  }
  return ''
}

function parseDNAInfo(data: unknown): DNAInfo | null {
  if (typeof data !== 'object' || data === null) return null
  const rec = data as Record<string, unknown>
  const hasHostname = typeof rec.hostname === 'string'
  const hasOS = typeof rec.os === 'string'
  const hasAttrs = typeof rec.attributes === 'object' && rec.attributes !== null
  if (!hasHostname && !hasOS && !hasAttrs) return null

  const raw = hasAttrs ? (rec.attributes as Record<string, unknown>) : {}
  const attributes = Object.fromEntries(
    Object.entries(raw).filter(
      (e): e is [string, string] => typeof e[1] === 'string',
    ),
  )
  return {
    hostname: typeof rec.hostname === 'string' ? rec.hostname : '',
    os: typeof rec.os === 'string' ? rec.os : '',
    architecture: typeof rec.architecture === 'string' ? rec.architecture : '',
    attributes,
  }
}

// Fetch result keyed by steward ID — same derived-state pattern as useStewards.ts
// so the effect body never calls setState synchronously.
interface FetchResult {
  stewardId: string
  dna?: DNAInfo
  error?: string
}

export default function DnaDrawer({
  steward,
  onClose,
  nowMs,
}: {
  steward: Steward | null
  onClose: () => void
  nowMs: number
}) {
  const [result, setResult] = useState<FetchResult | null>(null)

  const open = steward !== null
  const stewardId = steward === null ? null : steward.id

  // Escape closes the drawer — consistent with the shell overlay conventions.
  useEffect(() => {
    if (!open) return
    function onKeyDown(event: KeyboardEvent) {
      if (event.key === 'Escape') onClose()
    }
    document.addEventListener('keydown', onKeyDown)
    return () => document.removeEventListener('keydown', onKeyDown)
  }, [open, onClose])

  // Fetch DNA when a steward is selected. Loading is derived from key mismatch
  // (same pattern as useStewards.ts) — no synchronous setState inside the effect.
  useEffect(() => {
    if (stewardId === null) return
    let cancelled = false
    apiFetch(`/api/v1/stewards/${encodeURIComponent(stewardId)}/dna`)
      .then(async (response) => {
        if (!response.ok) {
          throw new Error(`GET /api/v1/stewards/${stewardId}/dna — ${response.status}`)
        }
        const body: unknown = await response.json()
        const parsed = parseDNAInfo((body as Record<string, unknown> | null)?.data)
        if (parsed === null) throw new Error('unexpected DNA response shape')
        if (cancelled) return
        setResult({ stewardId, dna: parsed })
      })
      .catch((cause: unknown) => {
        if (cancelled) return
        const msg =
          cause instanceof Error
            ? cause.message
            : `GET /api/v1/stewards/${stewardId}/dna — request failed`
        setResult({ stewardId, error: msg })
      })
    return () => {
      cancelled = true
    }
  }, [stewardId])

  if (!open || steward === null) return null

  // Derived state: loading is true while no matching result has arrived.
  const currentResult = result?.stewardId === stewardId ? result : null
  const loading = currentResult === null
  const dna = currentResult?.dna ?? null
  const error = currentResult?.error ?? null

  const health = deriveHealth(steward.status, steward.last_seen, nowMs)
  const name = steward.dna?.hostname || steward.id

  return (
    <>
      {/* Own scrim — z-index 40, above nav drawer (35), below panel (45) */}
      <div
        className="dna-scrim"
        data-testid="dna-scrim"
        onClick={onClose}
        aria-hidden="true"
      />
      <aside className="det" data-testid="dna-drawer" aria-label={`DNA detail for ${name}`}>
        <div className="dh">
          <span className={`pill ${health.tone}`}>
            <span className="dot" />
            {health.label}
          </span>
          <span className="nm">{name}</span>
          <button
            type="button"
            className="icobtn x"
            aria-label="Close DNA detail"
            onClick={onClose}
          >
            <svg width="15" height="15" viewBox="0 0 24 24" fill="none" aria-hidden="true">
              <path
                d="M6 6l12 12M18 6L6 18"
                stroke="currentColor"
                strokeWidth="1.8"
                strokeLinecap="round"
              />
            </svg>
          </button>
        </div>
        <div className="db" data-testid="dna-body">
          {loading && (
            <div className="dna-loading" data-testid="dna-loading" aria-busy="true">
              <div className="skrow">
                <span className="skel" style={{ width: '75%' }} />
                <span className="skel" style={{ width: '60%' }} />
              </div>
              <div className="skrow">
                <span className="skel" style={{ width: '80%' }} />
                <span className="skel" style={{ width: '55%' }} />
              </div>
              <div className="skrow">
                <span className="skel" style={{ width: '65%' }} />
                <span className="skel" style={{ width: '70%' }} />
              </div>
            </div>
          )}
          {error !== null && !loading && (
            <div className="notice err" role="alert" data-testid="dna-error">
              <div className="ic">!</div>
              <p className="detail">{error}</p>
            </div>
          )}
          {dna !== null && !loading && error === null && (
            <DnaGroups dna={dna} steward={steward} nowMs={nowMs} />
          )}
        </div>
      </aside>
    </>
  )
}

function DnaGroups({
  dna,
  steward,
  nowMs,
}: {
  dna: DNAInfo
  steward: Steward
  nowMs: number
}) {
  const attrs = dna.attributes

  // Overflow entries: attribute keys not consumed by any named group row.
  // Uses Object.entries to avoid variable-key bracket access (security).
  const otherEntries = Object.entries(attrs)
    .filter(([k]) => !KNOWN_ATTR_KEYS.has(k))
    .sort(([a], [b]) => a.localeCompare(b))

  const lastSeen = formatLastSeen(steward.last_seen, nowMs)
  const agentVersion = steward.version || attrValue(attrs, ['steward.version'])

  return (
    <>
      {DNA_GROUPS.map((group, gi) => (
        <div key={group.label}>
          {gi > 0 && <div className="gsep" />}
          <div className="grp">
            {/* Group heading is a hardcoded constant — never from data (A10.1) */}
            <div className="lbl">{group.label}</div>
          </div>
          {group.label === 'Session & agent' && (
            <>
              <KV label="Last check-in" value={lastSeen} />
              <KV label="Agent version" value={agentVersion} />
            </>
          )}
          {group.rows.map((row) => (
            <KV key={row.label} label={row.label} value={attrValue(attrs, row.keys)} />
          ))}
          {group.label === 'System' && !attrValue(attrs, ['os_pretty_name']) && dna.os && (
            <KV label="OS" value={dna.os} />
          )}
          {group.label === 'System' && dna.architecture && (
            <KV label="Architecture" value={dna.architecture} />
          )}
        </div>
      ))}
      {otherEntries.length > 0 && (
        <div>
          <div className="gsep" />
          <div className="grp">
            {/* "Other attributes" heading is a hardcoded constant — never from data (A10.1) */}
            <div className="lbl">Other attributes</div>
          </div>
          {otherEntries.map(([k, v]) => (
            // Both key and value are steward-supplied data; rendered as text
            // nodes only via JSX interpolation — never as markup (A9.1).
            <KV key={k} label={k} value={v} />
          ))}
        </div>
      )}
      <details className="raw">
        <summary>View all DNA (raw)</summary>
        <pre>{JSON.stringify(dna, null, 2)}</pre>
      </details>
    </>
  )
}

function KV({ label, value }: { label: string; value: string }) {
  return (
    <div className="kv">
      <span className="k">{label}</span>
      <span className="v mono">{value || '—'}</span>
    </div>
  )
}
