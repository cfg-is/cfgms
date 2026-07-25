// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz

/*
 * Asset-DNA content (Story #2498, #2723) — DNA fetch/render for one
 * steward, now route-driven. Gets the steward ID from `useParams` via the
 * /stewards/:id route; mounted as the DNA tab inside StewardAssetPage.
 *
 * Grouping: a FIXED client-side allowlist maps known attribute keys into
 * the mockup's designed groups; every attribute the steward reports that
 * isn't in the allowlist lands under "Other attributes", so new DNA appears
 * without UI changes. Group headings and row labels come ONLY from that
 * allowlist — never from data (security A10.1). Steward-supplied keys and
 * values are UNTRUSTED and cross into the DOM as JSX text nodes only; do
 * not introduce dangerouslySetInnerHTML here.
 *
 * The endpoint may 404 (cross-tenant, no DNA yet, denylist redaction) or
 * fail — those render the error state, never a blank panel.
 */
import { useEffect, useState } from 'react'
import { useParams } from 'react-router'
import { apiFetch } from '../api/client.ts'

export interface StewardDNAInfo {
  hostname: string
  os: string
  architecture: string
  configHash: string
  collectedAt: string
  attributes: Record<string, string>
}

/** Validate the DNA payload (untrusted wire data). Throws on non-objects. */
export function parseDNAInfo(data: unknown): StewardDNAInfo {
  if (typeof data !== 'object' || data === null) {
    throw new Error('unexpected response shape')
  }
  const record = data as Record<string, unknown>
  const str = (value: unknown): string => (typeof value === 'string' ? value : '')
  let attributes: Record<string, string> = {}
  if (typeof record.attributes === 'object' && record.attributes !== null) {
    attributes = Object.fromEntries(
      Object.entries(record.attributes).filter(
        (entry): entry is [string, string] => typeof entry[1] === 'string',
      ),
    )
  }
  return {
    hostname: str(record.hostname),
    os: str(record.os),
    architecture: str(record.architecture),
    configHash: str(record.config_hash),
    collectedAt: str(record.collected_at),
    attributes,
  }
}

interface RowSpec {
  /** Fixed display label — never derived from data. */
  label: string
  value: (dna: StewardDNAInfo) => string
}

interface GroupSpec {
  heading: string
  rows: RowSpec[]
}

/* Entry scan instead of computed member access: attribute maps are
 * steward-supplied (untrusted), so no dynamic-key indexing into them
 * (same idiom as columns.ts). */
const attr =
  (...keys: string[]) =>
  (dna: StewardDNAInfo): string => {
    for (const key of keys) {
      const value = Object.entries(dna.attributes).find(([k]) => k === key)?.[1]
      if (value) return value
    }
    return ''
  }

/*
 * The fixed grouping allowlist (mockup drawer groups). Attribute keys named
 * here render under their designed group; everything else overflows into
 * "Other attributes".
 */
const DNA_GROUPS: readonly GroupSpec[] = [
  {
    heading: 'Identity',
    rows: [
      { label: 'Hostname', value: (dna) => dna.hostname },
      { label: 'Company / tenant', value: attr('tenant') },
      { label: 'Ring', value: attr('deployment_ring') },
      { label: 'Machine ID', value: attr('machine_id', 'system_uuid', 'hardware_uuid') },
    ],
  },
  {
    heading: 'Network',
    rows: [
      { label: 'IP address', value: attr('primary_ip') },
      { label: 'MAC', value: attr('primary_mac') },
      { label: 'IP addresses', value: attr('ip_addresses') },
      { label: 'Default gateway', value: attr('default_gateway') },
      { label: 'DNS servers', value: attr('dns_servers', 'dns_nameservers') },
      { label: 'DNS domain', value: attr('dns_domain', 'domain_name') },
    ],
  },
  {
    heading: 'System',
    rows: [
      { label: 'OS / platform', value: (dna) => dna.os || attr('os_pretty_name')(dna) },
      { label: 'Architecture', value: (dna) => dna.architecture || attr('arch')(dna) },
      { label: 'Kernel', value: attr('kernel_version') },
      { label: 'Model', value: attr('system_model', 'hardware_model') },
      { label: 'Manufacturer', value: attr('system_manufacturer') },
      { label: 'Serial', value: attr('system_serial_number', 'motherboard_serial') },
      { label: 'CPU', value: attr('cpu_model', 'cpu_name') },
      { label: 'CPU cores', value: attr('cpu_cores', 'cpu_count') },
      { label: 'Memory', value: attr('memory_total_human', 'memory_total_gb') },
      { label: 'Uptime', value: attr('system_uptime') },
    ],
  },
  {
    heading: 'Session & agent',
    rows: [
      { label: 'Last logged-in user', value: attr('current_user') },
      { label: 'Logged-in users', value: attr('logged_in_users') },
      { label: 'Agent version', value: attr('steward.version') },
      { label: 'Config hash', value: (dna) => dna.configHash },
      { label: 'Collected', value: (dna) => dna.collectedAt },
    ],
  },
]

const OTHER_HEADING = 'Other attributes'

/** Every heading the drawer can render — the A10.1 test asserts against this. */
export const DNA_GROUP_HEADINGS: readonly string[] = [
  ...DNA_GROUPS.map((group) => group.heading),
  OTHER_HEADING,
]

/* Attribute keys consumed by the designed groups (including fallbacks) —
 * anything the steward reports beyond these overflows to Other attributes. */
const GROUPED_ATTR_KEYS = new Set<string>([
  'tenant',
  'deployment_ring',
  'machine_id',
  'system_uuid',
  'hardware_uuid',
  'primary_ip',
  'primary_mac',
  'ip_addresses',
  'default_gateway',
  'dns_servers',
  'dns_nameservers',
  'dns_domain',
  'domain_name',
  'os_pretty_name',
  'arch',
  'kernel_version',
  'system_model',
  'hardware_model',
  'system_manufacturer',
  'system_serial_number',
  'motherboard_serial',
  'cpu_model',
  'cpu_name',
  'cpu_cores',
  'cpu_count',
  'memory_total_human',
  'memory_total_gb',
  'system_uptime',
  'current_user',
  'logged_in_users',
  'steward.version',
])

interface FetchOutcome {
  /** Which (steward, attempt) request this outcome answers. */
  key: string
  dna?: StewardDNAInfo
  error?: string
}

function KVRow({ label, value }: { label: string; value: string }) {
  return (
    <div className="kv">
      <span className="k">{label}</span>
      <span className="v mono2">{value}</span>
    </div>
  )
}

/** DNA content panel — rendered inside the DNA tab of StewardAssetPage or the overlay drawer.
 * Accepts an explicit stewardId prop; falls back to useParams for the route-driven case. */
export default function DnaDrawer({ stewardId: propId }: { stewardId?: string } = {}) {
  const { id: paramId = '' } = useParams<{ id: string }>()
  const stewardId = propId !== undefined ? propId : paramId
  const [attempt, setAttempt] = useState(0)
  const [outcome, setOutcome] = useState<FetchOutcome | null>(null)
  const key = `${stewardId}:${attempt}`

  useEffect(() => {
    let cancelled = false
    const path = `/api/v1/stewards/${encodeURIComponent(stewardId)}/dna`
    apiFetch(path)
      .then(async (response) => {
        if (!response.ok) {
          throw new Error(`GET ${path} — ${response.status}`)
        }
        const body: unknown = await response.json()
        const dna = parseDNAInfo((body as Record<string, unknown> | null)?.data)
        if (!cancelled) setOutcome({ key, dna })
      })
      .catch((cause: unknown) => {
        if (cancelled) return
        setOutcome({
          key,
          error:
            cause instanceof Error && cause.message
              ? cause.message
              : `GET ${path} — request failed`,
        })
      })
    return () => {
      cancelled = true
    }
  }, [key, stewardId])

  const current = outcome?.key === key ? outcome : null
  const dna = current?.dna

  const otherAttrs =
    dna === undefined
      ? []
      : Object.entries(dna.attributes)
          .filter(([attrKey]) => !GROUPED_ATTR_KEYS.has(attrKey))
          .sort(([a], [b]) => a.localeCompare(b))

  return (
    <div className="det">
      <div className="db">
        {current === null ? (
          <div data-testid="dna-loading" aria-label="Loading device DNA">
            {Array.from({ length: 8 }, (_, i) => (
              <div className="kv" key={i}>
                <span className="skel" style={{ width: '30%' }} />
                <span className="skel" style={{ width: '45%' }} />
              </div>
            ))}
          </div>
        ) : current.error !== undefined ? (
          <div className="notice err" role="alert">
            <div className="ic">!</div>
            <h3>Couldn&apos;t load device DNA</h3>
            <p>
              The DNA for this steward isn&apos;t available — it may not have
              reported yet, or you may not have access to it.
            </p>
            <span className="mono2 detail">{current.error}</span>
            <button
              type="button"
              className="btn"
              onClick={() => setAttempt((n) => n + 1)}
            >
              Retry
            </button>
          </div>
        ) : (
          dna !== undefined && (
            <>
              {DNA_GROUPS.map((group) => {
                const rows = group.rows
                  .map((row) => ({ label: row.label, value: row.value(dna) }))
                  .filter((row) => row.value !== '')
                if (rows.length === 0) return null
                return (
                  <div key={group.heading}>
                    <div className="grp">
                      <div className="lbl">{group.heading}</div>
                    </div>
                    {rows.map((row) => (
                      <KVRow key={row.label} label={row.label} value={row.value} />
                    ))}
                    <div className="gsep" />
                  </div>
                )
              })}
              {otherAttrs.length > 0 && (
                <div>
                  <div className="grp">
                    <div className="lbl">{OTHER_HEADING}</div>
                  </div>
                  {otherAttrs.map(([attrKey, value]) => (
                    <KVRow key={attrKey} label={attrKey} value={value} />
                  ))}
                  <div className="gsep" />
                </div>
              )}
              <details className="raw">
                <summary>View all DNA (raw)</summary>
                <pre>{JSON.stringify(dna, null, 2)}</pre>
              </details>
            </>
          )
        )}
      </div>
    </div>
  )
}
