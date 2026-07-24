// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz

/*
 * Device-DNA column registry for the fleet view (Story #2497).
 *
 * Column → attribute mapping is pinned here and documented in web/README.md.
 * Steward-supplied values are UNTRUSTED (threat model: stewards run on hosts
 * that may be compromised) — every value crosses into the DOM as a text node
 * only; nothing in this module or its consumers renders steward data as
 * markup (security A9.1).
 *
 * Column selection persists in localStorage under the literal key
 * 'cfgms.fleet.columns' — a UI display preference, not auth data; the key is
 * registered in the storage allowlist (Login.test.tsx STORAGE_ALLOWLIST) and
 * written inline at each call site per that scan's literal-key rule. Values
 * read back are untrusted input and are shape-validated before use.
 */

export interface StewardDNA {
  hostname?: string
  os?: string
  architecture?: string
  attributes?: Record<string, string>
}

/* GET /api/v1/stewards page-item payload (features/controller/api/types.go). */
export interface Steward {
  id: string
  status?: string
  last_seen?: string
  version?: string
  dna?: StewardDNA | null
}

export interface StewardPage {
  stewards: Steward[]
  total: number
  limit: number
  offset: number
}

export type ColumnKey =
  | 'name'
  | 'company'
  | 'user'
  | 'ip'
  | 'os'
  | 'agent'
  | 'serial'
  | 'model'
  | 'mac'
  | 'ring'
  | 'health'
  | 'seen'

/* Cell typography per the design system: mono carries machine data. */
export type CellKind = 'name' | 'muted' | 'mono' | 'health' | 'seen'

export interface ColumnDef {
  key: ColumnKey
  /** Table header text. */
  label: string
  /** Column-picker checkbox text (mockup wording). */
  pickerLabel: string
  defaultVisible: boolean
  /** Name anchors every row and cannot be hidden. */
  locked?: boolean
  kind: CellKind
  /** Raw display/filter value; '' renders as an em-dash placeholder. */
  value: (s: Steward) => string
}

function attr(s: Steward, key: string): string {
  const attributes = s.dna?.attributes
  if (attributes === undefined) return ''
  // Entry scan instead of computed member access: attribute maps are
  // steward-supplied (untrusted), so no dynamic-key indexing into them.
  return Object.entries(attributes).find(([k]) => k === key)?.[1] ?? ''
}

/*
 * Header order matches the mockup table. `health` and `seen` derive from
 * status/last_seen via health.ts; their value() here is the filter haystack
 * contribution only.
 */
export const COLUMNS: readonly ColumnDef[] = [
  {
    key: 'name',
    label: 'Name',
    pickerLabel: 'Name',
    defaultVisible: true,
    locked: true,
    kind: 'name',
    value: (s) => s.dna?.hostname || s.id,
  },
  {
    key: 'company',
    label: 'Company',
    pickerLabel: 'Company',
    defaultVisible: true,
    kind: 'muted',
    // Tenant path attribute; the controller does not emit it yet, so this
    // renders the em-dash placeholder until it does (see web/README.md).
    value: (s) => attr(s, 'tenant'),
  },
  {
    key: 'user',
    label: 'Last user',
    pickerLabel: 'Last logged-in user',
    defaultVisible: true,
    kind: 'mono',
    value: (s) => attr(s, 'current_user'),
  },
  {
    key: 'ip',
    label: 'IP',
    pickerLabel: 'IP address',
    defaultVisible: true,
    kind: 'mono',
    value: (s) => attr(s, 'primary_ip'),
  },
  {
    key: 'os',
    label: 'OS',
    pickerLabel: 'OS / platform',
    defaultVisible: false,
    kind: 'muted',
    value: (s) => s.dna?.os || attr(s, 'os_pretty_name'),
  },
  {
    key: 'agent',
    label: 'Agent',
    pickerLabel: 'Agent version',
    defaultVisible: false,
    kind: 'mono',
    value: (s) => s.version || attr(s, 'steward.version'),
  },
  {
    key: 'serial',
    label: 'Serial',
    pickerLabel: 'Serial',
    defaultVisible: false,
    kind: 'mono',
    value: (s) => attr(s, 'system_serial_number') || attr(s, 'motherboard_serial'),
  },
  {
    key: 'model',
    label: 'Model',
    pickerLabel: 'Model',
    defaultVisible: false,
    kind: 'muted',
    value: (s) => attr(s, 'system_model') || attr(s, 'hardware_model'),
  },
  {
    key: 'mac',
    label: 'MAC',
    pickerLabel: 'MAC address',
    defaultVisible: false,
    kind: 'mono',
    value: (s) => attr(s, 'primary_mac'),
  },
  {
    key: 'ring',
    label: 'Ring',
    pickerLabel: 'Ring',
    defaultVisible: false,
    kind: 'mono',
    value: (s) => attr(s, 'deployment_ring'),
  },
  {
    key: 'health',
    label: 'Health',
    pickerLabel: 'Health',
    defaultVisible: true,
    kind: 'health',
    value: (s) => s.status ?? '',
  },
  {
    key: 'seen',
    label: 'Last check-in',
    pickerLabel: 'Last check-in',
    defaultVisible: true,
    kind: 'seen',
    value: (s) => s.last_seen ?? '',
  },
] as const

/** Resolve the display name for a steward: hostname from DNA, falling back to the steward ID. */
export function stewardDisplayName(steward: Pick<Steward, 'id' | 'dna'>): string {
  return steward.dna?.hostname || steward.id
}

export const DEFAULT_VISIBLE: readonly ColumnKey[] = COLUMNS.filter(
  (c) => c.defaultVisible,
).map((c) => c.key)

const VALID_KEYS = new Set<string>(COLUMNS.map((c) => c.key))

/*
 * Load the persisted column selection. Returns null (caller falls back to
 * defaults) when nothing is stored or the stored value fails validation —
 * localStorage contents are untrusted input, never assumed well-formed.
 */
export function loadColumnPrefs(): ColumnKey[] | null {
  const raw = localStorage.getItem('cfgms.fleet.columns')
  if (raw === null) return null
  let parsed: unknown
  try {
    parsed = JSON.parse(raw)
  } catch {
    return null
  }
  if (!Array.isArray(parsed)) return null
  const keys = parsed.filter(
    (k): k is ColumnKey => typeof k === 'string' && VALID_KEYS.has(k),
  )
  if (keys.length === 0) return null
  return [...new Set<ColumnKey>(['name', ...keys])]
}

export function saveColumnPrefs(keys: readonly ColumnKey[]): void {
  localStorage.setItem('cfgms.fleet.columns', JSON.stringify(keys))
}
