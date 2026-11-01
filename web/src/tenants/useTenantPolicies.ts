// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz

/*
 * Tenant policy data layer (Issue #5444, Epic #5300).
 *
 * GET|PUT /api/v1/tenants/{tenant_path}/refresh-policy
 * GET|PUT /api/v1/tenants/{tenant_path}/assurance-policy
 *
 * The step-up ceremony (elevation, or elevation plus a presence tap) is owned
 * by apiFetch + the AuthProvider's StepUpModal: a 401 CFGMS-StepUp challenge is
 * resolved there and the mutation is retried with X-Presence-Token when the
 * server required presence. If the operator cancels the ceremony the original
 * 401 comes back, which is reported as PolicyStepUpError.
 *
 * Untrusted wire data passes through parse* validators; a malformed payload is
 * rejected (null / thrown) rather than coerced into a plausible policy.
 */
import { apiFetch, unwrapEnvelope } from '../api/client.ts'

export type RefreshMode = 'auto_accept' | 'require_approval' | 'reject'
export const refreshModes: readonly RefreshMode[] = ['auto_accept', 'require_approval', 'reject']

export type MinOverride = 'basic' | 'strong'

export interface RefreshPolicy {
  mode: RefreshMode
  max_dormancy_days?: number
}

export interface AssuranceOverride {
  permission_id: string
  min_override?: MinOverride
  require_user_presence: boolean
}

export interface AssurancePolicy {
  overrides: AssuranceOverride[]
}

export class PolicyApiError extends Error {
  readonly status: number
  constructor(message: string, status: number) {
    super(message)
    this.name = 'PolicyApiError'
    this.status = status
  }
}

/** The step-up ceremony was cancelled or failed, so nothing was saved. */
export class PolicyStepUpError extends PolicyApiError {
  constructor() {
    super('Passkey confirmation was cancelled or failed — nothing was saved', 401)
    this.name = 'PolicyStepUpError'
  }
}

// ── Validators ────────────────────────────────────────────────────────────────

export function parseRefreshPolicy(value: unknown): RefreshPolicy | null {
  if (typeof value !== 'object' || value === null) return null
  const r = value as Record<string, unknown>
  if (typeof r.mode !== 'string' || !(refreshModes as readonly string[]).includes(r.mode)) return null
  const policy: RefreshPolicy = { mode: r.mode as RefreshMode }
  if (r.max_dormancy_days !== undefined && r.max_dormancy_days !== null) {
    const d = r.max_dormancy_days
    if (typeof d !== 'number' || !Number.isInteger(d) || d < 0) return null
    policy.max_dormancy_days = d
  }
  return policy
}

export function parseAssuranceOverride(value: unknown): AssuranceOverride | null {
  if (typeof value !== 'object' || value === null) return null
  const r = value as Record<string, unknown>
  if (typeof r.permission_id !== 'string' || r.permission_id === '') return null
  if (typeof r.require_user_presence !== 'boolean') return null
  const out: AssuranceOverride = {
    permission_id: r.permission_id,
    require_user_presence: r.require_user_presence,
  }
  if (r.min_override !== undefined && r.min_override !== null) {
    if (r.min_override !== 'basic' && r.min_override !== 'strong') return null
    out.min_override = r.min_override
  }
  return out
}

export function parseAssurancePolicy(value: unknown): AssurancePolicy | null {
  if (typeof value !== 'object' || value === null) return null
  const raw = (value as Record<string, unknown>).overrides
  // A null/absent list is how an empty policy serialises from Go.
  if (raw === undefined || raw === null) return { overrides: [] }
  if (!Array.isArray(raw)) return null
  const overrides: AssuranceOverride[] = []
  for (const item of raw) {
    const parsed = parseAssuranceOverride(item)
    if (parsed === null) return null
    overrides.push(parsed)
  }
  return { overrides }
}

// ── Transport ─────────────────────────────────────────────────────────────────

/** Encodes each `/`-separated segment of a tenant path, keeping the separators. */
export function encodeTenantPath(id: string): string {
  return id.split('/').map(encodeURIComponent).join('/')
}

async function apiError(response: Response, fallback: string): Promise<PolicyApiError> {
  const body = (await response.json().catch(() => ({}))) as Record<string, unknown>
  const envelope = body?.error
  let message = ''
  if (typeof envelope === 'object' && envelope !== null) {
    const m = (envelope as Record<string, unknown>).message
    if (typeof m === 'string') message = m
  } else if (typeof envelope === 'string') {
    message = envelope
  }
  return new PolicyApiError(message || `${fallback} — ${response.status}`, response.status)
}

async function readPolicy<T>(
  path: string,
  parse: (v: unknown) => T | null,
  what: string,
): Promise<T> {
  const response = await apiFetch(path)
  if (!response.ok) throw await apiError(response, `Could not load ${what}`)
  const body: unknown = await response.json().catch(() => null)
  const parsed = parse(unwrapEnvelope<unknown>(body))
  if (parsed === null) throw new PolicyApiError(`The ${what} response was malformed`, response.status)
  return parsed
}

async function writePolicy<T>(
  path: string,
  payload: unknown,
  parse: (v: unknown) => T | null,
  what: string,
): Promise<T> {
  const response = await apiFetch(path, {
    method: 'PUT',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(payload),
  })
  if (response.status === 401) throw new PolicyStepUpError()
  if (!response.ok) throw await apiError(response, `Could not save ${what}`)
  const body: unknown = await response.json().catch(() => null)
  const parsed = parse(unwrapEnvelope<unknown>(body))
  if (parsed === null) throw new PolicyApiError(`The ${what} response was malformed`, response.status)
  return parsed
}

export function getRefreshPolicy(tenantId: string): Promise<RefreshPolicy> {
  return readPolicy(`/api/v1/tenants/${encodeTenantPath(tenantId)}/refresh-policy`, parseRefreshPolicy, 'refresh policy')
}

export function putRefreshPolicy(tenantId: string, policy: RefreshPolicy): Promise<RefreshPolicy> {
  return writePolicy(
    `/api/v1/tenants/${encodeTenantPath(tenantId)}/refresh-policy`,
    policy,
    parseRefreshPolicy,
    'refresh policy',
  )
}

export function getAssurancePolicy(tenantId: string): Promise<AssurancePolicy> {
  return readPolicy(`/api/v1/tenants/${encodeTenantPath(tenantId)}/assurance-policy`, parseAssurancePolicy, 'assurance policy')
}

export function putAssurancePolicy(tenantId: string, policy: AssurancePolicy): Promise<AssurancePolicy> {
  return writePolicy(
    `/api/v1/tenants/${encodeTenantPath(tenantId)}/assurance-policy`,
    policy,
    parseAssurancePolicy,
    'assurance policy',
  )
}
