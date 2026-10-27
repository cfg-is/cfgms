// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz

/*
 * Tenant config source data layer (Issue #5453, Epic #5300).
 *
 * PUT  /api/v1/tenants/{tenant_path}/config-source/credential  {url, token}
 * POST /api/v1/tenants/{tenant_path}/config-source/test        (no body)
 *
 * Both are tenant:manage (Strong). The token is write-only: it is sent once and
 * never read back, logged or stored. The step-up ceremony is owned by apiFetch
 * and the AuthProvider's StepUpModal; a 401 that survives it is reported as
 * PolicyStepUpError. Untrusted wire data passes through parse* validators.
 */
import { apiFetch, unwrapEnvelope } from '../api/client.ts'
import { encodeTenantPath, PolicyApiError, PolicyStepUpError } from './useTenantPolicies.ts'

/** Mirrors configSourceCredentialMaxTokenLen in handlers_config_source_credential.go. */
export const configSourceCredentialMaxTokenLen = 4096

export interface ConfigSourceCredentialResult {
  credential_ref: string
  bound_repository_url: string
}

export interface ConfigSourceTestResult {
  reachable: boolean
  error?: string
}

export function parseCredentialResult(value: unknown): ConfigSourceCredentialResult | null {
  if (typeof value !== 'object' || value === null) return null
  const r = value as Record<string, unknown>
  if (typeof r.credential_ref !== 'string' || typeof r.bound_repository_url !== 'string') return null
  return { credential_ref: r.credential_ref, bound_repository_url: r.bound_repository_url }
}

export function parseTestResult(value: unknown): ConfigSourceTestResult | null {
  if (typeof value !== 'object' || value === null) return null
  const r = value as Record<string, unknown>
  if (typeof r.reachable !== 'boolean') return null
  const out: ConfigSourceTestResult = { reachable: r.reachable }
  if (r.error !== undefined && r.error !== null) {
    if (typeof r.error !== 'string') return null
    out.error = r.error
  }
  return out
}

async function serverError(response: Response, fallback: string): Promise<PolicyApiError> {
  const body = (await response.json().catch(() => ({}))) as Record<string, unknown> | null
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

async function send<T>(
  path: string,
  init: RequestInit,
  parse: (v: unknown) => T | null,
  what: string,
): Promise<T> {
  const response = await apiFetch(path, init)
  if (response.status === 401) throw new PolicyStepUpError()
  if (!response.ok) throw await serverError(response, `Could not ${what}`)
  const body: unknown = await response.json().catch(() => null)
  const parsed = parse(unwrapEnvelope<unknown>(body))
  if (parsed === null) throw new PolicyApiError(`The ${what} response was malformed`, response.status)
  return parsed
}

export function putConfigSourceCredential(
  tenantId: string,
  url: string,
  token: string,
): Promise<ConfigSourceCredentialResult> {
  return send(
    `/api/v1/tenants/${encodeTenantPath(tenantId)}/config-source/credential`,
    {
      method: 'PUT',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ url, token }),
    },
    parseCredentialResult,
    'save the config source credential',
  )
}

export function testConfigSource(tenantId: string): Promise<ConfigSourceTestResult> {
  return send(
    `/api/v1/tenants/${encodeTenantPath(tenantId)}/config-source/test`,
    { method: 'POST' },
    parseTestResult,
    'test the config source',
  )
}
