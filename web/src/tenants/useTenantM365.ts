// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz

/*
 * Tenant M365 / GDAP connection data layer (Issue #5457, Epic #5300).
 *
 * GET    /api/v1/tenants/{id}/m365-connection        tenant:read
 * PUT    /api/v1/tenants/{id}/m365-connection        tenant:manage (Strong)
 * DELETE /api/v1/tenants/{id}/m365-connection        tenant:manage (Strong)
 * POST   /api/v1/tenants/{id}/m365-gdap-customers    tenant:manage (Strong)
 * POST   /api/v1/tenants/{id}/m365-gdap-links        tenant:manage (Strong)
 *
 * Client secrets are write-only: sent once, never read back, logged or stored.
 * A 409 means a connection already exists (PolicyApiError.status === 409); the
 * caller offers Replace and resends with replace: true. The step-up ceremony is
 * owned by apiFetch; a 401 that survives it is a PolicyStepUpError. Untrusted
 * wire data passes through parse* validators.
 */
import { apiFetch, unwrapEnvelope } from '../api/client.ts'
import { encodeTenantPath, PolicyApiError, PolicyStepUpError } from './useTenantPolicies.ts'

export interface M365Connection {
  tenant_id: string
  mode: string
  app_id: string
  m365_tenant_id: string
  partner_tenant_id?: string
  gdap_roles?: string[]
  has_client_secret: boolean
}

export interface GdapCustomer {
  customer_tenant_id: string
  name: string
  status: string
  expires_at: string
  roles: string[]
  link_state: string
  linked_to?: string
}

export interface GdapLink {
  customer_tenant_id: string
  tenant_id: string
}

export interface M365DirectInput {
  app_id: string
  m365_tenant_id: string
  client_secret: string
  replace: boolean
}

export interface GdapPartnerInput {
  partner_tenant_id: string
  app_id: string
  client_secret: string
}

export interface GdapLinksInput extends GdapPartnerInput {
  links: GdapLink[]
  gdap_roles: string[]
  replace: boolean
}

function isRecord(v: unknown): v is Record<string, unknown> {
  return typeof v === 'object' && v !== null
}

function stringList(v: unknown): string[] | null {
  if (!Array.isArray(v)) return null
  const out: string[] = []
  for (const item of v) {
    if (typeof item !== 'string') return null
    out.push(item)
  }
  return out
}

export function parseM365Connection(value: unknown): M365Connection | null {
  if (!isRecord(value)) return null
  const { tenant_id, mode, app_id, m365_tenant_id, partner_tenant_id, gdap_roles, has_client_secret } = value
  if (
    typeof tenant_id !== 'string' ||
    typeof mode !== 'string' ||
    typeof app_id !== 'string' ||
    typeof m365_tenant_id !== 'string' ||
    typeof has_client_secret !== 'boolean'
  ) return null
  const out: M365Connection = { tenant_id, mode, app_id, m365_tenant_id, has_client_secret }
  if (partner_tenant_id !== undefined && partner_tenant_id !== null) {
    if (typeof partner_tenant_id !== 'string') return null
    out.partner_tenant_id = partner_tenant_id
  }
  if (gdap_roles !== undefined && gdap_roles !== null) {
    const roles = stringList(gdap_roles)
    if (roles === null) return null
    out.gdap_roles = roles
  }
  return out
}

export function parseGdapCustomer(value: unknown): GdapCustomer | null {
  if (!isRecord(value)) return null
  const { customer_tenant_id, name, status, expires_at, roles, link_state, linked_to } = value
  if (
    typeof customer_tenant_id !== 'string' ||
    typeof name !== 'string' ||
    typeof status !== 'string' ||
    typeof expires_at !== 'string' ||
    typeof link_state !== 'string'
  ) return null
  // The server omits no roles key, but a null list (Go nil slice) is an empty list.
  const roleList = roles === null || roles === undefined ? [] : stringList(roles)
  if (roleList === null) return null
  const out: GdapCustomer = { customer_tenant_id, name, status, expires_at, roles: roleList, link_state }
  if (linked_to !== undefined && linked_to !== null) {
    if (typeof linked_to !== 'string') return null
    out.linked_to = linked_to
  }
  return out
}

export function parseGdapCustomers(value: unknown): GdapCustomer[] | null {
  if (!isRecord(value)) return null
  if (value.customers === null || value.customers === undefined) return []
  if (!Array.isArray(value.customers)) return null
  const out: GdapCustomer[] = []
  for (const item of value.customers) {
    const row = parseGdapCustomer(item)
    if (row === null) return null
    out.push(row)
  }
  return out
}

export function parseGdapLinked(value: unknown): GdapLink[] | null {
  if (!isRecord(value)) return null
  if (value.linked === null || value.linked === undefined) return []
  if (!Array.isArray(value.linked)) return null
  const out: GdapLink[] = []
  for (const item of value.linked) {
    if (!isRecord(item) || typeof item.customer_tenant_id !== 'string' || typeof item.tenant_id !== 'string') return null
    out.push({ customer_tenant_id: item.customer_tenant_id, tenant_id: item.tenant_id })
  }
  return out
}

async function serverError(response: Response, fallback: string): Promise<PolicyApiError> {
  const body = (await response.json().catch(() => ({}))) as Record<string, unknown> | null
  const envelope = body?.error
  let message = ''
  if (isRecord(envelope)) {
    const m = envelope.message
    if (typeof m === 'string') message = m
  } else if (typeof envelope === 'string') {
    message = envelope
  }
  return new PolicyApiError(message || `${fallback} — ${response.status}`, response.status)
}

async function call<T>(
  path: string,
  init: RequestInit | undefined,
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

const jsonInit = (method: string, payload: unknown): RequestInit => ({
  method,
  headers: { 'Content-Type': 'application/json' },
  body: JSON.stringify(payload),
})

const base = (tenantId: string) => `/api/v1/tenants/${encodeTenantPath(tenantId)}`

/** Resolves null when the tenant has no connection (404). */
export async function getM365Connection(tenantId: string): Promise<M365Connection | null> {
  const response = await apiFetch(`${base(tenantId)}/m365-connection`)
  if (response.status === 404) return null
  if (!response.ok) throw await serverError(response, 'Could not load the M365 connection')
  const body: unknown = await response.json().catch(() => null)
  const parsed = parseM365Connection(unwrapEnvelope<unknown>(body))
  if (parsed === null) throw new PolicyApiError('The M365 connection response was malformed', response.status)
  return parsed
}

export function putM365Connection(tenantId: string, input: M365DirectInput): Promise<M365Connection> {
  return call(
    `${base(tenantId)}/m365-connection`,
    jsonInit('PUT', input),
    parseM365Connection,
    'save the M365 connection',
  )
}

export async function deleteM365Connection(tenantId: string): Promise<void> {
  await call(
    `${base(tenantId)}/m365-connection`,
    { method: 'DELETE' },
    (v) => (isRecord(v) && v.deleted === true ? true : null),
    'clear the M365 connection',
  )
}

export function listGdapCustomers(tenantId: string, input: GdapPartnerInput): Promise<GdapCustomer[]> {
  return call(
    `${base(tenantId)}/m365-gdap-customers`,
    jsonInit('POST', input),
    parseGdapCustomers,
    'list GDAP customers',
  )
}

export function linkGdapCustomers(tenantId: string, input: GdapLinksInput): Promise<GdapLink[]> {
  return call(
    `${base(tenantId)}/m365-gdap-links`,
    jsonInit('POST', input),
    parseGdapLinked,
    'link GDAP customers',
  )
}
