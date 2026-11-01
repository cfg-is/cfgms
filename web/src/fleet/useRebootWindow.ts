// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz

/*
 * Reboot window data layer (Issue #5458, Epic #5300).
 *
 * GET|PUT /api/v1/tenants/{id}/reboot-window    reboot_window:read | :override
 * GET|PUT /api/v1/stewards/{id}/reboot-window   reboot_window:read | :override
 *
 * Neither route has a permissionAssurance entry, so a save needs no step-up
 * and no presence ceremony. The PUT body is {schedule_yaml,
 * tenant_default_timezone?}; the timezone is sent on the tenant scope only.
 * A server validation error (schedule.Parse) is surfaced verbatim. Untrusted
 * wire data passes through parseRebootWindow.
 */
import { apiFetch, unwrapEnvelope } from '../api/client.ts'
import { encodeTenantPath, PolicyApiError } from '../tenants/useTenantPolicies.ts'

export type RebootWindowScope = 'tenants' | 'stewards'
export type RebootWindowStatus = 'scheduled' | 'unrestricted'

export interface RebootWindow {
  tenant_id?: string
  steward_id?: string
  tenant_default_timezone?: string
  declared_schedule_yaml?: string
  next_occurrence?: string
  next_occurrence_display?: string
  status: RebootWindowStatus
}

export interface RebootWindowInput {
  schedule_yaml: string
  tenant_default_timezone?: string
}

function isRecord(v: unknown): v is Record<string, unknown> {
  return typeof v === 'object' && v !== null
}

function optString(v: unknown): string | undefined | null {
  if (v === undefined || v === null) return undefined
  return typeof v === 'string' ? v : null
}

export function parseRebootWindow(value: unknown): RebootWindow | null {
  if (!isRecord(value)) return null
  if (value.status !== 'scheduled' && value.status !== 'unrestricted') return null
  const fields = [
    optString(value.tenant_id),
    optString(value.steward_id),
    optString(value.tenant_default_timezone),
    optString(value.declared_schedule_yaml),
    optString(value.next_occurrence),
    optString(value.next_occurrence_display),
  ]
  if (fields.some((f) => f === null)) return null
  const [tenant_id, steward_id, tenant_default_timezone, declared_schedule_yaml, next_occurrence, next_occurrence_display] =
    fields as (string | undefined)[]
  const out: RebootWindow = { status: value.status }
  if (tenant_id !== undefined) out.tenant_id = tenant_id
  if (steward_id !== undefined) out.steward_id = steward_id
  if (tenant_default_timezone !== undefined) out.tenant_default_timezone = tenant_default_timezone
  if (declared_schedule_yaml !== undefined) out.declared_schedule_yaml = declared_schedule_yaml
  if (next_occurrence !== undefined) out.next_occurrence = next_occurrence
  if (next_occurrence_display !== undefined) out.next_occurrence_display = next_occurrence_display
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

async function call(path: string, init: RequestInit | undefined, what: string): Promise<RebootWindow> {
  const response = await apiFetch(path, init)
  if (!response.ok) throw await serverError(response, `Could not ${what}`)
  const body: unknown = await response.json().catch(() => null)
  const parsed = parseRebootWindow(unwrapEnvelope<unknown>(body))
  if (parsed === null) throw new PolicyApiError(`The ${what} response was malformed`, response.status)
  return parsed
}

const path = (scope: RebootWindowScope, id: string) => `/api/v1/${scope}/${encodeTenantPath(id)}/reboot-window`

/** Reads the declared window and its next occurrence for a tenant or steward. */
export function useRebootWindow(scope: RebootWindowScope) {
  return {
    get: (id: string): Promise<RebootWindow> => call(path(scope, id), undefined, 'load the reboot window'),
    save: (id: string, input: RebootWindowInput): Promise<RebootWindow> => {
      const body: RebootWindowInput = { schedule_yaml: input.schedule_yaml }
      if (scope === 'tenants' && input.tenant_default_timezone !== undefined) {
        body.tenant_default_timezone = input.tenant_default_timezone
      }
      return call(
        path(scope, id),
        { method: 'PUT', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(body) },
        'save the reboot window',
      )
    },
  }
}
