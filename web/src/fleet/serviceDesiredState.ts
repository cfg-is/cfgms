// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz

/*
 * Derives the desired service states from a steward's effective configuration
 * (GET /api/v1/stewards/{id}/config/effective → EffectiveConfiguration).
 *
 * The payload's `config.resources` is a list of {name, module, config}; the
 * `service` module's resource name is the OS service name and `config.state`
 * is "running" or "stopped". Anything else is ignored.
 *
 * The handler defaults the tenant to "default" when the request carries none,
 * so only a response scoped to a real tenant is trusted: otherwise the result
 * is null ("managed unknown") rather than a possibly-wrong desired state.
 */

export type DesiredServices = Map<string, string>

const UNSCOPED_TENANT = 'default'

function isRecord(v: unknown): v is Record<string, unknown> {
  return typeof v === 'object' && v !== null
}

export function deriveDesiredServices(payload: unknown): DesiredServices | null {
  if (!isRecord(payload)) return null
  const body = isRecord(payload.data) ? payload.data : payload
  const tenant = body.tenant_id
  if (typeof tenant !== 'string' || tenant === '' || tenant === UNSCOPED_TENANT) return null
  const config = body.config
  if (!isRecord(config)) return null

  const desired: DesiredServices = new Map()
  const resources = Array.isArray(config.resources) ? config.resources : []
  for (const r of resources) {
    if (!isRecord(r) || r.module !== 'service' || typeof r.name !== 'string') continue
    const state = isRecord(r.config) ? r.config.state : undefined
    if (typeof state === 'string') desired.set(r.name.toLowerCase(), state.toLowerCase())
  }
  return desired
}

// Observed states that satisfy a desired "running".
const RUNNING_STATES = new Set(['running', 'active'])

/** True when a managed service's observed state differs from its desired one. */
export function isDrifted(desired: string, observed: string): boolean {
  const obs = observed.toLowerCase()
  if (desired === 'running') return !RUNNING_STATES.has(obs)
  if (desired === 'stopped') return RUNNING_STATES.has(obs)
  return false
}
