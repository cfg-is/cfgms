// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz

/*
 * Entity edge assertion hook (Story #5464, Epic #5300).
 *
 *   POST /api/v1/entities/edges  {edge_type, from_eid, to_eid, attributes}
 *
 * handleAssertEdge (features/controller/api/handlers_entities.go) answers 201
 * with NO body, so success is read from the status alone and the body is never
 * parsed. Refusals it can return:
 *   404  an endpoint is missing or outside the caller's tenants — deliberately
 *        not saying which, so neither does this hook;
 *   401  CFGMS-StepUp tenant-crossing — the link reaches into a tenant that
 *        needs a crossing (apiFetch runs the central crossing prompt first; a
 *        401 that still arrives here was cancelled or refused);
 *   400  validation text;  500 / 503  failure.
 * `entity:write` has no permissionAssurance entry: no step-up and no presence
 * request is made or handled here.
 *
 * The server reserves '|' as the subject delimiter, so the client rejects it in
 * edge_type, from_eid and to_eid before sending.
 */
import { useCallback, useEffect, useRef, useState } from 'react'
import { apiFetch } from '../api/client.ts'

export interface AssertEdgeInput {
  edgeType: string
  fromEid: string
  toEid: string
  attributes: Record<string, string>
}

export type AssertEdgeState =
  | { kind: 'idle' }
  | { kind: 'submitting' }
  | { kind: 'success' }
  | { kind: 'invalid'; message: string }
  | { kind: 'not-found' }
  | { kind: 'crossing'; tenantId: string }
  | { kind: 'error'; status: number; message: string }

export const EDGE_SUBJECT_DELIMITER = '|'

export const PIPE_MESSAGE =
  'Remove the | character. The controller uses it to separate the parts of a relationship, so it cannot appear in a relationship type or an entity ID.'

export function containsPipe(value: string): boolean {
  return value.includes(EDGE_SUBJECT_DELIMITER)
}

const breakGlassPattern = /^\/api\/v1\/tenants\/([^/]+)\/break-glass$/

// Best-effort: the tenant the crossing challenge names; '' when it is unreadable.
async function crossingTenant(res: Response): Promise<string> {
  try {
    const body = (await res.clone().json()) as Record<string, unknown>
    const endpoint = body.break_glass_endpoint
    const match = typeof endpoint === 'string' ? breakGlassPattern.exec(endpoint) : null
    return match ? decodeURIComponent(match[1]!) : ''
  } catch {
    return ''
  }
}

async function bodyText(res: Response): Promise<string> {
  try {
    return (await res.text()).trim()
  } catch {
    return ''
  }
}

async function classify(res: Response): Promise<AssertEdgeState> {
  if (res.ok) return { kind: 'success' }
  if (res.status === 404) return { kind: 'not-found' }
  if (res.status === 401) {
    const challenge = res.headers.get('WWW-Authenticate') ?? ''
    if (challenge.startsWith('CFGMS-StepUp') && challenge.includes('required="tenant-crossing"')) {
      return { kind: 'crossing', tenantId: await crossingTenant(res) }
    }
    return { kind: 'error', status: 401, message: 'Your session is no longer valid.' }
  }
  const text = await bodyText(res)
  if (res.status === 400) {
    return { kind: 'invalid', message: text || 'The controller rejected the relationship.' }
  }
  return { kind: 'error', status: res.status, message: text || 'assertion failed' }
}

export function useAssertEdge(): {
  state: AssertEdgeState
  assertEdge: (input: AssertEdgeInput) => Promise<AssertEdgeState>
  reset: () => void
} {
  const [state, setState] = useState<AssertEdgeState>({ kind: 'idle' })
  // Only the latest call may publish its outcome; reset and unmount supersede it.
  const latest = useRef(0)

  useEffect(
    () => () => {
      latest.current += 1
    },
    [],
  )

  const publish = useCallback((call: number, next: AssertEdgeState): AssertEdgeState => {
    if (latest.current === call) setState(next)
    return next
  }, [])

  const assertEdge = useCallback(
    async (input: AssertEdgeInput): Promise<AssertEdgeState> => {
      const call = ++latest.current
      if (
        containsPipe(input.edgeType) ||
        containsPipe(input.fromEid) ||
        containsPipe(input.toEid)
      ) {
        return publish(call, { kind: 'invalid', message: PIPE_MESSAGE })
      }
      setState({ kind: 'submitting' })
      try {
        const res = await apiFetch('/api/v1/entities/edges', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({
            edge_type: input.edgeType,
            from_eid: input.fromEid,
            to_eid: input.toEid,
            attributes: input.attributes,
          }),
        })
        return publish(call, await classify(res))
      } catch (err) {
        return publish(call, {
          kind: 'error',
          status: 0,
          message: err instanceof Error && err.message ? err.message : 'request failed',
        })
      }
    },
    [publish],
  )

  const reset = useCallback(() => {
    latest.current += 1
    setState({ kind: 'idle' })
  }, [])

  return { state, assertEdge, reset }
}
