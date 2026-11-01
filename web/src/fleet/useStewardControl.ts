// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz

/*
 * Steward process/service action helpers (Story #4629).
 *
 * performAction signs the action with the operator's passkey (signAction.ts),
 * POSTs it through apiFetch (the existing CFGMS-StepUp flow applies to every
 * step-up-gated call), then polls the run's job until it reaches a terminal
 * status. The outcome is a plain value so a menu can render every case; a poll
 * window that ends without a terminal status is "pending", never a failure.
 * No client-side RBAC: a 403 is rendered as the server's denial.
 */
import { useCallback, useMemo } from 'react'
import { apiFetch, unwrapEnvelope } from '../api/client.ts'
import {
  ControlHttpError,
  NoPasskeyError,
  SignCancelledError,
  signAction,
  type ActionSpec,
} from './signAction.ts'

export const POLL_INTERVAL_MS = 1_000
export const POLL_WINDOW_MS = 30_000

/** Result codes a finished job can carry (expired / no_result come from the job status). */
export type ResultCode =
  | 'ok'
  | 'self_protect'
  | 'process_changed'
  | 'unsupported'
  | 'expired'
  | 'no_result'
  | 'failed'

export type ActionOutcome =
  | { kind: 'result'; code: ResultCode }
  | { kind: 'pending'; runId: string }
  | { kind: 'denied' }
  | { kind: 'cancelled' }
  | { kind: 'no_passkey' }
  | { kind: 'error'; message: string }

interface JobView {
  status?: string
  result_code?: string
}

const TERMINAL = new Set(['completed', 'failed', 'cancelled', 'expired', 'no_result'])
const KNOWN_CODES = new Set<string>(['ok', 'self_protect', 'process_changed', 'unsupported', 'expired', 'no_result'])

function jobResultCode(job: JobView): ResultCode {
  if (job.status === 'expired' || job.status === 'no_result') return job.status
  if (job.result_code && KNOWN_CODES.has(job.result_code)) return job.result_code as ResultCode
  return job.status === 'completed' ? 'ok' : 'failed'
}

function sleep(ms: number): Promise<void> {
  return new Promise((resolve) => setTimeout(resolve, ms))
}

function toOutcome(e: unknown): ActionOutcome {
  if (e instanceof SignCancelledError) return { kind: 'cancelled' }
  if (e instanceof NoPasskeyError) return { kind: 'no_passkey' }
  if (e instanceof ControlHttpError) {
    if (e.status === 403) return { kind: 'denied' }
    if (e.status === 401) return { kind: 'error', message: 'Step-up verification was not completed.' }
    return { kind: 'error', message: `The request failed (${e.status}).` }
  }
  return { kind: 'error', message: 'The action could not be sent.' }
}

/** Polls the run's job until terminal or the window ends (then 'pending'). */
export async function pollRun(runId: string): Promise<ActionOutcome> {
  const deadline = Date.now() + POLL_WINDOW_MS
  for (;;) {
    const resp = await apiFetch(`/api/v1/runs/${encodeURIComponent(runId)}/jobs`)
    if (resp.status === 403) return { kind: 'denied' }
    if (!resp.ok) return { kind: 'error', message: `The result could not be read (${resp.status}).` }
    const jobs = unwrapEnvelope<JobView[]>(await resp.json())
    const job = Array.isArray(jobs) ? jobs[0] : undefined
    if (job && job.status && TERMINAL.has(job.status)) {
      return { kind: 'result', code: jobResultCode(job) }
    }
    if (Date.now() + POLL_INTERVAL_MS > deadline) return { kind: 'pending', runId }
    await sleep(POLL_INTERVAL_MS)
  }
}

/**
 * Signs and sends one action, then polls for the result. onAccepted fires once the
 * 202 is received (the row is pending from then on). Never throws.
 */
export async function performAction(
  stewardId: string,
  spec: ActionSpec,
  justification: string,
  onAccepted?: () => void,
): Promise<ActionOutcome> {
  let runId: string
  try {
    const proof = await signAction(stewardId, spec)
    const base = `/api/v1/stewards/${encodeURIComponent(stewardId)}`
    const path =
      spec.targetKind === 'process'
        ? `${base}/processes/${encodeURIComponent(spec.targetName)}/actions`
        : `${base}/services/${encodeURIComponent(spec.targetName)}/actions`
    const resp = await apiFetch(path, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        action: spec.action,
        justification,
        ...(spec.image !== undefined ? { image: spec.image } : {}),
        nonce: proof.nonce,
        expires_at: proof.expires_at,
        targets: proof.targets,
        webauthn: proof.webauthn,
      }),
    })
    if (!resp.ok) throw new ControlHttpError(resp.status)
    runId = unwrapEnvelope<{ run_id: string }>(await resp.json()).run_id
    if (!runId) return { kind: 'error', message: 'The controller did not return a run id.' }
  } catch (e) {
    return toOutcome(e)
  }
  onAccepted?.()
  try {
    return await pollRun(runId)
  } catch (e) {
    return toOutcome(e)
  }
}

export interface StewardControl {
  perform: (spec: ActionSpec, justification: string, onAccepted?: () => void) => Promise<ActionOutcome>
  /** Re-polls a run left pending when the poll window ended. */
  refresh: (runId: string) => Promise<ActionOutcome>
}

export function useStewardControl(stewardId: string): StewardControl {
  const perform = useCallback(
    (spec: ActionSpec, justification: string, onAccepted?: () => void) =>
      performAction(stewardId, spec, justification, onAccepted),
    [stewardId],
  )
  const refresh = useCallback(async (runId: string) => {
    try {
      return await pollRun(runId)
    } catch (e) {
      return toOutcome(e)
    }
  }, [])
  return useMemo(() => ({ perform, refresh }), [perform, refresh])
}
