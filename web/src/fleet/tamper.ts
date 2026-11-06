// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz

/*
 * Tampered-steward operator verbs (Story #5668): restore, repair and restore, ban
 * (POST) and the repair state (GET), over the #5667 / N3 endpoints.
 *
 * Passkey step-up: each verb is Strong-assurance. apiFetch answers the controller's
 * CFGMS-StepUp 401 by running the central passkey ceremony and replaying the request,
 * so nothing here signs anything. When the operator cancels (or the ceremony fails)
 * apiFetch hands back the original step-up 401, which maps to `cancelled`: nothing
 * changed and the verb can be retried.
 *
 * Every function resolves to a plain outcome value and never throws, so a dialog can
 * render each case. Wire data is untrusted (a steward on a tampered host supplies the
 * codes); it crosses into the DOM as text only.
 */
import { apiFetch, unwrapEnvelope } from '../api/client.ts'
import type { HealthReason } from './health.ts'

export type TamperOutcome<T> =
  | { kind: 'ok'; value: T }
  /** 409 fault_still_reported: restore refused, offer Repair and restore. */
  | { kind: 'fault_still_reported'; codes: string[]; message: string }
  /** 409 loss_approval_required: the approval did not match; lossCodes is the current set. */
  | { kind: 'loss_approval_required'; lossCodes: string[]; message: string }
  /** Any other 409: someone else already changed the steward. */
  | { kind: 'conflict'; message: string }
  | { kind: 'not_found' }
  | { kind: 'cancelled' }
  | { kind: 'denied' }
  | { kind: 'session_expired' }
  | { kind: 'error'; message: string }

export interface VerbResult {
  status: string
}

export interface RepairAccepted {
  repairId: string
  delivered: boolean
  lossCodes: string[]
}

export type RepairStateName =
  | 'waiting'
  | 'running'
  | 'completed'
  | 'restored'
  | 'failed'
  | 'refused_data_loss'
  | 'cancelled'
  | 'contested'

export interface RepairState {
  repairId: string
  state: RepairStateName
  requestedBy: string
  requestedAt: string
  lossCodes: string[]
  outcomeCodes: string[]
  completedFrom: string
}

const REPAIR_STATES: ReadonlySet<string> = new Set([
  'waiting',
  'running',
  'completed',
  'restored',
  'failed',
  'refused_data_loss',
  'cancelled',
  'contested',
])

/** Repair states in which a request is still in flight (the poll continues). */
export function isRepairActive(state: RepairStateName | undefined): boolean {
  return state === 'waiting' || state === 'running' || state === 'completed'
}

const JSON_HEADERS = { 'Content-Type': 'application/json' }

function stewardPath(stewardId: string, verb: string): string {
  return `/api/v1/stewards/${encodeURIComponent(stewardId)}/tamper/${verb}`
}

function stringList(value: unknown): string[] {
  return Array.isArray(value) ? value.filter((v): v is string => typeof v === 'string') : []
}

async function readBody(resp: Response): Promise<Record<string, unknown>> {
  try {
    const body: unknown = await resp.json()
    return typeof body === 'object' && body !== null ? (body as Record<string, unknown>) : {}
  } catch {
    return {}
  }
}

/** The message of a standard ErrorResponse (`{ error: { code, message } }`), or ''. */
function envelopeError(body: Record<string, unknown>): { code: string; message: string } {
  const e = body.error
  if (typeof e === 'object' && e !== null) {
    const r = e as Record<string, unknown>
    return {
      code: typeof r.code === 'string' ? r.code : '',
      message: typeof r.message === 'string' ? r.message : '',
    }
  }
  return { code: '', message: '' }
}

/**
 * Maps a non-success response. The two machine-readable 409s carry `error` as a
 * string; every other error uses the standard envelope.
 */
async function mapFailure<T>(resp: Response): Promise<TamperOutcome<T>> {
  if (resp.status === 401) {
    return (resp.headers.get('WWW-Authenticate') ?? '').startsWith('CFGMS-StepUp')
      ? { kind: 'cancelled' }
      : { kind: 'session_expired' }
  }
  if (resp.status === 403) return { kind: 'denied' }
  if (resp.status === 404) return { kind: 'not_found' }
  const body = await readBody(resp)
  if (resp.status === 409) {
    const message = typeof body.message === 'string' ? body.message : envelopeError(body).message
    if (body.error === 'fault_still_reported') {
      return { kind: 'fault_still_reported', codes: stringList(body.codes), message }
    }
    if (body.error === 'loss_approval_required') {
      return { kind: 'loss_approval_required', lossCodes: stringList(body.loss_codes), message }
    }
    return { kind: 'conflict', message: message || 'Someone else already changed this steward.' }
  }
  return { kind: 'error', message: `The request failed (${resp.status}).` }
}

async function post<T>(
  path: string,
  body: Record<string, unknown>,
  parse: (data: Record<string, unknown>) => T,
): Promise<TamperOutcome<T>> {
  try {
    const resp = await apiFetch(path, { method: 'POST', headers: JSON_HEADERS, body: JSON.stringify(body) })
    if (!resp.ok) return await mapFailure<T>(resp)
    const data = unwrapEnvelope<Record<string, unknown> | null>(await readBody(resp))
    return { kind: 'ok', value: parse(data ?? {}) }
  } catch {
    return { kind: 'error', message: 'The request could not be sent.' }
  }
}

function reasonBody(reason: string | undefined): Record<string, unknown> {
  return reason !== undefined && reason !== '' ? { reason } : {}
}

/** POST /stewards/{id}/tamper/restore. */
export function restoreSteward(stewardId: string, reason?: string): Promise<TamperOutcome<VerbResult>> {
  return post(stewardPath(stewardId, 'restore'), reasonBody(reason), (d) => ({
    status: typeof d.status === 'string' ? d.status : '',
  }))
}

/** POST /stewards/{id}/tamper/ban. */
export function banSteward(stewardId: string, reason?: string): Promise<TamperOutcome<VerbResult>> {
  return post(stewardPath(stewardId, 'ban'), reasonBody(reason), (d) => ({
    status: typeof d.status === 'string' ? d.status : '',
  }))
}

/**
 * POST /stewards/{id}/tamper/repair. approvedLossCodes must be exactly the loss
 * codes the steward reported (empty when it reported none).
 */
export function repairSteward(
  stewardId: string,
  approvedLossCodes: string[],
  reason?: string,
): Promise<TamperOutcome<RepairAccepted>> {
  return post(
    stewardPath(stewardId, 'repair'),
    { ...reasonBody(reason), approved_loss_codes: approvedLossCodes },
    (d) => ({
      repairId: typeof d.repair_id === 'string' ? d.repair_id : '',
      delivered: d.delivered === true,
      lossCodes: stringList(d.loss_codes),
    }),
  )
}

function parseRepairState(data: Record<string, unknown>): RepairState | null {
  const state = data.state
  if (typeof state !== 'string' || !REPAIR_STATES.has(state)) return null
  const str = (v: unknown) => (typeof v === 'string' ? v : '')
  return {
    repairId: str(data.repair_id),
    state: state as RepairStateName,
    requestedBy: str(data.requested_by),
    requestedAt: str(data.requested_at),
    lossCodes: stringList(data.loss_codes),
    outcomeCodes: stringList(data.outcome_codes),
    completedFrom: str(data.completed_from),
  }
}

/**
 * GET /stewards/{id}/tamper/repair. `ok` with a null value means no repair has
 * been requested (REPAIR_NOT_FOUND); a missing steward is `not_found`.
 */
export async function getRepairState(stewardId: string): Promise<TamperOutcome<RepairState | null>> {
  try {
    const resp = await apiFetch(stewardPath(stewardId, 'repair'))
    if (resp.status === 404) {
      const { code } = envelopeError(await readBody(resp))
      return code === 'REPAIR_NOT_FOUND' ? { kind: 'ok', value: null } : { kind: 'not_found' }
    }
    if (!resp.ok) return await mapFailure<RepairState | null>(resp)
    const data = unwrapEnvelope<Record<string, unknown> | null>(await readBody(resp))
    const parsed = parseRepairState(data ?? {})
    return parsed === null ? { kind: 'error', message: 'The repair state was not understood.' } : { kind: 'ok', value: parsed }
  } catch {
    return { kind: 'error', message: 'The repair state could not be read.' }
  }
}

// ── Reason-code wording ──────────────────────────────────────────────────────

const LOSS_TEXT: ReadonlyMap<string, string> = new Map([
  ['repair.loss.local_logs', 'Local log buffer on the host'],
  ['repair.loss.action_history', 'Local action history on the host'],
])

/** Plain text for a repair.loss.* code; unknown codes are shown as the code itself. */
export function lossText(code: string): string {
  return LOSS_TEXT.get(code) ?? code
}

/** Reported repair.loss.* codes, distinct and sorted. */
export function lossCodesOf(reasons: readonly HealthReason[]): string[] {
  return [...new Set(reasons.map((r) => r.code).filter((c) => c.startsWith('repair.loss.')))].sort()
}

const REPAIR_OUTCOME_TEXT: ReadonlyMap<string, string> = new Map([
  ['repair.failed', 'The steward could not complete the repair.'],
  ['repair.refused_data_loss', 'The steward refused: the repair would lose local data that was not approved.'],
  ['repair.loss_set_changed', 'The local data at risk changed since the repair was requested.'],
  ['repair.not_locked', 'The steward was not locked down when the repair arrived.'],
  ['repair.fault_persists', 'The fault is still present after the repair.'],
  ['repair.signature_invalid', 'The steward could not verify the repair request.'],
  ['repair.anchor_untrusted', 'The steward cannot trust the controller root it has built in.'],
])

/** Failure wording for the outcome codes of a failed repair; unknown codes show as the code. */
export function repairOutcomeText(codes: readonly string[]): string[] {
  return codes
    .filter((c) => c !== 'repair.running' && c !== 'repair.completed' && c !== 'repair.contested')
    .map((c) => REPAIR_OUTCOME_TEXT.get(c) ?? c)
}

const TAMPER_CODE_LABEL: ReadonlyMap<string, string> = new Map([
  ['tamper_data_dir', 'Data folder rights changed'],
  ['tamper_security_profile', 'Security profile downgraded'],
])

/** Human label for a tamper code, or '' when the code has no known wording. */
export function tamperCodeLabel(code: string): string {
  return TAMPER_CODE_LABEL.get(code) ?? ''
}

const LOCKED_TOOLS_TEXT: ReadonlyMap<string, string> = new Map([
  ['locked_tools.no_baked_root', "Its steward was installed without this controller's root certificate built in, so it cannot check that a command really comes from an operator."],
  ['locked_tools.baked_root_malformed', "The root certificate built into its steward is not valid, so it cannot check that a command really comes from an operator."],
  ['locked_tools.root_mismatch', 'The certificate chain on the command does not lead to a root certificate built into its steward.'],
  ['locked_tools.link_not_anchored', "The connection the command arrived on is not secured by the root certificate built into its steward."],
  ['locked_tools.revocation_stale', 'Its steward has no recent enough revocation list signed by its built-in root, so it cannot tell whether the operator is still trusted.'],
])

/** One plain-language reason per reported locked_tools.* code, in the order reported. */
export function lockedToolsReasons(reasons: readonly HealthReason[]): { code: string; text: string }[] {
  const seen = new Set<string>()
  const out: { code: string; text: string }[] = []
  for (const r of reasons) {
    if (!r.code.startsWith('locked_tools.') || seen.has(r.code)) continue
    seen.add(r.code)
    out.push({
      code: r.code,
      text: LOCKED_TOOLS_TEXT.get(r.code) ?? 'Its steward cannot check that a command really comes from an operator.',
    })
  }
  return out
}

/** True when the steward reports that repair cannot be trusted on this host. */
export function hasAnchorUntrusted(reasons: readonly HealthReason[]): boolean {
  return reasons.some((r) => r.code === 'repair.anchor_untrusted')
}

// ── Host name confirmation ───────────────────────────────────────────────────

// Control characters, line/paragraph separators, and bidirectional controls and marks.
const HIDDEN_CHARS = new RegExp('[\\p{Cc}\\u061C\\u200E\\u200F\\u2028\\u2029\\u202A-\\u202E\\u2066-\\u2069]', 'gu')

/** Replaces control and bidi code points with a visible \u{HEX} escape. */
export function escapeHidden(name: string): string {
  return name.replace(HIDDEN_CHARS, (c) => `\\u{${c.codePointAt(0)!.toString(16).toUpperCase()}}`)
}

export function hasHiddenChars(name: string): boolean {
  return escapeHidden(name) !== name
}

/**
 * True when typed is the host name: an exact code-point match. A name with control
 * or bidi characters cannot be typed, so its escaped rendering (the exact code
 * points spelled out) is accepted for it.
 */
export function banNameMatches(typed: string, expected: string): boolean {
  if (expected === '') return false
  if (typed === expected) return true
  return hasHiddenChars(expected) && typed === escapeHidden(expected)
}
