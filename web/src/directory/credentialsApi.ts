// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz

/*
 * Pending-credential client (Issue #5566) — the #5559 routes:
 *   GET  /api/v1/directory/credentials              → listCredentials (credential-list)
 *   POST /api/v1/directory/credentials/{id}/reveal  → revealCredential (Strong + presence tap)
 *
 * The step-up and the presence tap are handled by the apiFetch interceptor and
 * StepUpModal (web/src/auth); this module never reads or sends a presence token and
 * never touches WebAuthn. When the tap is cancelled or fails the interceptor does not
 * retry, the 401 comes back here, and revealCredential throws without a value.
 *
 * Secret handling: the record id is the only thing in the URL; the request has no body
 * and the password is read from the response, returned to the caller and nothing else —
 * it is never logged, stored, or placed in an error message. Error messages carry an
 * HTTP status only; no response body text is ever copied into one.
 *
 * Security A9.1: every wire value is coerced through a parser and rendered as text.
 */
import { apiFetch, unwrapEnvelope } from '../api/client.ts'

const credentialsPath = '/api/v1/directory/credentials'

export interface PendingCredential {
  id: string
  resource_id: string
  created_at: string
  expires_at: string
}

/** A reveal either returns the one-time value or reports that it is gone. */
export type RevealResult = { status: 'revealed'; password: string } | { status: 'gone' }

export class CredentialsError extends Error {
  readonly httpStatus: number
  constructor(message: string, httpStatus: number) {
    super(message)
    this.name = 'CredentialsError'
    this.httpStatus = httpStatus
  }
}

function str(value: unknown): string {
  return typeof value === 'string' ? value : ''
}

export function parsePendingCredential(value: unknown): PendingCredential | null {
  if (typeof value !== 'object' || value === null) return null
  const r = value as Record<string, unknown>
  const id = str(r.id)
  if (!id) return null
  return {
    id,
    resource_id: str(r.resource_id),
    created_at: str(r.created_at),
    expires_at: str(r.expires_at),
  }
}

/** Accepts `{ items }`; null/absent items is an empty list, any other shape throws. */
export function parsePendingCredentialList(data: unknown): PendingCredential[] {
  if (data === null || data === undefined) return []
  if (typeof data !== 'object' || Array.isArray(data)) throw new Error('unexpected response shape')
  const items = (data as Record<string, unknown>).items
  if (items === null || items === undefined) return []
  if (!Array.isArray(items)) throw new Error('unexpected response shape')
  const list: PendingCredential[] = []
  for (const item of items) {
    const parsed = parsePendingCredential(item)
    if (parsed !== null) list.push(parsed)
  }
  return list
}

/** The password of a reveal response, or null when the shape is wrong or it is empty. */
export function parseRevealedPassword(data: unknown): string | null {
  if (typeof data !== 'object' || data === null) return null
  const password = (data as Record<string, unknown>).password
  return typeof password === 'string' && password.length > 0 ? password : null
}

export async function listCredentials(): Promise<PendingCredential[]> {
  const response = await apiFetch(credentialsPath)
  if (!response.ok) throw new CredentialsError(`GET ${credentialsPath} — ${response.status}`, response.status)
  return parsePendingCredentialList(unwrapEnvelope<unknown>(await response.json()))
}

function revealFailure(status: number): CredentialsError {
  switch (status) {
    case 401:
      return new CredentialsError('Presence confirmation was not completed — nothing was revealed', status)
    case 403:
      return new CredentialsError('You do not have permission to reveal this credential', status)
    case 404:
      return new CredentialsError('This credential was not found', status)
    case 409:
      return new CredentialsError('A reveal of this credential is in progress — try again shortly', status)
    default:
      return new CredentialsError(`Reveal failed — ${status}`, status)
  }
}

/**
 * Reveals the one-time password of a pending record. A 410 is the neutral
 * "already revealed" outcome, not an error. Any other failure throws a
 * CredentialsError that never carries the value or response text.
 */
export async function revealCredential(id: string): Promise<RevealResult> {
  const response = await apiFetch(`${credentialsPath}/${encodeURIComponent(id)}/reveal`, { method: 'POST' })
  if (response.status === 410) return { status: 'gone' }
  if (!response.ok) throw revealFailure(response.status)
  let body: unknown
  try {
    body = await response.json()
  } catch {
    throw new CredentialsError('Unexpected response from the reveal request', response.status)
  }
  const revealed = parseRevealedPassword(unwrapEnvelope<unknown>(body))
  if (revealed === null) throw new CredentialsError('Unexpected response from the reveal request', response.status)
  return { status: 'revealed', password: revealed }
}
