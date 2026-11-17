// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz

/*
 * MSP email sender for the Email delivery page (Issue #6247, Epic #6039).
 *
 * Endpoints covered (every one needs strong assurance; apiFetch runs the passkey
 * step-up and a cancelled ceremony comes back as the original 401):
 *   GET    /api/v1/tenants/{id}/email-sender       → fetchEmailSender / useEmailSender
 *   PUT    /api/v1/tenants/{id}/email-sender       → saveEmailSender
 *   DELETE /api/v1/tenants/{id}/email-sender       → removeEmailSender
 *   POST   /api/v1/tenants/{id}/email-sender/test  → testEmailSender
 *
 * The password is write-only: it appears in the PUT body and nowhere else. No
 * response carries it (`password_present` only says whether one is stored), it is
 * never put in a URL, a log or an error message, and a settings-only edit omits
 * the field so the server keeps the stored one.
 */
import { useCallback, useEffect, useState } from 'react'
import { apiFetch } from '../api/client.ts'
import { crossingChallengeError } from './useTenantCrossings.ts'
import { TenantApiError } from './useTenants.ts'

export type EmailTlsMode = 'starttls' | 'implicit_tls'

export interface EmailSender {
  /** A sender record exists. */
  configured: boolean
  /** A password is stored; its value is never returned. */
  passwordPresent: boolean
  host: string
  port: number
  tlsMode: string
  from: string
  username: string
}

export interface EmailSenderInput {
  host: string
  /** 0 asks for the server default of the TLS mode. */
  port: number
  tlsMode: EmailTlsMode
  from: string
  username: string
  /** Empty keeps the stored password. */
  password: string
}

export interface EmailTestRecipient {
  address: string
  accepted: boolean
  reason: string
}

export interface EmailTestResult {
  delivered: boolean
  recipients: EmailTestRecipient[]
  failureReason: string
}

/** The server's default port for a TLS mode (the MSP sender allows only these two). */
export function defaultPortFor(mode: EmailTlsMode): number {
  return mode === 'implicit_tls' ? 465 : 587
}

export const emptySender: EmailSender = {
  configured: false,
  passwordPresent: false,
  host: '',
  port: 0,
  tlsMode: '',
  from: '',
  username: '',
}

function str(v: unknown): string {
  return typeof v === 'string' ? v : ''
}

/** Parses a sender response; every field is coerced to its type and a malformed payload is "no sender". */
export function parseEmailSender(data: unknown): EmailSender {
  const b = data as Record<string, unknown> | null
  if (typeof b !== 'object' || b === null) return emptySender
  return {
    configured: b.configured === true,
    passwordPresent: b.password_present === true,
    host: str(b.host),
    port: typeof b.port === 'number' && Number.isFinite(b.port) ? b.port : 0,
    tlsMode: str(b.tls_mode),
    from: str(b.from),
    username: str(b.username),
  }
}

/** Parses a test response; recipient fields are coerced and kept as literal strings. */
export function parseEmailTestResult(data: unknown): EmailTestResult {
  const b = data as Record<string, unknown> | null
  const list = typeof b === 'object' && b !== null && Array.isArray(b.recipients) ? b.recipients : []
  const recipients: EmailTestRecipient[] = []
  for (const item of list) {
    const r = item as Record<string, unknown> | null
    if (typeof r !== 'object' || r === null) continue
    recipients.push({ address: str(r.address), accepted: r.accepted === true, reason: str(r.reason) })
  }
  return {
    delivered: b?.delivered === true,
    recipients,
    failureReason: str(b?.failure_reason),
  }
}

async function senderError(response: Response, fallback: string): Promise<TenantApiError> {
  const body = (await response.json().catch(() => ({}))) as Record<string, unknown> | null
  const raw = body?.error
  if (typeof raw === 'string') {
    // The crossing challenge: `{ "error": "tenant_crossing_required", ... }`.
    return new TenantApiError(`${fallback} — ${response.status}`, raw, response.status)
  }
  const envelope = raw as Record<string, unknown> | undefined
  const message =
    typeof envelope?.message === 'string' && envelope.message ? envelope.message : `${fallback} — ${response.status}`
  const code = typeof envelope?.code === 'string' ? envelope.code : ''
  return new TenantApiError(message, code, response.status)
}

function senderPath(tenantId: string): string {
  return `/api/v1/tenants/${encodeURIComponent(tenantId)}/email-sender`
}

function unwrap(body: unknown): unknown {
  const r = body as Record<string, unknown> | null
  return r?.data ?? r
}

export async function fetchEmailSender(tenantId: string): Promise<EmailSender> {
  const response = await apiFetch(senderPath(tenantId))
  if (!response.ok) throw await senderError(response, 'Load email sender failed')
  return parseEmailSender(unwrap(await response.json()))
}

/** Replaces every setting; resolves with the sender the server stored. The password is sent only when non-empty. */
export async function saveEmailSender(tenantId: string, input: EmailSenderInput): Promise<EmailSender> {
  const body: Record<string, unknown> = {
    host: input.host,
    port: input.port,
    tls_mode: input.tlsMode,
    from: input.from,
    username: input.username,
  }
  if (input.password !== '') body.password = input.password
  const response = await apiFetch(senderPath(tenantId), {
    method: 'PUT',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(body),
  })
  if (!response.ok) throw await senderError(response, 'Save email sender failed')
  return parseEmailSender(unwrap(await response.json()))
}

/** Deletes the sender and its stored password. */
export async function removeEmailSender(tenantId: string): Promise<EmailSender> {
  const response = await apiFetch(senderPath(tenantId), { method: 'DELETE' })
  if (!response.ok) throw await senderError(response, 'Remove email sender failed')
  return parseEmailSender(unwrap(await response.json()))
}

/** Sends the fixed test message (empty body) to the sender's own from address. */
export async function testEmailSender(tenantId: string): Promise<EmailTestResult> {
  const response = await apiFetch(`${senderPath(tenantId)}/test`, { method: 'POST' })
  if (!response.ok) throw await senderError(response, 'Send test failed')
  return parseEmailTestResult(unwrap(await response.json()))
}

/** How a failed load is shown. */
export type EmailSenderFailure = 'crossing' | 'forbidden' | 'error'

export interface UseEmailSenderResult {
  sender: EmailSender | null
  loading: boolean
  failure: EmailSenderFailure | null
  /** Server or fallback message for `failure === 'error'`. */
  error: string | null
  refetch: () => void
  /** Replaces the loaded sender with one a save or remove returned. */
  setSender: (sender: EmailSender) => void
}

interface Outcome {
  key: string
  data?: EmailSender
  failure?: EmailSenderFailure
  error?: string
}

export function classifyFailure(cause: unknown): { failure: EmailSenderFailure; error: string } {
  if (cause instanceof TenantApiError) {
    if (cause.status === 401 && cause.code === crossingChallengeError) {
      return { failure: 'crossing', error: cause.message }
    }
    if (cause.status === 403) return { failure: 'forbidden', error: cause.message }
    if (cause.status === 401) return { failure: 'error', error: 'The passkey check was cancelled. Try again.' }
  }
  return { failure: 'error', error: cause instanceof Error && cause.message ? cause.message : 'Request failed' }
}

/** Loads the sender of `tenantId`; `null` disables the fetch. */
export function useEmailSender(tenantId: string | null): UseEmailSenderResult {
  const [attempt, setAttempt] = useState(0)
  const [outcome, setOutcome] = useState<Outcome | null>(null)
  const refetch = useCallback(() => setAttempt((n) => n + 1), [])
  const key = `${tenantId ?? ''}:${attempt}`

  useEffect(() => {
    if (tenantId === null) return
    let cancelled = false
    fetchEmailSender(tenantId).then(
      (data) => {
        if (!cancelled) setOutcome({ key, data })
      },
      (cause: unknown) => {
        if (!cancelled) setOutcome({ key, ...classifyFailure(cause) })
      },
    )
    return () => {
      cancelled = true
    }
  }, [key, tenantId])

  const setSender = useCallback((data: EmailSender) => setOutcome({ key, data }), [key])

  if (tenantId === null) return { sender: null, loading: false, failure: null, error: null, refetch, setSender }
  const current = outcome?.key === key ? outcome : null
  return {
    sender: current?.data ?? null,
    loading: current === null,
    failure: current?.failure ?? null,
    error: current?.error ?? null,
    refetch,
    setSender,
  }
}
