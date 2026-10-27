// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz

/*
 * Account certificate bindings (Issue #5448, Epic #5300).
 *
 * Endpoints covered (handlers_cert_bindings.go):
 *   GET  /api/v1/accounts/{u}/certs                       → fetchCertBindings / useCertBindings
 *   POST /api/v1/accounts/{u}/certs/bind                  → bindCert
 *   POST /api/v1/accounts/{u}/certs/revoke/{serial}       → revokeCert
 *   POST /api/v1/accounts/{u}/certs/rotate/{old_serial}   → rotateCert
 *
 * The writes are Strong-assurance gated; apiFetch runs the elevation ceremony
 * transparently and retries, so nothing here handles the 401 itself.
 */
import { useCallback, useEffect, useState } from 'react'
import { apiFetch } from '../api/client.ts'

export interface CertBinding {
  serial: string
  fingerprint: string
  label: string
  boundAt: string
  lastUsedAt: string | null
  humanApprovedAt: string | null
}

function optionalString(value: unknown): string | null {
  return typeof value === 'string' && value !== '' ? value : null
}

/** Validates one CertBindingInfo; null when serial, fingerprint or bound_at is missing. */
export function parseCertBinding(value: unknown): CertBinding | null {
  if (typeof value !== 'object' || value === null) return null
  const r = value as Record<string, unknown>
  if (typeof r.serial !== 'string' || r.serial === '') return null
  if (typeof r.fingerprint !== 'string' || r.fingerprint === '') return null
  if (typeof r.bound_at !== 'string' || r.bound_at === '') return null
  return {
    serial: r.serial,
    fingerprint: r.fingerprint,
    label: typeof r.label === 'string' ? r.label : '',
    boundAt: r.bound_at,
    lastUsedAt: optionalString(r.last_used_at),
    humanApprovedAt: optionalString(r.human_approved_at),
  }
}

/** Reads the `{ data: [...] }` list envelope; malformed entries are dropped. */
export function parseCertBindingList(body: unknown): CertBinding[] {
  const envelope = body as Record<string, unknown> | null
  const list = typeof envelope === 'object' && envelope !== null ? envelope.data : null
  if (!Array.isArray(list)) return []
  const out: CertBinding[] = []
  for (const item of list) {
    const parsed = parseCertBinding(item)
    if (parsed !== null) out.push(parsed)
  }
  return out
}

function certsPath(username: string): string {
  return `/api/v1/accounts/${encodeURIComponent(username)}/certs`
}

async function failure(response: Response, fallback: string): Promise<Error> {
  const body = (await response.json().catch(() => ({}))) as Record<string, unknown> | null
  const envelope = body?.error as Record<string, unknown> | undefined
  const message = typeof envelope?.message === 'string' && envelope.message ? envelope.message : ''
  return new Error(message || `${fallback} — ${response.status}`)
}

export async function fetchCertBindings(username: string): Promise<CertBinding[]> {
  const response = await apiFetch(certsPath(username))
  if (!response.ok) throw await failure(response, 'Load certificates failed')
  return parseCertBindingList(await response.json())
}

export async function bindCert(
  username: string,
  input: { serial: string; fingerprint: string; label?: string },
): Promise<void> {
  const body: Record<string, string> = { serial: input.serial, fingerprint: input.fingerprint }
  if (input.label) body.label = input.label
  const response = await apiFetch(`${certsPath(username)}/bind`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(body),
  })
  if (!response.ok) throw await failure(response, 'Bind failed')
}

export async function revokeCert(username: string, serial: string): Promise<void> {
  const response = await apiFetch(`${certsPath(username)}/revoke/${encodeURIComponent(serial)}`, {
    method: 'POST',
  })
  if (!response.ok) throw await failure(response, 'Revoke failed')
}

/** Replaces `oldSerial` with the new certificate; the old serial rides in the path. */
export async function rotateCert(
  username: string,
  oldSerial: string,
  next: { serial: string; fingerprint?: string },
): Promise<void> {
  const body: Record<string, string> = { serial: next.serial }
  if (next.fingerprint) body.fingerprint = next.fingerprint
  const response = await apiFetch(`${certsPath(username)}/rotate/${encodeURIComponent(oldSerial)}`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(body),
  })
  if (!response.ok) throw await failure(response, 'Rotate failed')
}

export interface UseCertBindingsResult {
  bindings: CertBinding[]
  loading: boolean
  error: string | null
  refetch: () => void
}

interface Outcome {
  key: string
  data?: CertBinding[]
  error?: string
}

export function useCertBindings(username: string): UseCertBindingsResult {
  const [attempt, setAttempt] = useState(0)
  const [outcome, setOutcome] = useState<Outcome | null>(null)
  const refetch = useCallback(() => setAttempt((n) => n + 1), [])
  const key = `${username}:${attempt}`

  useEffect(() => {
    let cancelled = false
    fetchCertBindings(username).then(
      (data) => {
        if (!cancelled) setOutcome({ key, data })
      },
      (cause: unknown) => {
        if (cancelled) return
        setOutcome({ key, error: cause instanceof Error && cause.message ? cause.message : 'Request failed' })
      },
    )
    return () => {
      cancelled = true
    }
  }, [key, username])

  const current = outcome?.key === key ? outcome : null
  return { bindings: current?.data ?? [], loading: current === null, error: current?.error ?? null, refetch }
}
