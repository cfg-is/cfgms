// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz

/*
 * Test harness for the signed-action flow (Story #4629): a fetch stub that
 * answers prepare / sign begin / sign finish / action / run polling the way the
 * controller does, and a navigator.credentials stub for the passkey prompt.
 */
import { vi } from 'vitest'

export interface Call {
  url: string
  method: string
  body: unknown
}

export interface HarnessOptions {
  actionStatus?: number
  beginStatus?: number
  beginCode?: string
  /** Sequence of job views returned by successive polls; the last repeats. */
  jobs?: Array<Record<string, unknown>>
  pollStatus?: number
  /** Overrides what prepare returns for `content` (to simulate a mismatch). */
  prepareContent?: string
  /** Overrides the targets the begin envelope carries. */
  beginTargets?: string[]
}

export const ENVELOPE = {
  nonce: 'nonce-abc',
  expires_at: '2099-01-01T00:00:00Z',
  targets: ['st-1'],
}

export const PROOF = {
  authenticator_data: 'QUQ=',
  client_data_json: 'Q0Q=',
  signature: 'U0c=',
  credential_id: 'Q0k=',
}

export function contentFor(verb: string, kind: string, name: string, image?: string): string {
  return btoa(
    JSON.stringify({ v: 1, verb, target_kind: kind, target_name: name, parameters: image ? { image } : {} }),
  )
}

function json(body: unknown, status = 200): Response {
  return new Response(JSON.stringify(body), { status, headers: { 'Content-Type': 'application/json' } })
}

export function installHarness(opts: HarnessOptions = {}) {
  const calls: Call[] = []
  let polls = 0
  const state = { jobs: opts.jobs ?? [{ status: 'completed', result_code: 'ok' }] }
  const credGet = vi.fn<(o: unknown) => Promise<unknown>>()
  credGet.mockResolvedValue({
    id: 'cred-id',
    type: 'public-key',
    rawId: new Uint8Array([1, 2, 3]).buffer,
    response: {
      authenticatorData: new Uint8Array([4]).buffer,
      clientDataJSON: new Uint8Array([5]).buffer,
      signature: new Uint8Array([6]).buffer,
      userHandle: null,
    },
  })
  Object.defineProperty(navigator, 'credentials', { value: { get: credGet }, configurable: true })

  const fetchStub = vi.fn(async (input: RequestInfo | URL, init?: RequestInit) => {
    const url = String(input)
    const method = (init?.method ?? 'GET').toUpperCase()
    const body = init?.body ? JSON.parse(String(init.body)) : undefined
    calls.push({ url, method, body })
    if (url.endsWith('/actions/prepare')) {
      const b = body as { target_kind: string; target_name: string; action: string; image?: string }
      return json({
        data: {
          content: opts.prepareContent ?? contentFor(`${b.target_kind}.${b.action}`, b.target_kind, b.target_name, b.image),
          shell: 'steward-action',
        },
      })
    }
    if (url.endsWith('/operator-payload/sign/begin')) {
      if (opts.beginStatus) {
        return json({ error: { code: opts.beginCode ?? 'X', message: 'm' } }, opts.beginStatus)
      }
      return json({
        data: {
          assertion: { publicKey: { challenge: 'AQID', allowCredentials: [{ type: 'public-key', id: 'BAUG' }] } },
          envelope: { ...ENVELOPE, targets: opts.beginTargets ?? [(body as { selector: string }).selector.replace(/^id:/, '')] },
          envelope_hash: 'h',
        },
      })
    }
    if (url.endsWith('/operator-payload/sign/finish')) return json({ data: { ...PROOF, envelope: ENVELOPE } })
    if (url.endsWith('/actions')) {
      if (opts.actionStatus && opts.actionStatus !== 202) return json({ error: { code: 'DENIED' } }, opts.actionStatus)
      return json({ run_id: 'run-1' }, 202)
    }
    if (url.includes('/runs/')) {
      if (opts.pollStatus) return json({ error: { code: 'DENIED' } }, opts.pollStatus)
      const seq = state.jobs
      const job = seq[Math.min(polls, seq.length - 1)]
      polls++
      return json({ data: [job] })
    }
    return json({}, 404)
  })
  vi.stubGlobal('fetch', fetchStub)
  return { calls, credGet, fetchStub, state }
}
