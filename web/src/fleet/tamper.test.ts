// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz

/*
 * tamper.ts suite (Story #5668): request shape and error mapping for the restore,
 * ban and repair verbs and the repair state read.
 */
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'
import {
  banNameMatches,
  banSteward,
  escapeHidden,
  getRepairState,
  lockedToolsReasons,
  lossCodesOf,
  repairSteward,
  restoreSteward,
} from './tamper.ts'

const fetchMock = vi.fn<typeof fetch>()

beforeEach(() => {
  fetchMock.mockReset()
  vi.stubGlobal('fetch', fetchMock)
})
afterEach(() => vi.unstubAllGlobals())

function json(status: number, body: unknown, headers: Record<string, string> = {}): Response {
  return new Response(JSON.stringify(body), {
    status,
    headers: { 'Content-Type': 'application/json', ...headers },
  })
}

function lastCall(): { path: string; init: RequestInit; body: Record<string, unknown> } {
  const [path, init] = fetchMock.mock.calls.at(-1)!
  return { path: String(path), init: init!, body: JSON.parse(String(init!.body ?? '{}')) as Record<string, unknown> }
}

describe('request shape', () => {
  it('restore POSTs to the tamper/restore path with the id encoded', async () => {
    fetchMock.mockResolvedValue(json(200, { data: { id: 'a/b', status: 'active' } }))
    const out = await restoreSteward('a/b')
    expect(out).toEqual({ kind: 'ok', value: { status: 'active' } })
    const call = lastCall()
    expect(call.path).toBe('/api/v1/stewards/a%2Fb/tamper/restore')
    expect(call.init.method).toBe('POST')
    expect(call.body).toEqual({})
  })

  it('ban POSTs to the tamper/ban path', async () => {
    fetchMock.mockResolvedValue(json(200, { data: { status: 'revoked' } }))
    const out = await banSteward('stw-1', 'compromised')
    expect(out).toEqual({ kind: 'ok', value: { status: 'revoked' } })
    expect(lastCall().path).toBe('/api/v1/stewards/stw-1/tamper/ban')
    expect(lastCall().body).toEqual({ reason: 'compromised' })
  })

  it('repair sends exactly the approved loss codes', async () => {
    fetchMock.mockResolvedValue(
      json(202, { data: { repair_id: 'r1', state: 'waiting', delivered: true, loss_codes: ['repair.loss.local_logs'] } }),
    )
    const out = await repairSteward('stw-1', ['repair.loss.local_logs'])
    expect(out).toEqual({ kind: 'ok', value: { repairId: 'r1', delivered: true, lossCodes: ['repair.loss.local_logs'] } })
    expect(lastCall().path).toBe('/api/v1/stewards/stw-1/tamper/repair')
    expect(lastCall().body).toEqual({ approved_loss_codes: ['repair.loss.local_logs'] })
  })

  it('repair with no loss sends an empty list, not a missing field', async () => {
    fetchMock.mockResolvedValue(json(202, { data: { repair_id: 'r2' } }))
    await repairSteward('stw-1', [])
    expect(lastCall().body).toEqual({ approved_loss_codes: [] })
  })

  it('repair state GETs the same path', async () => {
    fetchMock.mockResolvedValue(
      json(200, {
        data: {
          repair_id: 'r1',
          state: 'completed',
          requested_by: 'ana',
          requested_at: '2026-11-06T10:00:00Z',
          loss_codes: [],
          outcome_codes: ['repair.completed'],
          completed_from: 'edge',
        },
      }),
    )
    const out = await getRepairState('stw-1')
    expect(out.kind).toBe('ok')
    if (out.kind === 'ok') expect(out.value).toMatchObject({ state: 'completed', requestedBy: 'ana', outcomeCodes: ['repair.completed'] })
    expect(lastCall().init.method).toBeUndefined()
  })
})

describe('error mapping', () => {
  it('maps 409 fault_still_reported with its codes', async () => {
    fetchMock.mockResolvedValue(
      json(409, { error: 'fault_still_reported', codes: ['tamper_data_dir'], message: 'still faulted' }),
    )
    expect(await restoreSteward('s')).toEqual({
      kind: 'fault_still_reported',
      codes: ['tamper_data_dir'],
      message: 'still faulted',
    })
  })

  it('maps 409 loss_approval_required with the current loss list', async () => {
    fetchMock.mockResolvedValue(
      json(409, { error: 'loss_approval_required', loss_codes: ['repair.loss.action_history'], message: 'approve' }),
    )
    expect(await repairSteward('s', [])).toEqual({
      kind: 'loss_approval_required',
      lossCodes: ['repair.loss.action_history'],
      message: 'approve',
    })
  })

  it('maps any other 409 to a conflict that carries the server message', async () => {
    fetchMock.mockResolvedValue(
      json(409, { error: { code: 'STEWARD_NOT_TAMPERED', message: 'Steward is active, not tampered' } }),
    )
    expect(await banSteward('s')).toEqual({ kind: 'conflict', message: 'Steward is active, not tampered' })
  })

  it('maps 404, 403 and 500', async () => {
    fetchMock.mockResolvedValueOnce(json(404, { error: { code: 'STEWARD_NOT_FOUND', message: 'x' } }))
    expect((await restoreSteward('s')).kind).toBe('not_found')
    fetchMock.mockResolvedValueOnce(json(403, {}))
    expect((await restoreSteward('s')).kind).toBe('denied')
    fetchMock.mockResolvedValueOnce(json(500, {}))
    expect(await restoreSteward('s')).toEqual({ kind: 'error', message: 'The request failed (500).' })
  })

  it('maps a cancelled passkey (step-up 401 handed back) to cancelled', async () => {
    fetchMock.mockResolvedValue(json(401, {}, { 'WWW-Authenticate': 'CFGMS-StepUp required="strong"' }))
    expect((await banSteward('s')).kind).toBe('cancelled')
  })

  it('maps a plain 401 to session_expired, not cancelled', async () => {
    fetchMock.mockResolvedValue(json(401, {}))
    expect((await banSteward('s')).kind).toBe('session_expired')
  })

  it('maps a network failure to an error without throwing', async () => {
    fetchMock.mockRejectedValue(new Error('offline'))
    expect((await restoreSteward('s')).kind).toBe('error')
  })

  it('treats REPAIR_NOT_FOUND on the state read as no repair, and other 404s as not_found', async () => {
    fetchMock.mockResolvedValueOnce(json(404, { error: { code: 'REPAIR_NOT_FOUND', message: 'none' } }))
    expect(await getRepairState('s')).toEqual({ kind: 'ok', value: null })
    fetchMock.mockResolvedValueOnce(json(404, { error: { code: 'STEWARD_NOT_FOUND', message: 'none' } }))
    expect((await getRepairState('s')).kind).toBe('not_found')
  })

  it('rejects an unknown repair state value', async () => {
    fetchMock.mockResolvedValue(json(200, { data: { state: 'bogus' } }))
    expect((await getRepairState('s')).kind).toBe('error')
  })
})

describe('reason helpers', () => {
  it('lossCodesOf keeps only distinct repair.loss.* codes, sorted', () => {
    expect(
      lossCodesOf([
        { component: 'repair', code: 'repair.loss.local_logs' },
        { component: 'repair', code: 'repair.running' },
        { component: 'repair', code: 'repair.loss.action_history' },
        { component: 'repair', code: 'repair.loss.local_logs' },
      ]),
    ).toEqual(['repair.loss.action_history', 'repair.loss.local_logs'])
  })

  it('lockedToolsReasons gives one wording per code and ignores other codes', () => {
    const codes = [
      'locked_tools.no_baked_root',
      'locked_tools.baked_root_malformed',
      'locked_tools.root_mismatch',
      'locked_tools.link_not_anchored',
      'locked_tools.revocation_stale',
    ]
    const out = lockedToolsReasons([
      { component: 'x', code: 'tamper_data_dir' },
      ...codes.map((code) => ({ component: 'locked_tools', code })),
      { component: 'locked_tools', code: 'locked_tools.root_mismatch' },
    ])
    expect(out.map((o) => o.code)).toEqual(codes)
    expect(new Set(out.map((o) => o.text)).size).toBe(5)
  })
})

describe('ban name confirmation', () => {
  it('matches only the exact name', () => {
    expect(banNameMatches('WS-ACCT-07', 'WS-ACCT-07')).toBe(true)
    expect(banNameMatches('ws-acct-07', 'WS-ACCT-07')).toBe(false)
    expect(banNameMatches('WS-ACCT-07 ', 'WS-ACCT-07')).toBe(false)
    expect(banNameMatches('', '')).toBe(false)
  })

  it('does not fold visually similar code points', () => {
    expect(banNameMatches('hostа', 'hosta')).toBe(false)
    expect(banNameMatches('é', 'é')).toBe(false)
  })

  it('escapes control and bidi characters and accepts the escaped spelling for them', () => {
    const bidi = String.fromCharCode(0x202e)
    const name = `a${bidi}b${String.fromCharCode(7)}`
    expect(escapeHidden(name)).toBe('a\\u{202E}b\\u{7}')
    expect(banNameMatches('a\\u{202E}b\\u{7}', name)).toBe(true)
    expect(banNameMatches('a\\u{202E}b', name)).toBe(false)
  })
})
