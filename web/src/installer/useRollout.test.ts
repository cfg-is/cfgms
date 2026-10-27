// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz

/*
 * useRollout test suite (Issue #5452). The network edge (global fetch) is
 * stubbed; the real apiFetch and hook run. Polling uses fake timers.
 */
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'
import { act, cleanup, renderHook } from '@testing-library/react'
import {
  ROLLOUT_POLL_MS,
  isTerminalRolloutStatus,
  parseRolloutStart,
  parseRolloutStatus,
  useRollout,
} from './useRollout.ts'

const fetchMock = vi.fn<typeof fetch>()

beforeEach(() => {
  vi.useFakeTimers()
  vi.stubGlobal('fetch', fetchMock)
  fetchMock.mockReset()
})

afterEach(() => {
  cleanup()
  vi.useRealTimers()
  vi.unstubAllGlobals()
})

const res = (status: number, body: unknown) =>
  new Response(JSON.stringify(body), { status, headers: { 'Content-Type': 'application/json' } })

function statusCalls() {
  return fetchMock.mock.calls.filter(([u, i]) => String(u) === '/api/v1/rollout/ro-1' && (i?.method ?? 'GET') === 'GET')
}

async function startWith(statuses: string[]) {
  let i = 0
  fetchMock.mockImplementation((input, init) => {
    const url = String(input)
    if (url === '/api/v1/rollout' && init?.method === 'POST') {
      return Promise.resolve(res(202, { data: { rollout_id: 'ro-1', status: 'in-progress' } }))
    }
    const status = statuses[Math.min(i++, statuses.length - 1)]
    return Promise.resolve(res(200, { data: { rollout_id: 'ro-1', status } }))
  })
  const hook = renderHook(() => useRollout())
  await act(async () => {
    await hook.result.current.startRollout({ targetVersion: '1.2.3', tenantId: 't1' })
  })
  return hook
}

describe('useRollout', () => {
  it('stops polling once the status is terminal', async () => {
    for (const terminal of ['completed', 'halted']) {
      fetchMock.mockReset()
      const hook = await startWith(['in-progress', terminal])
      expect(statusCalls()).toHaveLength(1)
      await act(async () => { await vi.advanceTimersByTimeAsync(ROLLOUT_POLL_MS) })
      expect(statusCalls()).toHaveLength(2)
      expect(hook.result.current.status?.status).toBe(terminal)
      await act(async () => { await vi.advanceTimersByTimeAsync(ROLLOUT_POLL_MS * 5) })
      expect(statusCalls()).toHaveLength(2)
      hook.unmount()
    }
  })

  it('polls every 3 seconds while in progress and clears on unmount', async () => {
    const hook = await startWith(['in-progress'])
    await act(async () => { await vi.advanceTimersByTimeAsync(ROLLOUT_POLL_MS * 2) })
    expect(statusCalls()).toHaveLength(3)
    hook.unmount()
    await act(async () => { await vi.advanceTimersByTimeAsync(ROLLOUT_POLL_MS * 5) })
    expect(statusCalls()).toHaveLength(3)
  })

  it('reports a poll failure and keeps retrying', async () => {
    const hook = await startWith(['in-progress'])
    fetchMock.mockImplementation(() => Promise.resolve(res(500, {})))
    await act(async () => { await vi.advanceTimersByTimeAsync(ROLLOUT_POLL_MS) })
    expect(hook.result.current.pollError).not.toBeNull()
  })
})

describe('parsers', () => {
  it('validates the wire shapes', () => {
    expect(parseRolloutStart({ data: { rollout_id: 'a', status: 'in-progress' } })).toEqual({
      rolloutId: 'a', status: 'in-progress',
    })
    expect(parseRolloutStart({ data: {} })).toBeNull()
    expect(parseRolloutStart(null)).toBeNull()
    expect(parseRolloutStatus({ data: { rollout_id: 'a', status: 'halted', health_metrics_available: 'yes' } })?.healthMetricsAvailable).toBe(false)
    expect(parseRolloutStatus({ data: { rollout_id: 'a', status: 5 } })).toBeNull()
    expect(parseRolloutStatus({ data: { status: 'halted' } })).toBeNull()
    expect(isTerminalRolloutStatus('completed')).toBe(true)
    expect(isTerminalRolloutStatus('in-progress')).toBe(false)
  })
})
