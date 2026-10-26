// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz

/*
 * useUpgrade test suite (Issue #5445). The network edge (global fetch) is
 * stubbed; the real apiFetch and hook run. Polling uses fake timers.
 */
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'
import { act, cleanup, renderHook } from '@testing-library/react'
import {
  UPGRADE_POLL_MS,
  isTerminalUpgradeStatus,
  parseUpgradeDispatch,
  parseUpgradeRecord,
  useUpgrade,
} from './useUpgrade.ts'

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
  return fetchMock.mock.calls.filter(([u]) => String(u) === '/api/v1/stewards/upgrade/up-1')
}

async function startWith(statuses: string[]) {
  let i = 0
  fetchMock.mockImplementation((input, init) => {
    const url = String(input)
    if (url === '/api/v1/stewards/upgrade' && init?.method === 'POST') {
      return Promise.resolve(res(202, { data: { upgrade_id: 'up-1', steward_count: 1, status: 'accepted' } }))
    }
    const status = statuses[Math.min(i++, statuses.length - 1)]
    return Promise.resolve(res(200, { data: { ID: 'up-1', Status: status } }))
  })
  const hook = renderHook(() => useUpgrade())
  await act(async () => {
    await hook.result.current.startUpgrade({ selector: 'os:linux', version: '1', platform: 'linux', arch: 'amd64' })
  })
  return hook
}

describe('useUpgrade', () => {
  it('stops polling at committed, rolled_back and failed', async () => {
    for (const terminal of ['committed', 'rolled_back', 'failed']) {
      fetchMock.mockReset()
      const hook = await startWith(['dispatched', terminal])
      expect(statusCalls()).toHaveLength(1)
      await act(async () => { await vi.advanceTimersByTimeAsync(UPGRADE_POLL_MS) })
      expect(statusCalls()).toHaveLength(2)
      expect(hook.result.current.record?.status).toBe(terminal)
      await act(async () => { await vi.advanceTimersByTimeAsync(UPGRADE_POLL_MS * 5) })
      expect(statusCalls()).toHaveLength(2)
      hook.unmount()
    }
  })

  it('keeps polling every 3 seconds while non-terminal and clears on unmount', async () => {
    const hook = await startWith(['dispatched'])
    await act(async () => { await vi.advanceTimersByTimeAsync(UPGRADE_POLL_MS * 2) })
    expect(statusCalls()).toHaveLength(3)
    hook.unmount()
    await act(async () => { await vi.advanceTimersByTimeAsync(UPGRADE_POLL_MS * 5) })
    expect(statusCalls()).toHaveLength(3)
  })

  it('reports a poll failure and keeps retrying', async () => {
    const hook = await startWith(['dispatched'])
    fetchMock.mockImplementation(() => Promise.resolve(res(500, {})))
    await act(async () => { await vi.advanceTimersByTimeAsync(UPGRADE_POLL_MS) })
    expect(hook.result.current.pollError).not.toBeNull()
  })
})

describe('parsers', () => {
  it('validates the wire shapes', () => {
    expect(parseUpgradeDispatch({ data: { upgrade_id: 'a', steward_count: 3, status: 'accepted' } })).toEqual({
      upgradeId: 'a', stewardCount: 3, status: 'accepted',
    })
    expect(parseUpgradeDispatch({ data: {} })).toBeNull()
    expect(parseUpgradeDispatch(null)).toBeNull()
    expect(parseUpgradeRecord({ data: { Status: 'failed', ErrorMessage: 'x' } })?.errorMessage).toBe('x')
    expect(parseUpgradeRecord({ data: { Status: 5 } })).toBeNull()
    expect(isTerminalUpgradeStatus('committed')).toBe(true)
    expect(isTerminalUpgradeStatus('swapped')).toBe(false)
  })
})
