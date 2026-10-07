// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz

/*
 * useCaseWatch tests (Story #3613).
 *
 * Verifies:
 *  - Hook exposes isLive=false and connectedSince=null before the socket opens.
 *  - Hook sets isLive=true and connectedSince on socket open.
 *  - Hook dispatches typed WatchEvents to lastEvent on a valid "event" frame.
 *  - Hook ignores unknown frame types and malformed JSON without throwing.
 *  - Hook resets to not-connected state when the socket closes.
 *  - Hook closes the socket on unmount to avoid leaks.
 *
 * WebSocket is replaced with a synchronous FakeWebSocket so tests run without
 * a real network connection. FakeWebSocket instances are captured by URL for
 * per-connection access.
 */
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'
import { cleanup, renderHook, act } from '@testing-library/react'
import { useCaseWatch } from './useCaseWatch.ts'

class FakeWebSocket {
  static instances: FakeWebSocket[] = []

  readyState: number = WebSocket.CONNECTING
  onopen: ((e: Event) => void) | null = null
  onmessage: ((e: MessageEvent) => void) | null = null
  onclose: ((e: CloseEvent) => void) | null = null
  onerror: ((e: Event) => void) | null = null

  url: string

  constructor(url: string) {
    // Explicit field + assignment: TS parameter properties are not erasable
    // syntax, which this project's tsconfig disallows.
    this.url = url
    FakeWebSocket.instances.push(this)
  }

  close() {
    this.readyState = WebSocket.CLOSED
    this.onclose?.(new CloseEvent('close'))
  }

  // Test-side helpers
  simulateOpen() {
    this.readyState = WebSocket.OPEN
    this.onopen?.(new Event('open'))
  }

  simulateMessage(data: string) {
    this.onmessage?.(new MessageEvent('message', { data }))
  }

  simulateClose() {
    this.readyState = WebSocket.CLOSED
    this.onclose?.(new CloseEvent('close'))
  }

  // The hook never sends application frames.
  send() {}
}

beforeEach(() => {
  FakeWebSocket.instances = []
  vi.stubGlobal('WebSocket', FakeWebSocket)
})

afterEach(() => {
  vi.unstubAllGlobals()
  cleanup()
})

function latestSocket(): FakeWebSocket {
  const s = FakeWebSocket.instances.at(-1)
  if (!s) throw new Error('no FakeWebSocket created')
  return s
}

describe('useCaseWatch', () => {
  it('starts as not-connected before the socket opens', () => {
    const { result } = renderHook(() => useCaseWatch('case-001'))
    expect(result.current.isLive).toBe(false)
    expect(result.current.connectedSince).toBeNull()
    expect(result.current.lastEvent).toBeNull()
  })

  it('sets isLive and connectedSince on socket open', () => {
    const { result } = renderHook(() => useCaseWatch('case-001'))
    act(() => { latestSocket().simulateOpen() })
    expect(result.current.isLive).toBe(true)
    expect(result.current.connectedSince).toBeInstanceOf(Date)
    expect(result.current.lastEvent).toBeNull()
  })

  it('dispatches a typed event from a valid "event" frame', () => {
    const { result } = renderHook(() => useCaseWatch('case-001'))
    act(() => { latestSocket().simulateOpen() })

    act(() => {
      latestSocket().simulateMessage(
        JSON.stringify({
          type: 'event',
          subject: 'cfgms:agent1/host/sql-primary',
          event_kind: 'entity-updated',
          version: 3,
          at: '2026-08-01T10:00:00Z',
        }),
      )
    })

    expect(result.current.lastEvent).toMatchObject({
      subject: 'cfgms:agent1/host/sql-primary',
      event_kind: 'entity-updated',
      version: 3,
      at: '2026-08-01T10:00:00Z',
    })
  })

  it('ignores "resync" frames without throwing', () => {
    const { result } = renderHook(() => useCaseWatch('case-001'))
    act(() => { latestSocket().simulateOpen() })

    expect(() => {
      act(() => {
        latestSocket().simulateMessage(JSON.stringify({ type: 'resync' }))
      })
    }).not.toThrow()

    // No lastEvent from a resync frame.
    expect(result.current.lastEvent).toBeNull()
  })

  it('ignores malformed JSON without throwing', () => {
    const { result } = renderHook(() => useCaseWatch('case-001'))
    act(() => { latestSocket().simulateOpen() })

    expect(() => {
      act(() => { latestSocket().simulateMessage('not-json') })
    }).not.toThrow()

    expect(result.current.lastEvent).toBeNull()
  })

  it('resets to not-connected when the socket closes', () => {
    const { result } = renderHook(() => useCaseWatch('case-001'))
    act(() => { latestSocket().simulateOpen() })
    expect(result.current.isLive).toBe(true)

    // Suppress the reconnect timer that onclose schedules.
    vi.useFakeTimers()
    act(() => { latestSocket().simulateClose() })
    expect(result.current.isLive).toBe(false)
    expect(result.current.connectedSince).toBeNull()
    vi.useRealTimers()
  })

  it('closes the socket on unmount to avoid resource leaks', () => {
    const { unmount } = renderHook(() => useCaseWatch('case-001'))
    act(() => { latestSocket().simulateOpen() })

    const socket = latestSocket()
    unmount()

    expect(socket.readyState).toBe(WebSocket.CLOSED)
  })

  it('builds the WebSocket URL from the caseId', () => {
    renderHook(() => useCaseWatch('case-abc'))
    const socket = latestSocket()
    expect(socket.url).toContain('/api/v1/cases/case-abc/watch')
  })

  it('percent-encodes caseId in the WebSocket URL', () => {
    renderHook(() => useCaseWatch('case/with/slashes'))
    const socket = latestSocket()
    expect(socket.url).toContain(encodeURIComponent('case/with/slashes'))
  })
})
