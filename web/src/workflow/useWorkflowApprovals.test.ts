// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz

/*
 * useWorkflowApprovals test suite (Issue #5861): response parsing, the approve and
 * revoke requests, and the hook's load, refusal and refetch behaviour. Only the
 * network boundary (fetch) is stubbed.
 */
import { beforeEach, afterEach, describe, expect, it, vi } from 'vitest'
import { act, cleanup, renderHook, waitFor } from '@testing-library/react'
import {
  approveWorkflowVersion,
  parseWorkflowApprovalEntry,
  parseWorkflowApprovalListing,
  revokeWorkflowApproval,
  useWorkflowApprovals,
} from './useWorkflowApprovals.ts'

const fetchMock = vi.fn<typeof fetch>()

beforeEach(() => {
  vi.stubGlobal('fetch', fetchMock)
  fetchMock.mockReset()
})

afterEach(() => {
  vi.unstubAllGlobals()
  cleanup()
})

const json = (status: number, body: unknown) =>
  new Response(JSON.stringify(body), { status, headers: { 'Content-Type': 'application/json' } })
const envelope = (data: unknown) => ({ data, timestamp: new Date().toISOString() })

const LIST = '/api/v1/automation/approvals/workflows'
const entry = {
  workflow_id: 'deploy',
  version: '1.0.0',
  content_hash: 'c-1',
  approval_hash: 'a-1',
  state: 'pending',
}

describe('parseWorkflowApprovalEntry', () => {
  it('coerces every field to a string and defaults an unknown state', () => {
    const parsed = parseWorkflowApprovalEntry({ ...entry, state: 'weird', reason: 7, approval: null })
    expect(parsed).toEqual({
      workflow_id: 'deploy',
      version: '1.0.0',
      content_hash: 'c-1',
      approval_hash: 'a-1',
      state: 'unknown',
      reason: '',
      approval: null,
    })
  })

  it('reads the approval record', () => {
    const parsed = parseWorkflowApprovalEntry({
      ...entry,
      state: 'approved',
      approval: { approved_by: 'admin-1', approved_at: 't', method: 'approve_tap' },
    })
    expect(parsed?.approval).toEqual({ approved_by: 'admin-1', approved_at: 't', method: 'approve_tap' })
  })

  it.each([null, 'x', 4, { version: '1.0.0' }, { workflow_id: 'deploy' }])(
    'drops an entry without an id and version: %j',
    (value) => {
      expect(parseWorkflowApprovalEntry(value)).toBeNull()
    },
  )
})

describe('parseWorkflowApprovalListing', () => {
  it('parses the mode and the entries, skipping malformed ones', () => {
    const listing = parseWorkflowApprovalListing({ mode: 'approve', workflows: [entry, null, { x: 1 }] })
    expect(listing.mode).toBe('approve')
    expect(listing.entries).toHaveLength(1)
  })

  it('treats a missing workflows list as empty', () => {
    expect(parseWorkflowApprovalListing({ mode: 'signed' }).entries).toEqual([])
  })

  it.each([null, 'x', { workflows: [] }, { mode: 'bypass', workflows: [] }, { mode: 'signed', workflows: 'x' }])(
    'rejects an unexpected shape: %j',
    (value) => {
      expect(() => parseWorkflowApprovalListing(value)).toThrow('unexpected response shape')
    },
  )
})

describe('approveWorkflowVersion', () => {
  it('posts the four server-provided fields and nothing else', async () => {
    fetchMock.mockResolvedValue(json(201, envelope({})))
    const result = await approveWorkflowVersion({ ...entry, extra: 'ignored' } as typeof entry)

    expect(result).toEqual({ ok: true })
    const [url, init] = fetchMock.mock.calls[0]!
    expect(String(url)).toBe(LIST)
    expect(init?.method).toBe('POST')
    expect(JSON.parse(String(init?.body))).toEqual({
      workflow_id: 'deploy',
      version: '1.0.0',
      approval_hash: 'a-1',
      content_hash: 'c-1',
    })
  })

  it('reports the server message of a refusal', async () => {
    fetchMock.mockResolvedValue(json(409, { error: { message: 'Hash does not match' } }))
    expect(await approveWorkflowVersion(entry)).toEqual({ ok: false, error: 'Hash does not match' })
  })

  it('falls back to the status when the refusal has no message', async () => {
    fetchMock.mockResolvedValue(new Response('nope', { status: 500 }))
    expect(await approveWorkflowVersion(entry)).toEqual({ ok: false, error: 'Approval failed — 500' })
  })

  it('reports a network failure', async () => {
    fetchMock.mockRejectedValue(new Error('network down'))
    expect(await approveWorkflowVersion(entry)).toEqual({ ok: false, error: 'network down' })
  })
})

describe('revokeWorkflowApproval', () => {
  it('deletes by id, version and approval hash', async () => {
    fetchMock.mockResolvedValue(new Response(null, { status: 204 }))
    expect(await revokeWorkflowApproval(entry)).toEqual({ ok: true })
    const [url, init] = fetchMock.mock.calls[0]!
    expect(String(url)).toBe(`${LIST}/deploy/1.0.0/a-1`)
    expect(init?.method).toBe('DELETE')
  })

  it('reports the server message of a refusal', async () => {
    fetchMock.mockResolvedValue(json(404, { error: 'Approval not found' }))
    expect(await revokeWorkflowApproval(entry)).toEqual({ ok: false, error: 'Approval not found' })
  })
})

describe('useWorkflowApprovals', () => {
  it('loads the mode and entries, then refetches after a successful approve', async () => {
    fetchMock.mockImplementation((_input, init) =>
      Promise.resolve(
        init?.method === 'POST'
          ? json(201, envelope({}))
          : json(200, envelope({ mode: 'approve', workflows: [entry] })),
      ),
    )
    const { result } = renderHook(() => useWorkflowApprovals())

    expect(result.current.loading).toBe(true)
    await waitFor(() => expect(result.current.loading).toBe(false))
    expect(result.current.mode).toBe('approve')
    expect(result.current.entries).toHaveLength(1)

    let outcome: unknown
    await act(async () => {
      outcome = await result.current.approve(result.current.entries[0]!)
    })
    expect(outcome).toEqual({ ok: true })
    await waitFor(() =>
      expect(fetchMock.mock.calls.filter(([, i]) => (i?.method ?? 'GET') === 'GET').length).toBe(2),
    )
  })

  it('does not refetch when the approve is refused', async () => {
    fetchMock.mockImplementation((_input, init) =>
      Promise.resolve(
        init?.method === 'POST'
          ? json(409, { error: { message: 'Hash does not match' } })
          : json(200, envelope({ mode: 'approve', workflows: [entry] })),
      ),
    )
    const { result } = renderHook(() => useWorkflowApprovals())
    await waitFor(() => expect(result.current.loading).toBe(false))

    let outcome: unknown
    await act(async () => {
      outcome = await result.current.approve(result.current.entries[0]!)
    })
    expect(outcome).toEqual({ ok: false, error: 'Hash does not match' })
    expect(fetchMock.mock.calls.filter(([, i]) => (i?.method ?? 'GET') === 'GET')).toHaveLength(1)
  })

  it('refetches after a successful revoke', async () => {
    fetchMock.mockImplementation((_input, init) =>
      Promise.resolve(
        init?.method === 'DELETE'
          ? new Response(null, { status: 204 })
          : json(200, envelope({ mode: 'approve', workflows: [{ ...entry, state: 'approved' }] })),
      ),
    )
    const { result } = renderHook(() => useWorkflowApprovals())
    await waitFor(() => expect(result.current.loading).toBe(false))

    await act(async () => {
      await result.current.revoke(result.current.entries[0]!)
    })
    await waitFor(() =>
      expect(fetchMock.mock.calls.filter(([, i]) => (i?.method ?? 'GET') === 'GET').length).toBe(2),
    )
  })

  it('reports a failed load and retries', async () => {
    fetchMock.mockResolvedValueOnce(json(500, { error: 'boom' }))
    fetchMock.mockResolvedValue(json(200, envelope({ mode: 'signed', workflows: [] })))
    const { result } = renderHook(() => useWorkflowApprovals())

    await waitFor(() => expect(result.current.error).toContain('500'))
    expect(result.current.mode).toBeNull()

    act(() => result.current.retry())
    await waitFor(() => expect(result.current.mode).toBe('signed'))
    expect(result.current.error).toBeNull()
  })
})
