// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'
import { renderHook, waitFor, act } from '@testing-library/react'
import { parseApproval, parseApprovalList, useApprovals } from './useApprovals.ts'

const fetchMock = vi.fn<typeof fetch>()

beforeEach(() => {
  fetchMock.mockReset()
  vi.stubGlobal('fetch', fetchMock)
})

afterEach(() => {
  vi.unstubAllGlobals()
})

function json(status: number, body: unknown): Response {
  return new Response(JSON.stringify(body), { status, headers: { 'Content-Type': 'application/json' } })
}

describe('parsers', () => {
  it('rejects entries without an approval_id and coerces bad fields', () => {
    expect(parseApproval(null)).toBeNull()
    expect(parseApproval({ workflow_name: 'x' })).toBeNull()
    expect(parseApproval({ approval_id: 'a', workflow_name: 5, message: {} })).toMatchObject({
      approval_id: 'a',
      workflow_name: '',
      message: '',
    })
  })

  it('treats null as empty and rejects non-arrays', () => {
    expect(parseApprovalList(null)).toEqual([])
    expect(() => parseApprovalList({})).toThrow()
    expect(parseApprovalList([{ approval_id: 'a' }, 7])).toHaveLength(1)
  })
})

describe('useApprovals', () => {
  it('loads the list and decide posts the body then reloads', async () => {
    fetchMock.mockImplementation((_u, init) =>
      Promise.resolve(json(200, { data: init?.method === 'POST' ? {} : [{ approval_id: 'a/1' }] })),
    )
    const { result } = renderHook(() => useApprovals())
    await waitFor(() => expect(result.current.approvals).toHaveLength(1))
    let res: Awaited<ReturnType<typeof result.current.decide>> | undefined
    await act(async () => {
      res = await result.current.decide('a/1', 'approve', 'fine')
    })
    expect(res).toEqual({ ok: true })
    const post = fetchMock.mock.calls.find(([, init]) => init?.method === 'POST')!
    expect(String(post[0])).toBe('/api/v1/workflows/approvals/a%2F1/decision')
    expect(JSON.parse(String(post[1]?.body))).toEqual({ decision: 'approve', justification: 'fine' })
  })

  it('returns the server message on failure and reports list errors', async () => {
    fetchMock.mockImplementation((_u, init) =>
      Promise.resolve(
        init?.method === 'POST' ? json(403, { error: { message: 'nope' } }) : json(200, { data: [] }),
      ),
    )
    const { result } = renderHook(() => useApprovals())
    await waitFor(() => expect(result.current.loading).toBe(false))
    let res: Awaited<ReturnType<typeof result.current.decide>> | undefined
    await act(async () => {
      res = await result.current.decide('a', 'reject', 'x')
    })
    expect(res).toEqual({ ok: false, error: 'nope' })

    fetchMock.mockReset()
    fetchMock.mockResolvedValue(json(500, {}))
    const failing = renderHook(() => useApprovals())
    await waitFor(() => expect(failing.result.current.error).toMatch(/500/))
  })
})
