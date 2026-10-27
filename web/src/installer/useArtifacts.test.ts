// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz

import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'
import { act, renderHook } from '@testing-library/react'
import { MAX_BODY_BYTES, OVERSIZE_MESSAGE, useArtifacts } from './useArtifacts.ts'

const fetchMock = vi.fn<typeof fetch>()

beforeEach(() => {
  vi.stubGlobal('fetch', fetchMock)
  fetchMock.mockReset()
})
afterEach(() => vi.unstubAllGlobals())

function bigFile(): File {
  const f = new File(['x'], 'big.bin')
  Object.defineProperty(f, 'size', { value: MAX_BODY_BYTES + 1 })
  return f
}

describe('useArtifacts', () => {
  it('upload sends PUT with the file as body and reports success', async () => {
    fetchMock.mockResolvedValue(new Response('{}', { status: 200 }))
    const changed = vi.fn()
    const { result } = renderHook(() => useArtifacts(changed))
    const file = new File(['abc'], 'a.bin')
    await act(async () => {
      expect(await result.current.upload('linux', 'amd64', file)).toBe(true)
    })
    const [url, init] = fetchMock.mock.calls[0]!
    expect(url).toBe('/api/v1/installer/artifacts/linux/amd64')
    expect(init?.method).toBe('PUT')
    expect(init?.body).toBe(file)
    expect(changed).toHaveBeenCalled()
  })

  it('refuses an oversize upload without a request and states the limit', async () => {
    const { result } = renderHook(() => useArtifacts(vi.fn()))
    await act(async () => {
      expect(await result.current.upload('linux', 'amd64', bigFile())).toBe(false)
    })
    expect(fetchMock).not.toHaveBeenCalled()
    expect(result.current.error).toBe(OVERSIZE_MESSAGE)
    expect(OVERSIZE_MESSAGE).toContain('64 MiB')
  })

  it('publish refuses a missing signature without a request', async () => {
    const { result } = renderHook(() => useArtifacts(vi.fn()))
    await act(async () => {
      expect(
        await result.current.publish({ version: '1.0.0', platform: 'linux', arch: 'amd64', signature: ' ', file: new File(['a'], 'a') }),
      ).toBe(false)
    })
    expect(fetchMock).not.toHaveBeenCalled()
    expect(result.current.error).toMatch(/signature/i)
  })

  it('publish encodes the signature in the query', async () => {
    fetchMock.mockResolvedValue(new Response('{}', { status: 201 }))
    const { result } = renderHook(() => useArtifacts(vi.fn()))
    await act(async () => {
      await result.current.publish({ version: '1.0.0', platform: 'linux', arch: 'amd64', signature: 'a+b/c==', file: new File(['a'], 'a') })
    })
    expect(fetchMock.mock.calls[0]![0]).toBe(
      '/api/v1/installer/steward-binaries/1.0.0/linux/amd64?signature=a%2Bb%2Fc%3D%3D',
    )
  })

  it('surfaces the server message on rejection', async () => {
    fetchMock.mockResolvedValue(new Response(JSON.stringify({ error: { message: 'bad sig' } }), { status: 400 }))
    const { result } = renderHook(() => useArtifacts(vi.fn()))
    await act(async () => {
      await result.current.publish({ version: '1', platform: 'linux', arch: 'amd64', signature: 's', file: new File(['a'], 'a') })
    })
    expect(result.current.error).toBe('Publish failed — bad sig')
  })
})
