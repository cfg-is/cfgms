// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz

/* YamlPane tests (Issue #4619): debounce, latest-wins, gutter, error state. */
import { beforeEach, afterEach, describe, expect, it, vi } from 'vitest'
import { act, cleanup, render, screen } from '@testing-library/react'
import { MemoryRouter } from 'react-router'
import { AuthProvider } from '../auth/AuthContext.tsx'
import YamlPane from './YamlPane.tsx'

const fetchMock = vi.fn<typeof fetch>()

beforeEach(() => {
  vi.useFakeTimers()
  vi.stubGlobal('fetch', fetchMock)
  fetchMock.mockReset()
})

afterEach(() => {
  vi.useRealTimers()
  vi.unstubAllGlobals()
  cleanup()
})

function pane(body: Record<string, unknown>) {
  return (
    <MemoryRouter>
      <AuthProvider>
        <YamlPane body={body} debounceMs={100} />
      </AuthProvider>
    </MemoryRouter>
  )
}

async function settle(ms: number) {
  await act(async () => {
    await vi.advanceTimersByTimeAsync(ms)
  })
}

describe('YamlPane', () => {
  it('shows loading, then the rendered YAML with a line gutter', async () => {
    fetchMock.mockResolvedValue(new Response('name: a\nsteps:\n  - name: s\n'))
    render(pane({ name: 'a', steps: [] }))
    expect(screen.getByTestId('yaml-loading')).toBeInTheDocument()
    await settle(100)
    const lines = screen.getAllByTestId('yaml-line')
    expect(lines).toHaveLength(3)
    expect(lines[2]!.textContent).toContain('3')
    expect(lines[2]!.textContent).toContain('- name: s')
    const [url, init] = fetchMock.mock.calls[0]!
    expect(String(url)).toBe('/api/v1/workflows/render-yaml')
    expect(init?.method).toBe('POST')
  })

  it('debounces rapid edits into one render call', async () => {
    fetchMock.mockResolvedValue(new Response('name: c\n'))
    const { rerender } = render(pane({ name: 'a' }))
    await settle(50)
    rerender(pane({ name: 'b' }))
    await settle(50)
    rerender(pane({ name: 'c' }))
    await settle(100)
    expect(fetchMock).toHaveBeenCalledTimes(1)
    expect(JSON.parse(String(fetchMock.mock.calls[0]![1]?.body))).toEqual({ name: 'c' })
  })

  it('applies only the latest response', async () => {
    let releaseFirst!: (r: Response) => void
    fetchMock.mockImplementationOnce(() => new Promise<Response>((res) => { releaseFirst = res }))
    fetchMock.mockResolvedValueOnce(new Response('name: new\n'))
    const { rerender } = render(pane({ name: 'old' }))
    await settle(100)
    rerender(pane({ name: 'new' }))
    await settle(100)
    expect(screen.getByTestId('yaml-code').textContent).toContain('name: new')
    await act(async () => { releaseFirst(new Response('name: old\n')) })
    expect(screen.getByTestId('yaml-code').textContent).toContain('name: new')
    expect(screen.getByTestId('yaml-code').textContent).not.toContain('name: old')
  })

  it('shows the server rejection as an error', async () => {
    fetchMock.mockResolvedValue(new Response(JSON.stringify({ error: 'workflow cannot be rendered as YAML' }), { status: 400 }))
    render(pane({ name: 'a' }))
    await settle(100)
    expect(screen.getByTestId('yaml-error').textContent).toBe('workflow cannot be rendered as YAML')
  })

  it('shows an empty state for an empty document', async () => {
    fetchMock.mockResolvedValue(new Response(''))
    render(pane({ name: '' }))
    await settle(100)
    expect(screen.getByTestId('yaml-empty')).toBeInTheDocument()
  })
})
