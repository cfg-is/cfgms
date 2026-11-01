// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz

/*
 * SchedulePanel tests (Issue #4617). The declaration editor is exercised
 * inside the real WorkflowBuilder against a stateful fetch transport, so a
 * save followed by a reload shows what the controller would return.
 */
import { afterEach, beforeAll, beforeEach, describe, expect, it, vi } from 'vitest'
import { cleanup, fireEvent, render, screen, waitFor, within } from '@testing-library/react'
import { MemoryRouter, Route, Routes } from 'react-router'
import WorkflowBuilder from './WorkflowBuilder.tsx'

beforeAll(() => {
  if (typeof globalThis.ResizeObserver === 'undefined') {
    globalThis.ResizeObserver = class implements ResizeObserver {
      observe(): void {}
      unobserve(): void {}
      disconnect(): void {}
    }
  }
  if (typeof globalThis.DOMMatrixReadOnly === 'undefined') {
    globalThis.DOMMatrixReadOnly = class {
      m22 = 1
    } as unknown as typeof DOMMatrixReadOnly
  }
})

function json(status: number, body: unknown): Response {
  return new Response(JSON.stringify(body), { status, headers: { 'Content-Type': 'application/json' } })
}

let stored: Map<string, Record<string, unknown>>
let writes: Record<string, unknown>[]
let executeBodies: Record<string, unknown>[]

beforeEach(() => {
  stored = new Map()
  writes = []
  executeBodies = []
  vi.stubGlobal('fetch', (input: RequestInfo | URL, init?: RequestInit) => {
    const url = typeof input === 'string' ? input : input instanceof URL ? input.href : input.url
    const method = (init?.method ?? 'GET').toUpperCase()
    if (method === 'GET' && url.endsWith('/api/v1/workflows')) {
      return Promise.resolve(json(200, { workflows: [...stored.values()], count: stored.size }))
    }
    if (method === 'GET' && url.endsWith('/api/v1/triggers')) return Promise.resolve(json(200, { triggers: [], count: 0 }))
    if (url.endsWith('/execute')) {
      executeBodies.push(JSON.parse(init?.body as string) as Record<string, unknown>)
      return Promise.resolve(json(202, { execution_id: 'ex1' }))
    }
    if (method === 'GET' && url.includes('/executions/')) {
      return Promise.resolve(json(200, { id: 'ex1', workflow_name: 'wf', status: 'running', start_time: 't' }))
    }
    if (method === 'PUT' || method === 'POST') {
      const body = JSON.parse(init?.body as string) as Record<string, unknown>
      writes.push(body)
      stored.set(body.name as string, { version: '1.0.0', ...body })
      return Promise.resolve(json(200, body))
    }
    return Promise.resolve(json(404, {}))
  })
})

afterEach(() => {
  cleanup()
  vi.unstubAllGlobals()
})

function mount(path: string) {
  return render(
    <MemoryRouter initialEntries={[path]}>
      <Routes>
        <Route path="/workflows/new/builder" element={<WorkflowBuilder />} />
        <Route path="/workflows/:name/builder" element={<WorkflowBuilder />} />
      </Routes>
    </MemoryRouter>,
  )
}

const STEP = { id: 's1', name: 'first', type: 'script' }

describe('SchedulePanel in the builder', () => {
  it('shows the empty state and a save-first note for a new workflow', async () => {
    mount('/workflows/new/builder')
    fireEvent.click(screen.getByTestId('builder-schedule-toggle'))
    expect(screen.getByTestId('inputs-empty')).toBeInTheDocument()
    expect(screen.getByTestId('triggers-need-save')).toBeInTheDocument()
  })

  it('embeds the workflow-filtered trigger panel for a saved workflow', async () => {
    stored.set('wf', { name: 'wf', version: '1.0.0', steps: [STEP] })
    mount('/workflows/wf/builder')
    await screen.findByTestId('workflow-builder')
    fireEvent.click(screen.getByTestId('builder-schedule-toggle'))
    expect(await screen.findByTestId('trigger-panel')).toBeInTheDocument()
  })

  it('[REQUIRED] saving a workflow persists the edited input declarations', async () => {
    stored.set('wf', { name: 'wf', version: '1.0.0', steps: [STEP] })
    const first = mount('/workflows/wf/builder')
    await screen.findByTestId('workflow-builder')
    fireEvent.click(screen.getByTestId('builder-schedule-toggle'))

    fireEvent.click(screen.getByTestId('add-input'))
    fireEvent.change(screen.getByTestId('input-name'), { target: { value: 'ring' } })
    fireEvent.change(screen.getByTestId('input-type'), { target: { value: 'enum' } })
    fireEvent.change(screen.getByTestId('input-options'), { target: { value: 'canary, broad,' } })
    fireEvent.change(screen.getByTestId('input-default'), { target: { value: 'canary' } })
    fireEvent.click(screen.getByTestId('input-required'))
    fireEvent.click(screen.getByTestId('add-input'))
    const rows = screen.getAllByTestId('input-row')
    fireEvent.change(within(rows.at(1) as HTMLElement).getByTestId('input-name'), { target: { value: 'reboot' } })
    fireEvent.change(within(rows.at(1) as HTMLElement).getByTestId('input-type'), { target: { value: 'bool' } })

    fireEvent.click(screen.getByTestId('builder-save'))
    await screen.findByTestId('builder-save-success')
    expect(writes.at(0)?.inputs).toEqual([
      { name: 'ring', type: 'enum', required: true, default: 'canary', options: ['canary', 'broad'] },
      { name: 'reboot', type: 'bool' },
    ])

    first.unmount()
    mount('/workflows/wf/builder')
    await screen.findByTestId('workflow-builder')
    expect(screen.getByTestId('builder-schedule-toggle')).toHaveTextContent('(2)')
    fireEvent.click(screen.getByTestId('builder-schedule-toggle'))
    expect(screen.getAllByTestId('input-name').map((e) => (e as HTMLInputElement).value)).toEqual(['ring', 'reboot'])
  })

  it('refuses to save an enum input with no options', async () => {
    stored.set('wf', { name: 'wf', version: '1.0.0', steps: [STEP] })
    mount('/workflows/wf/builder')
    await screen.findByTestId('workflow-builder')
    fireEvent.click(screen.getByTestId('builder-schedule-toggle'))
    fireEvent.click(screen.getByTestId('add-input'))
    fireEvent.change(screen.getByTestId('input-name'), { target: { value: 'ring' } })
    fireEvent.change(screen.getByTestId('input-type'), { target: { value: 'enum' } })
    fireEvent.click(screen.getByTestId('builder-save'))
    expect(await screen.findByTestId('builder-notice')).toHaveTextContent('needs at least one option')
    expect(writes).toHaveLength(0)
  })

  it('builder Run renders the declared inputs and sends them', async () => {
    stored.set('wf', {
      name: 'wf', version: '1.0.0', steps: [STEP],
      inputs: [{ name: 'target', type: 'string', required: true }],
    })
    mount('/workflows/wf/builder')
    await screen.findByTestId('workflow-builder')
    fireEvent.click(screen.getByTestId('builder-run'))
    expect(screen.getByTestId('run-input-required-target')).toBeInTheDocument()
    fireEvent.click(screen.getByTestId('builder-run-start'))
    expect(screen.getByTestId('run-input-error-target')).toBeInTheDocument()
    expect(executeBodies).toHaveLength(0)
    fireEvent.change(screen.getByLabelText(/^target/), { target: { value: 'srv1' } })
    fireEvent.click(screen.getByTestId('builder-run-start'))
    await waitFor(() => expect(executeBodies).toHaveLength(1))
    expect(executeBodies.at(0)).toEqual({ variables: {}, inputs: { target: 'srv1' } })
  })
})
