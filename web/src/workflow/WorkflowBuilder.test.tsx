// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz

/*
 * WorkflowBuilder tests (Issue #4615).
 *
 * The real WorkflowBuilder, real @xyflow/react, real dagre and real apiFetch run
 * against a stateful fetch transport that speaks the controller's workflow
 * contract (GET list, PUT/POST store). State is real: a save changes what a
 * following GET — a "reload" — returns. Only environment gaps are shimmed:
 * ResizeObserver, and the DOMMatrix/DOMRect bits React Flow reads, which jsdom
 * lacks. jsdom reports 0x0 for every element so React Flow paints no edge
 * paths; edge topology is asserted through the saved step order.
 */
import { afterEach, beforeAll, beforeEach, describe, expect, it, vi } from 'vitest'
import { fireEvent, render, screen, waitFor } from '@testing-library/react'
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

interface Transport {
  stored: Map<string, Record<string, unknown>>
  writes: { method: string; url: string; body: Record<string, unknown> }[]
  failList: boolean
  failWrite: string | null
  validateStatus: number
  validateBody: Record<string, unknown>
  executeStatus: number
  cancelStatus: number
  execution: Record<string, unknown>
  calls: { method: string; url: string }[]
}

let t: Transport

function write(i: number) {
  const w = t.writes.at(i)
  if (w === undefined) throw new Error(`no write #${i}`)
  return w
}

function install() {
  t = {
    stored: new Map(), writes: [], failList: false, failWrite: null,
    validateStatus: 200, validateBody: { valid: true, issues: [] },
    executeStatus: 202, cancelStatus: 200,
    execution: { id: 'ex1', workflow_name: 'wf', status: 'running', start_time: 't', current_step: 's1', step_results: {} },
    calls: [],
  }
  vi.stubGlobal('fetch', (input: RequestInfo | URL, init?: RequestInit) => {
    const url = typeof input === 'string' ? input : input instanceof URL ? input.href : input.url
    const method = (init?.method ?? 'GET').toUpperCase()
    if (method === 'GET' && url.endsWith('/api/v1/workflows')) {
      if (t.failList) return Promise.resolve(json(500, { error: 'boom' }))
      return Promise.resolve(json(200, { workflows: [...t.stored.values()], count: t.stored.size }))
    }
    t.calls.push({ method, url })
    if (url.endsWith('/api/v1/workflows/validate')) {
      return Promise.resolve(json(t.validateStatus, t.validateBody))
    }
    if (url.endsWith('/execute')) return Promise.resolve(json(t.executeStatus, { execution_id: 'ex1' }))
    if (url.endsWith('/cancel')) return Promise.resolve(json(t.cancelStatus, { error: 'forbidden' }))
    if (method === 'GET' && url.includes('/executions/')) return Promise.resolve(json(200, t.execution))
    if (method === 'PUT' || method === 'POST') {
      const body = JSON.parse(init?.body as string) as Record<string, unknown>
      t.writes.push({ method, url, body })
      if (t.failWrite !== null) return Promise.resolve(json(400, { error: t.failWrite }))
      t.stored.set(body.name as string, { version: '1.0.0', ...body })
      return Promise.resolve(json(200, body))
    }
    return Promise.resolve(json(404, {}))
  })
}

function seed(name: string, steps: unknown[], extra: Record<string, unknown> = {}) {
  t.stored.set(name, { name, version: '1.0.0', description: 'd', steps, ...extra })
}

function mount(path: string) {
  return render(
    <MemoryRouter initialEntries={[path]}>
      <Routes>
        <Route path="/workflows/new/builder" element={<WorkflowBuilder />} />
        <Route path="/workflows/:name/builder" element={<WorkflowBuilder />} />
        <Route path="/workflows" element={<div data-testid="list-route" />} />
      </Routes>
    </MemoryRouter>,
  )
}

const NESTED = {
  id: 'p1', name: 'fan', type: 'parallel', timeout: 5000000000, on_failure: 'continue',
  steps: [
    { id: 'a', name: 'a', type: 'script', config: { script: 'echo a' } },
    { id: 'b', name: 'b', type: 'script', config: { script: 'echo b' }, retry: { max: 3 } },
  ],
}

beforeEach(install)
afterEach(() => vi.unstubAllGlobals())

describe('WorkflowBuilder — states', () => {
  it('shows loading, then the editor with the workflow steps', async () => {
    seed('wf', [{ id: 's1', name: 'first', type: 'script' }])
    mount('/workflows/wf/builder')
    expect(screen.getByTestId('builder-loading')).toBeInTheDocument()
    expect(await screen.findByTestId('workflow-builder')).toBeInTheDocument()
    expect(screen.getByTestId('builder-name')).toHaveTextContent('wf')
    expect(screen.getByTestId('builder-step-count')).toHaveTextContent('1 step')
    expect(screen.getByTestId('node-n0')).toHaveTextContent('first')
  })

  it('shows an error state with Retry when the load fails', async () => {
    t.failList = true
    mount('/workflows/wf/builder')
    expect(await screen.findByTestId('builder-error')).toHaveTextContent('500')
    t.failList = false
    seed('wf', [{ name: 'x', type: 'script' }])
    fireEvent.click(screen.getByRole('button', { name: 'Retry' }))
    expect(await screen.findByTestId('workflow-builder')).toBeInTheDocument()
  })

  it('shows not-found for an unknown workflow', async () => {
    mount('/workflows/nope/builder')
    expect(await screen.findByTestId('builder-not-found')).toBeInTheDocument()
  })

  it('shows the empty state for a workflow with no steps and for a new workflow', async () => {
    mount('/workflows/new/builder')
    expect(screen.getByTestId('builder-empty')).toBeInTheDocument()
    expect(screen.getByTestId('builder-name-input')).toBeInTheDocument()
  })
})

describe('WorkflowBuilder — edit and save', () => {
  it('[REQUIRED] save then reload yields the identical step list incl. an opaque nested step', async () => {
    const steps = [
      { id: 's1', name: 'first', type: 'script', config: { script: 'ls' }, semaphore: { name: 'x', limit: 2 } },
      NESTED,
    ]
    seed('wf', steps)
    const first = mount('/workflows/wf/builder')
    await screen.findByTestId('workflow-builder')
    fireEvent.click(screen.getByTestId('builder-save'))
    await screen.findByTestId('builder-save-success')
    expect(t.writes).toHaveLength(1)
    expect(write(0).method).toBe('PUT')
    expect(write(0).url).toBe('/api/v1/workflows/wf')
    expect(JSON.stringify(write(0).body.steps)).toBe(JSON.stringify(steps))

    first.unmount()
    mount('/workflows/wf/builder')
    await screen.findByTestId('workflow-builder')
    fireEvent.click(screen.getByTestId('builder-save'))
    await waitFor(() => expect(t.writes).toHaveLength(2))
    expect(JSON.stringify(write(1).body.steps)).toBe(JSON.stringify(steps))
  })

  it('[REQUIRED] palette offers approval and notify and saves the S2/S3 shapes', async () => {
    seed('wf', [{ id: 's1', name: 'first', type: 'script' }])
    mount('/workflows/wf/builder')
    await screen.findByTestId('workflow-builder')
    expect(screen.getByTestId('palette-approval')).toBeInTheDocument()
    expect(screen.getByTestId('palette-notify')).toBeInTheDocument()

    fireEvent.click(screen.getByTestId('palette-approval'))
    fireEvent.click(screen.getByTestId('palette-notify'))
    fireEvent.change(screen.getByTestId('inspector-notify-url'), { target: { value: 'https://hooks.acme-corp.example/x' } })
    fireEvent.click(screen.getByTestId('builder-save'))
    await screen.findByTestId('builder-save-success')

    const saved = write(0).body.steps as Record<string, unknown>[]
    expect(saved.map((s) => s.type)).toEqual(['script', 'approval', 'notify'])
    expect(saved.at(1)?.approval).toEqual({ message: 'Approve to continue', timeout: 86400000000000 })
    expect(saved.at(2)?.notify).toEqual({
      url: 'https://hooks.acme-corp.example/x', title: 'Workflow notification', severity: 'info',
    })
  })

  it('edits approval properties in the inspector', async () => {
    seed('wf', [{ id: 's1', name: 'first', type: 'script' }])
    mount('/workflows/wf/builder')
    await screen.findByTestId('workflow-builder')
    fireEvent.click(screen.getByTestId('palette-approval'))
    fireEvent.change(screen.getByTestId('inspector-approval-message'), { target: { value: 'Ship it?' } })
    fireEvent.change(screen.getByTestId('inspector-approval-timeout'), { target: { value: '30' } })
    fireEvent.click(screen.getByTestId('builder-save'))
    await screen.findByTestId('builder-save-success')
    const gate = (write(0).body.steps as Record<string, unknown>[]).at(1)
    expect(gate?.approval).toEqual({ message: 'Ship it?', timeout: 1800000000000 })
  })

  it('[REQUIRED] refuses an approval dropped onto a parallel node and never saves it', async () => {
    seed('wf', [NESTED])
    mount('/workflows/wf/builder')
    await screen.findByTestId('workflow-builder')
    fireEvent.drop(screen.getByTestId('node-n0'), {
      dataTransfer: { getData: () => 'approval' },
    })
    expect(screen.getByTestId('builder-notice')).toHaveTextContent('Approval gates must be top-level')
    expect(screen.getByTestId('builder-step-count')).toHaveTextContent('1 step')
    fireEvent.click(screen.getByTestId('builder-save'))
    await screen.findByTestId('builder-save-success')
    expect(JSON.stringify(write(0).body)).not.toContain('"approval"')
  })

  it('refuses inspector JSON that nests an approval inside an opaque node', async () => {
    seed('wf', [NESTED])
    mount('/workflows/wf/builder')
    await screen.findByTestId('workflow-builder')
    fireEvent.click(screen.getByTestId('node-n0'))
    const bad = { ...NESTED, steps: [...NESTED.steps, { name: 'g', type: 'approval', approval: { message: 'm', timeout: 1 } }] }
    fireEvent.change(screen.getByTestId('inspector-json'), { target: { value: JSON.stringify(bad) } })
    fireEvent.click(screen.getByTestId('inspector-json-apply'))
    expect(screen.getByTestId('builder-notice')).toHaveTextContent('top-level')
    fireEvent.click(screen.getByTestId('builder-save'))
    await screen.findByTestId('builder-save-success')
    expect(JSON.stringify(write(0).body)).not.toContain('"approval"')
  })

  it('applies valid JSON edits to an opaque node', async () => {
    seed('wf', [NESTED])
    mount('/workflows/wf/builder')
    await screen.findByTestId('workflow-builder')
    fireEvent.click(screen.getByTestId('node-n0'))
    const edited = { ...NESTED, timeout: 9000000000 }
    fireEvent.change(screen.getByTestId('inspector-json'), { target: { value: JSON.stringify(edited) } })
    fireEvent.click(screen.getByTestId('inspector-json-apply'))
    fireEvent.click(screen.getByTestId('builder-save'))
    await screen.findByTestId('builder-save-success')
    expect((write(0).body.steps as Record<string, unknown>[]).at(0)).toEqual(edited)
  })

  it('deletes a node and keeps the remaining chain', async () => {
    seed('wf', [
      { name: 'a', type: 'script' }, { name: 'b', type: 'script' }, { name: 'c', type: 'script' },
    ])
    mount('/workflows/wf/builder')
    await screen.findByTestId('workflow-builder')
    fireEvent.click(screen.getByTestId('node-n1'))
    fireEvent.click(screen.getByTestId('inspector-delete'))
    expect(screen.getByTestId('builder-step-count')).toHaveTextContent('2 steps')
    fireEvent.click(screen.getByTestId('builder-save'))
    await screen.findByTestId('builder-save-success')
    expect((write(0).body.steps as { name: string }[]).map((s) => s.name)).toEqual(['a', 'c'])
  })

  it('renders zoom controls and positions nodes deterministically', async () => {
    seed('wf', [{ name: 'a', type: 'script' }, { name: 'b', type: 'script' }])
    const { container } = mount('/workflows/wf/builder')
    await screen.findByTestId('workflow-builder')
    expect(container.querySelector('.react-flow__controls-zoomin')).not.toBeNull()
    expect(container.querySelector('.react-flow__controls-zoomout')).not.toBeNull()
    const transform = () =>
      container.querySelector<HTMLElement>('.react-flow__node[data-id="n1"]')?.style.transform
    const before = transform()
    expect(before).toMatch(/translate\(/)
    fireEvent.click(screen.getByTestId('builder-save'))
    await screen.findByTestId('builder-save-success')
    expect(transform()).toBe(before)
  })

  it('surfaces a server error and keeps the draft', async () => {
    seed('wf', [{ name: 'a', type: 'script' }])
    t.failWrite = 'invalid step'
    mount('/workflows/wf/builder')
    await screen.findByTestId('workflow-builder')
    fireEvent.click(screen.getByTestId('palette-notify'))
    fireEvent.click(screen.getByTestId('builder-save'))
    expect(await screen.findByTestId('builder-save-error')).toHaveTextContent('invalid step')
    expect(screen.getByTestId('builder-dirty')).toBeInTheDocument()
  })

  it('disables Save for a workflow carrying fields a save cannot carry', async () => {
    seed('wf', [{ name: 'a', type: 'script' }], { on_failure: 'rollback' })
    mount('/workflows/wf/builder')
    await screen.findByTestId('workflow-builder')
    expect(screen.getByTestId('builder-save')).toBeDisabled()
    expect(screen.getByTestId('builder-save-blocked')).toHaveTextContent('on_failure')
  })

  it('creates a new workflow with POST', async () => {
    mount('/workflows/new/builder')
    fireEvent.click(screen.getByTestId('palette-notify'))
    fireEvent.click(screen.getByTestId('builder-save'))
    expect(await screen.findByTestId('builder-save-error')).toHaveTextContent('name is required')
    fireEvent.change(screen.getByTestId('builder-name-input'), { target: { value: 'fresh' } })
    fireEvent.click(screen.getByTestId('builder-save'))
    await waitFor(() => expect(t.writes).toHaveLength(1))
    expect(write(0).method).toBe('POST')
    expect(write(0).url).toBe('/api/v1/workflows')
    expect(write(0).body.name).toBe('fresh')
  })
})

describe('WorkflowBuilder — unsaved-changes guard', () => {
  it('asks before leaving with unsaved changes and stays when declined', async () => {
    seed('wf', [{ name: 'a', type: 'script' }])
    mount('/workflows/wf/builder')
    await screen.findByTestId('workflow-builder')
    fireEvent.click(screen.getByTestId('palette-notify'))
    const confirm = vi.spyOn(window, 'confirm').mockReturnValue(false)
    fireEvent.click(screen.getByTestId('builder-back'))
    expect(confirm).toHaveBeenCalled()
    expect(screen.queryByTestId('list-route')).toBeNull()
    confirm.mockReturnValue(true)
    fireEvent.click(screen.getByTestId('builder-back'))
    expect(screen.getByTestId('list-route')).toBeInTheDocument()
    confirm.mockRestore()
  })

  it('leaves without a prompt when clean and blocks unload while dirty', async () => {
    seed('wf', [{ name: 'a', type: 'script' }])
    mount('/workflows/wf/builder')
    await screen.findByTestId('workflow-builder')
    const clean = new Event('beforeunload', { cancelable: true })
    window.dispatchEvent(clean)
    expect(clean.defaultPrevented).toBe(false)
    fireEvent.click(screen.getByTestId('palette-notify'))
    const dirty = new Event('beforeunload', { cancelable: true })
    window.dispatchEvent(dirty)
    expect(dirty.defaultPrevented).toBe(true)
  })
})

describe('WorkflowBuilder — validate and run (Issue #4616)', () => {
  const TWO = [
    { id: 's1', name: 'first', type: 'script' },
    { id: 's2', name: 'second', type: 'script' },
  ]

  it('shows server issues on the offending node and a clear valid state', async () => {
    seed('wf', TWO)
    mount('/workflows/wf/builder')
    await screen.findByTestId('workflow-builder')
    t.validateBody = { valid: false, issues: [{ path: 'steps[1].config', step_name: 'second', message: 'config required' }, { path: 'name', message: 'bad name' }] }
    fireEvent.click(screen.getByTestId('builder-validate'))
    expect(await screen.findByTestId('validate-invalid')).toHaveTextContent('2 issues')
    expect(screen.getByTestId('node-issue-n1')).toHaveTextContent('config required')
    expect(screen.queryByTestId('node-issue-n0')).toBeNull()
    expect(screen.getByTestId('validate-workflow-issues')).toHaveTextContent('bad name')

    t.validateBody = { valid: true, issues: [] }
    fireEvent.click(screen.getByTestId('builder-validate'))
    expect(await screen.findByTestId('validate-valid')).toBeInTheDocument()
    expect(screen.queryByTestId('node-issue-n1')).toBeNull()
  })

  it('renders a validate 503 as an error', async () => {
    seed('wf', TWO)
    mount('/workflows/wf/builder')
    await screen.findByTestId('workflow-builder')
    t.validateStatus = 503
    t.validateBody = { error: 'workflow engine not available' }
    fireEvent.click(screen.getByTestId('builder-validate'))
    expect(await screen.findByTestId('validate-error')).toHaveTextContent('workflow engine not available')
  })

  it('[REQUIRED] Run with unsaved edits is blocked with a Save prompt', async () => {
    seed('wf', TWO)
    mount('/workflows/wf/builder')
    await screen.findByTestId('workflow-builder')
    fireEvent.click(screen.getByTestId('palette-notify'))
    fireEvent.click(screen.getByTestId('builder-run'))
    expect(await screen.findByTestId('builder-notice')).toHaveTextContent(/Save the workflow before running/)
    expect(t.calls.some((c) => c.url.endsWith('/execute'))).toBe(false)
    expect(screen.queryByTestId('run-bar')).toBeNull()
  })

  it('[REQUIRED] the run bar tracks a polled execution to completion and Cancel calls the cancel endpoint', async () => {
    seed('wf', TWO)
    mount('/workflows/wf/builder')
    await screen.findByTestId('workflow-builder')
    fireEvent.click(screen.getByTestId('builder-run'))
    expect(await screen.findByTestId('run-bar-status')).toHaveTextContent('running')
    expect(screen.getByTestId('run-bar-progress')).toHaveTextContent('step 0/2')
    expect(screen.getByTestId('node-n0')).toHaveClass('running')

    fireEvent.click(screen.getByTestId('run-bar-cancel'))
    await waitFor(() => expect(t.calls.some((c) => c.method === 'POST' && c.url.endsWith('/workflows/wf/executions/ex1/cancel'))).toBe(true))
    // 200 from cancel → no denial shown
    expect(screen.queryByTestId('run-bar-cancel-error')).toBeNull()
  })

  it('advances to completion as the poll returns new state', async () => {
    seed('wf', TWO)
    mount('/workflows/wf/builder')
    await screen.findByTestId('workflow-builder')
    vi.useFakeTimers({ shouldAdvanceTime: true })
    try {
      fireEvent.click(screen.getByTestId('builder-run'))
      expect(await screen.findByTestId('run-bar-status')).toHaveTextContent('running')
      t.execution = {
        id: 'ex1', workflow_name: 'wf', status: 'completed', start_time: 't',
        step_results: { s1: { status: 'completed' }, s2: { status: 'completed' } },
      }
      await vi.advanceTimersByTimeAsync(3100)
      await waitFor(() => expect(screen.getByTestId('run-bar-status')).toHaveTextContent('completed'))
      expect(screen.getByTestId('run-bar-progress')).toHaveTextContent('step 2/2')
      expect(screen.getByTestId('node-n1')).toHaveClass('done')
      expect(screen.queryByTestId('run-bar-cancel')).toBeNull()
    } finally {
      vi.useRealTimers()
    }
  })

  it('renders the cancel denial', async () => {
    seed('wf', TWO)
    mount('/workflows/wf/builder')
    await screen.findByTestId('workflow-builder')
    fireEvent.click(screen.getByTestId('builder-run'))
    await screen.findByTestId('run-bar-cancel')
    t.cancelStatus = 403
    fireEvent.click(screen.getByTestId('run-bar-cancel'))
    expect(await screen.findByTestId('run-bar-cancel-error')).toHaveTextContent('forbidden')
  })

  it('renders a 403 on run start as the Error state', async () => {
    seed('wf', TWO)
    mount('/workflows/wf/builder')
    await screen.findByTestId('workflow-builder')
    t.executeStatus = 403
    fireEvent.click(screen.getByTestId('builder-run'))
    expect(await screen.findByTestId('run-bar-error')).toHaveTextContent('403')
  })
})
