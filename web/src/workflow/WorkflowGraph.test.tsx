// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz

/*
 * WorkflowGraph component tests (Story #3037).
 *
 * Tests run against the REAL @xyflow/react renderer and the REAL @dagrejs/dagre
 * layout engine — no library is stubbed or mocked. The only environment shim is
 * a ResizeObserver polyfill: jsdom does not implement the ResizeObserver DOM API
 * that React Flow uses to measure its viewport, so without it the renderer
 * throws on mount. That is a missing browser API, not a substituted component.
 *
 * Because jsdom reports every element as 0x0, React Flow never resolves handle
 * bounds and therefore paints no edge SVG paths. Edge topology is consequently
 * asserted on buildGraphElements() — the real, exported block-tree → graph
 * mapping the renderer itself consumes — while node rendering, run-state
 * classes, dagre-computed positions and the read-only surface are asserted on
 * the real mounted DOM.
 *
 * Security A9.1: every node label/footer is verified to reach the DOM as a
 * text node (RTL getByText), confirming no dangerouslySetInnerHTML path.
 */
import { beforeAll, describe, expect, it, vi } from 'vitest'
import { render, screen } from '@testing-library/react'
import WorkflowGraph, { buildGraphElements, TRIGGER_NODE_ID } from './WorkflowGraph.tsx'
import type { WorkflowStep, WorkflowExecution } from './useWorkflows.ts'

// ── jsdom environment polyfill ────────────────────────────────────────────────

beforeAll(() => {
  if (typeof globalThis.ResizeObserver === 'undefined') {
    // Minimal spec-shaped ResizeObserver: jsdom never lays elements out, so no
    // observation ever fires. React Flow only requires the constructor and the
    // observe/unobserve/disconnect surface to exist.
    globalThis.ResizeObserver = class implements ResizeObserver {
      observe(): void {}
      unobserve(): void {}
      disconnect(): void {}
    }
  }
})

// ── Helpers ───────────────────────────────────────────────────────────────────

function step(
  overrides: Partial<WorkflowStep> & Pick<WorkflowStep, 'id' | 'name'>,
): WorkflowStep {
  return { type: 'module', config: {}, ...overrides }
}

function renderGraph(steps: WorkflowStep[], execution?: WorkflowExecution) {
  return render(<WorkflowGraph steps={steps} execution={execution} />)
}

// React Flow's node wrapper carries the dagre-computed transform; the inner
// element is the component's own card (data-testid={`node-${id}`}).
function nodeWrapper(container: HTMLElement, id: string): HTMLElement {
  const el = container.querySelector<HTMLElement>(`.react-flow__node[data-id="${CSS.escape(id)}"]`)
  if (el === null) throw new Error(`no rendered React Flow node for id ${id}`)
  return el
}

// ── Sequential topology ───────────────────────────────────────────────────────

describe('WorkflowGraph — sequential topology', () => {
  it('renders one node per step plus the synthetic trigger node', () => {
    const steps = [step({ id: 's1', name: 'step-one' }), step({ id: 's2', name: 'step-two' })]
    const { container } = renderGraph(steps)
    expect(screen.getByTestId('node-__trigger__')).toBeInTheDocument()
    expect(screen.getByTestId('node-s1')).toBeInTheDocument()
    expect(screen.getByTestId('node-s2')).toBeInTheDocument()
    expect(container.querySelectorAll('.react-flow__node')).toHaveLength(3)
  })

  it('chain edges connect steps in order: trigger → s1 → s2', () => {
    const steps = [step({ id: 's1', name: 'a' }), step({ id: 's2', name: 'b' })]
    const { edges } = buildGraphElements(steps)
    expect(edges.some((e) => e.source === TRIGGER_NODE_ID && e.target === 's1')).toBe(true)
    expect(edges.some((e) => e.source === 's1' && e.target === 's2')).toBe(true)
    // A chain must not fan out: exactly one outgoing edge per node.
    expect(edges).toHaveLength(2)
  })

  it('nodes are keyed by step.id, not by array position', () => {
    const steps = [step({ id: 'unique-step-id', name: 'check' })]
    const { container } = renderGraph(steps)
    expect(screen.getByTestId('node-unique-step-id')).toBeInTheDocument()
    // React Flow keys its wrapper by node id — position indexes never appear.
    expect(nodeWrapper(container, 'unique-step-id')).toBeInTheDocument()
  })

  it('buildGraphElements produces one node per step plus trigger', () => {
    const steps = [step({ id: 'x', name: 'x' }), step({ id: 'y', name: 'y' })]
    const { nodes } = buildGraphElements(steps)
    expect(nodes.map((n) => n.id)).toContain(TRIGGER_NODE_ID)
    expect(nodes.map((n) => n.id)).toContain('x')
    expect(nodes.map((n) => n.id)).toContain('y')
    expect(nodes).toHaveLength(3)
  })

  it('dagre auto-layout assigns each node a distinct position (never hardcoded)', () => {
    const steps = [step({ id: 's1', name: 'a' }), step({ id: 's2', name: 'b' })]
    const { container } = renderGraph(steps)
    const transforms = [TRIGGER_NODE_ID, 's1', 's2'].map(
      (id) => nodeWrapper(container, id).style.transform,
    )
    expect(new Set(transforms).size).toBe(3)
    // buildGraphElements emits placeholder 0,0 — the rendered transform proves
    // the real dagre layout ran and moved the chain apart.
    expect(transforms.every((t) => t !== '' && t !== 'translate(0px,0px)')).toBe(true)
  })
})

// ── Parallel topology ─────────────────────────────────────────────────────────

describe('WorkflowGraph — parallel topology', () => {
  it('fan-out: parallel step produces edges to each child branch', () => {
    const steps = [
      step({
        id: 'par',
        name: 'parallel-block',
        type: 'parallel',
        steps: [
          step({ id: 'child-a', name: 'branch-a' }),
          step({ id: 'child-b', name: 'branch-b' }),
        ],
      }),
    ]
    const { edges } = buildGraphElements(steps)
    expect(edges.some((e) => e.source === 'par' && e.target === 'child-a')).toBe(true)
    expect(edges.some((e) => e.source === 'par' && e.target === 'child-b')).toBe(true)
  })

  it('fan-in: child exit nodes each connect to the next step in the parent list', () => {
    const steps = [
      step({
        id: 'par',
        name: 'parallel-block',
        type: 'parallel',
        steps: [
          step({ id: 'child-a', name: 'branch-a' }),
          step({ id: 'child-b', name: 'branch-b' }),
        ],
      }),
      step({ id: 'join', name: 'after-parallel' }),
    ]
    const { edges } = buildGraphElements(steps)
    expect(edges.some((e) => e.source === 'child-a' && e.target === 'join')).toBe(true)
    expect(edges.some((e) => e.source === 'child-b' && e.target === 'join')).toBe(true)
    // The join is not also wired directly from the parallel container.
    expect(edges.some((e) => e.source === 'par' && e.target === 'join')).toBe(false)
  })

  it('renders all parallel branch nodes', () => {
    const steps = [
      step({
        id: 'par',
        name: 'parallel',
        type: 'parallel',
        steps: [step({ id: 'ba', name: 'ba' }), step({ id: 'bb', name: 'bb' })],
      }),
    ]
    renderGraph(steps)
    expect(screen.getByTestId('node-par')).toBeInTheDocument()
    expect(screen.getByTestId('node-ba')).toBeInTheDocument()
    expect(screen.getByTestId('node-bb')).toBeInTheDocument()
  })
})

// ── Conditional topology ──────────────────────────────────────────────────────

describe('WorkflowGraph — conditional topology', () => {
  it('conditional node has isConditional=true in graph data', () => {
    const steps = [step({ id: 'cond', name: 'check', type: 'condition' })]
    const { nodes } = buildGraphElements(steps)
    const condNode = nodes.find((n) => n.id === 'cond')
    expect(condNode?.data.isConditional).toBe(true)
  })

  it('yes branch: edge from cond → yes-step uses sourceHandle="yes"', () => {
    const steps = [
      step({
        id: 'cond',
        name: 'check-license',
        type: 'condition',
        steps: [step({ id: 'yes-step', name: 'ok-path' })],
      }),
    ]
    const { edges } = buildGraphElements(steps)
    const yesEdge = edges.find((e) => e.source === 'cond' && e.target === 'yes-step')
    expect(yesEdge).toBeDefined()
    expect(yesEdge?.sourceHandle).toBe('yes')
  })

  it('no branch rejoins the step following the conditional', () => {
    const steps = [
      step({
        id: 'cond',
        name: 'check-license',
        type: 'condition',
        steps: [step({ id: 'yes-step', name: 'ok-path' })],
      }),
      step({ id: 'after', name: 'after-cond' }),
    ]
    const { edges } = buildGraphElements(steps)
    const noEdge = edges.find(
      (e) => e.source === 'cond' && e.target === 'after' && e.sourceHandle === 'no',
    )
    expect(noEdge).toBeDefined()
    expect(edges.some((e) => e.source === 'yes-step' && e.target === 'after')).toBe(true)
  })

  it('renders both labeled branch ports on the conditional node', () => {
    renderGraph([
      step({
        id: 'cond',
        name: 'check',
        type: 'condition',
        steps: [step({ id: 'yes-step', name: 'ok-path' })],
      }),
    ])
    expect(screen.getByText('yes')).toBeInTheDocument()
    expect(screen.getByText('no')).toBeInTheDocument()
  })

  it('conditional type "conditional" is also recognized', () => {
    const steps = [step({ id: 'c', name: 'c', type: 'conditional' })]
    const { nodes } = buildGraphElements(steps)
    const n = nodes.find((n) => n.id === 'c')
    expect(n?.data.isConditional).toBe(true)
  })
})

// ── Switch topology ───────────────────────────────────────────────────────────

describe('WorkflowGraph — switch topology', () => {
  it('switch renders one labeled edge per case with sequential case-N handles', () => {
    const steps = [
      step({
        id: 'sw',
        name: 'route',
        type: 'switch',
        switch: [
          { label: 'option-a', steps: [step({ id: 'a', name: 'handle-a' })] },
          { label: 'option-b', steps: [step({ id: 'b', name: 'handle-b' })] },
          { label: 'option-c', steps: [step({ id: 'c', name: 'handle-c' })] },
        ],
      }),
    ]
    const { edges } = buildGraphElements(steps)
    expect(
      edges.some((e) => e.source === 'sw' && e.target === 'a' && e.sourceHandle === 'case-0'),
    ).toBe(true)
    expect(
      edges.some((e) => e.source === 'sw' && e.target === 'b' && e.sourceHandle === 'case-1'),
    ).toBe(true)
    expect(
      edges.some((e) => e.source === 'sw' && e.target === 'c' && e.sourceHandle === 'case-2'),
    ).toBe(true)
    // Exactly one edge leaves the switch per case (plus none extra).
    expect(edges.filter((e) => e.source === 'sw')).toHaveLength(3)
  })

  it('switch case labels are recorded in node data and rendered as port labels', () => {
    const steps = [
      step({
        id: 'sw',
        name: 'route',
        type: 'switch',
        switch: [
          { label: 'opt-a', steps: [] },
          { label: 'opt-b', steps: [] },
        ],
      }),
    ]
    const { nodes } = buildGraphElements(steps)
    const swNode = nodes.find((n) => n.id === 'sw')
    expect(Array.isArray(swNode?.data.switchCaseLabels)).toBe(true)
    expect(swNode?.data.switchCaseLabels as string[]).toHaveLength(2)

    renderGraph(steps)
    expect(screen.getByText('opt-a')).toBeInTheDocument()
    expect(screen.getByText('opt-b')).toBeInTheDocument()
  })
})

// ── Execution colorization ────────────────────────────────────────────────────

describe('WorkflowGraph — execution colorization', () => {
  it('node matching current_step renders with running class', () => {
    const steps = [step({ id: 'step-x', name: 'running-step' })]
    const execution: WorkflowExecution = {
      id: 'exec-1',
      workflow_name: 'wf',
      status: 'running',
      start_time: '2026-01-01T00:00:00Z',
      current_step: 'step-x',
    }
    renderGraph(steps, execution)
    const nodeEl = screen.getByTestId('node-step-x')
    expect(nodeEl.className).toContain('running')
  })

  it('step with completed status in step_results renders with done class', () => {
    const steps = [step({ id: 'step-y', name: 'done-step' })]
    const execution: WorkflowExecution = {
      id: 'exec-1',
      workflow_name: 'wf',
      status: 'running',
      start_time: '2026-01-01T00:00:00Z',
      step_results: { 'step-y': { status: 'completed' } },
    }
    renderGraph(steps, execution)
    const nodeEl = screen.getByTestId('node-step-y')
    expect(nodeEl.className).toContain('done')
  })

  it('step with failed status in step_results renders with failed class', () => {
    const steps = [step({ id: 'step-f', name: 'failed-step' })]
    const execution: WorkflowExecution = {
      id: 'exec-1',
      workflow_name: 'wf',
      status: 'failed',
      start_time: '2026-01-01T00:00:00Z',
      step_results: { 'step-f': { status: 'failed' } },
    }
    renderGraph(steps, execution)
    const nodeEl = screen.getByTestId('node-step-f')
    expect(nodeEl.className).toContain('failed')
  })

  it('only the matching step.id is colorized; siblings stay pending', () => {
    const steps = [
      step({ id: 'done-one', name: 'first' }),
      step({ id: 'later-one', name: 'second' }),
    ]
    const execution: WorkflowExecution = {
      id: 'exec-1',
      workflow_name: 'wf',
      status: 'running',
      start_time: '2026-01-01T00:00:00Z',
      step_results: { 'done-one': { status: 'completed' } },
    }
    renderGraph(steps, execution)
    expect(screen.getByTestId('node-done-one').className).toContain('done')
    expect(screen.getByTestId('node-later-one').className).toContain('pending')
  })

  it('a prototype-named step id resolves to pending, never an inherited property', () => {
    // step ids are user-authored; "__proto__"/"constructor" must not be able to
    // reach Object.prototype through the step_results lookup.
    const steps = [
      step({ id: '__proto__', name: 'proto-step' }),
      step({ id: 'constructor', name: 'ctor-step' }),
    ]
    const execution: WorkflowExecution = {
      id: 'exec-1',
      workflow_name: 'wf',
      status: 'running',
      start_time: '2026-01-01T00:00:00Z',
      step_results: {},
    }
    renderGraph(steps, execution)
    expect(screen.getByTestId('node-__proto__').className).toContain('pending')
    expect(screen.getByTestId('node-constructor').className).toContain('pending')
    // Nothing (status lookup or dagre layout) wrote through to Object.prototype:
    // its own properties are all non-enumerable, so any pollution shows up here.
    expect(Object.keys(Object.prototype)).toHaveLength(0)
  })

  it('all nodes render as pending when no execution prop is provided', () => {
    const steps = [step({ id: 'step-z', name: 'pending-step' })]
    renderGraph(steps)
    const nodeEl = screen.getByTestId('node-step-z')
    expect(nodeEl.className).toContain('pending')
  })

  it('WorkflowGraph performs no fetching or polling internally', () => {
    const steps = [step({ id: 'step-a', name: 'a' })]
    const fetchSpy = vi.spyOn(globalThis, 'fetch')
    renderGraph(steps)
    expect(fetchSpy).not.toHaveBeenCalled()
    fetchSpy.mockRestore()
  })
})

// ── A9.1 security: text nodes only, no innerHTML ──────────────────────────────

describe('WorkflowGraph — A9.1 security (no dangerouslySetInnerHTML)', () => {
  it('step name with XSS payload is rendered as a text node, not executed HTML', () => {
    const xssName = '<img src=x onerror="window.__xss_graph=1">'
    const steps = [step({ id: 's1', name: xssName })]
    const { container } = renderGraph(steps)
    // getByText confirms the string reached the DOM as a text node
    expect(screen.getByText(xssName)).toBeInTheDocument()
    // …and no element was parsed out of it.
    expect(container.querySelector('img')).toBeNull()
    expect((window as unknown as Record<string, unknown>).__xss_graph).toBeUndefined()
  })

  it('config-derived footer with an XSS payload is rendered as a text node', () => {
    const payload = '<script>window.__xss_foot=1</script>'
    const steps = [step({ id: 's1', name: 'runner', config: { module: payload } })]
    const { container } = renderGraph(steps)
    expect(screen.getByText(payload)).toBeInTheDocument()
    expect(container.querySelector('script')).toBeNull()
    expect((window as unknown as Record<string, unknown>).__xss_foot).toBeUndefined()
  })

  it('step type is rendered as a text node (getByText finds it)', () => {
    const steps = [step({ id: 's1', name: 'step', type: 'module' })]
    renderGraph(steps)
    expect(screen.getByText('module')).toBeInTheDocument()
  })

  it('step name is rendered as a text node (getByText finds it)', () => {
    const steps = [step({ id: 's1', name: 'my-step-name' })]
    renderGraph(steps)
    expect(screen.getByText('my-step-name')).toBeInTheDocument()
  })
})

// ── Read-only surface ─────────────────────────────────────────────────────────

describe('WorkflowGraph — read-only surface', () => {
  it('renders successfully with only steps prop (no mutation callbacks in props)', () => {
    const steps = [step({ id: 's1', name: 'step' })]
    expect(() => renderGraph(steps)).not.toThrow()
  })

  it('React Flow nodes are not draggable and not selectable', () => {
    const { container } = renderGraph([step({ id: 's1', name: 'step' })])
    const wrapper = nodeWrapper(container, 's1')
    // React Flow adds `draggable` / `selectable` classes only when the
    // corresponding interaction is enabled.
    expect(wrapper.classList.contains('draggable')).toBe(false)
    expect(wrapper.classList.contains('selectable')).toBe(false)
  })

  it('renders an empty workflow (zero steps) as just the trigger node', () => {
    const { container } = renderGraph([])
    expect(screen.getByTestId('node-__trigger__')).toBeInTheDocument()
    expect(container.querySelectorAll('.react-flow__node')).toHaveLength(1)
  })
})
