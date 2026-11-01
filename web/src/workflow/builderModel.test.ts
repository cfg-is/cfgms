// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz

/*
 * builderModel tests (Issue #4615) — the pure step-list <-> chain-graph model.
 * Everything runs against the real functions; there is nothing to substitute.
 */
import { describe, expect, it } from 'vitest'
import { parseVersionedWorkflow } from './useWorkflows.ts'
import {
  NESTED_APPROVAL_MESSAGE,
  addNode,
  connectNodes,
  deleteNode,
  graphToSteps,
  isOpaque,
  newStep,
  orderNodes,
  parseStepJSON,
  stepsToGraph,
  unsaveableFields,
  validateSteps,
} from './builderModel.ts'

const NESTED_PARALLEL = {
  id: 'p1',
  name: 'fan',
  type: 'parallel',
  timeout: 5000000000,
  on_failure: 'continue',
  steps: [
    { id: 'a', name: 'a', type: 'script', config: { script: 'echo a' } },
    { id: 'b', name: 'b', type: 'script', config: { script: 'echo b' }, retry: { max: 3 } },
  ],
}

function load(steps: unknown[]) {
  const wf = parseVersionedWorkflow({ name: 'wf', steps })
  if (wf === null) throw new Error('fixture failed to parse')
  return wf.steps
}

describe('stepsToGraph / graphToSteps round trip', () => {
  it('returns the identical step list, including an opaque nested step and unmodeled keys', () => {
    const input = [
      { id: 's1', name: 'first', type: 'script', config: { script: 'ls' }, semaphore: { name: 'x', limit: 2 } },
      NESTED_PARALLEL,
      { id: 's3', name: 'ask', type: 'approval', approval: { message: 'ok?', timeout: 60000000000 } },
    ]
    const out = graphToSteps(stepsToGraph(load(input)))
    expect(JSON.stringify(out)).toBe(JSON.stringify(input))
  })

  it('builds a linear chain', () => {
    const g = stepsToGraph(load([{ name: 'a', type: 'script' }, { name: 'b', type: 'script' }]))
    expect(g.edges.map((e) => [e.source, e.target])).toEqual([['n0', 'n1']])
  })
})

describe('isOpaque', () => {
  it('flags parallel, loop and nested-step containers but not plain steps', () => {
    expect(isOpaque(NESTED_PARALLEL)).toBe(true)
    expect(isOpaque({ type: 'task', loop: { type: 'for' } })).toBe(true)
    expect(isOpaque({ type: 'script', config: {} })).toBe(false)
    expect(isOpaque({ type: 'approval', approval: { message: 'm' } })).toBe(false)
  })
})

describe('addNode', () => {
  it('appends to the chain and connects from the previous tail', () => {
    const g = stepsToGraph(load([{ name: 'a', type: 'script' }]))
    const r = addNode(g, 'notify')
    expect(r.ok).toBe(true)
    if (!r.ok) return
    expect(graphToSteps(r.graph).map((s) => s.type)).toEqual(['script', 'notify'])
    expect(r.graph.edges).toHaveLength(1)
  })

  it('creates approval and notify steps in the controller shapes', () => {
    expect(newStep('approval', 'gate')).toEqual({
      name: 'gate',
      type: 'approval',
      approval: { message: 'Approve to continue', timeout: 86400000000000 },
    })
    expect(newStep('notify', 'n')).toEqual({
      name: 'n',
      type: 'notify',
      notify: { url: '', title: 'Workflow notification', severity: 'info' },
    })
  })

  it('gives duplicate palette picks unique names', () => {
    let g = stepsToGraph([])
    for (let i = 0; i < 3; i++) {
      const r = addNode(g, 'notify')
      if (!r.ok) throw new Error('unexpected refusal')
      g = r.graph
    }
    expect(graphToSteps(g).map((s) => s.name)).toEqual(['notify', 'notify-2', 'notify-3'])
  })

  it('refuses an approval dropped into a container node', () => {
    const g = stepsToGraph(load([NESTED_PARALLEL]))
    const r = addNode(g, 'approval', 'n0')
    expect(r).toEqual({ ok: false, reason: NESTED_APPROVAL_MESSAGE })
  })

  it('allows an approval dropped on a plain node (added at the top level)', () => {
    const g = stepsToGraph(load([{ name: 'a', type: 'script' }]))
    expect(addNode(g, 'approval', 'n0').ok).toBe(true)
  })
})

describe('connectNodes / deleteNode', () => {
  const three = () =>
    stepsToGraph(load([{ name: 'a', type: 'script' }, { name: 'b', type: 'script' }, { name: 'c', type: 'script' }]))

  it('re-orders the chain when a node is reconnected', () => {
    // a->b->c ; connect a->c replaces a->b and b->c is dropped from c's inputs
    const g = connectNodes(three(), 'n0', 'n2')
    expect(orderNodes(g).map((n) => n.step.name)).toEqual(['a', 'c', 'b'])
  })

  it('refuses a self-loop and a cycle', () => {
    const g = three()
    expect(connectNodes(g, 'n1', 'n1')).toBe(g)
    expect(connectNodes(g, 'n2', 'n0')).toBe(g)
  })

  it('bridges neighbours when a middle node is deleted', () => {
    const g = deleteNode(three(), 'n1')
    expect(graphToSteps(g).map((s) => s.name)).toEqual(['a', 'c'])
    expect(g.edges.map((e) => [e.source, e.target])).toEqual([['n0', 'n2']])
  })

  it('never drops a step from the saved list', () => {
    const g = deleteNode(three(), 'n0')
    expect(graphToSteps(g)).toHaveLength(2)
  })
})

describe('nested approval rule', () => {
  it('finds an approval inside parallel steps, try blocks and switch cases', () => {
    const gate = { name: 'g', type: 'approval', approval: { message: 'm', timeout: 1 } }
    expect(validateSteps([{ name: 'p', type: 'parallel', steps: [gate] }])).toBe(NESTED_APPROVAL_MESSAGE)
    expect(validateSteps([{ name: 't', type: 'try', try: { try: [gate] } }])).toBe(NESTED_APPROVAL_MESSAGE)
    expect(validateSteps([{ name: 's', type: 'switch', switch: { cases: [{ steps: [gate] }] } }])).toBe(
      NESTED_APPROVAL_MESSAGE,
    )
    expect(validateSteps([gate])).toBeNull()
  })

  it('refuses inspector JSON that nests an approval', () => {
    const text = JSON.stringify({
      name: 'p', type: 'parallel', steps: [{ name: 'g', type: 'approval' }],
    })
    expect(parseStepJSON(text)).toEqual({ ok: false, reason: NESTED_APPROVAL_MESSAGE })
  })

  it('rejects malformed or non-object inspector JSON', () => {
    expect(parseStepJSON('{').ok).toBe(false)
    expect(parseStepJSON('[]').ok).toBe(false)
    expect(parseStepJSON('{"name":"x","type":"script"}').ok).toBe(true)
  })
})

describe('unsaveableFields', () => {
  it('lists stored workflow fields a save cannot carry', () => {
    expect(unsaveableFields({ on_failure: 'x', deprecated: true, version_tags: [] })).toEqual([
      'on_failure', 'deprecated',
    ])
    expect(unsaveableFields(undefined)).toEqual([])
  })
})
