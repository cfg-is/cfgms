// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz

/*
 * Pure model behind the full-screen workflow builder (Issue #4615).
 *
 * A workflow is an ordered list of top-level steps that the engine runs in
 * sequence, so the canvas is a chain: one node per top-level step, one edge
 * per adjacent pair. Connecting and deleting nodes re-orders that list.
 *
 * Round-trip guarantee: every node carries the step's verbatim controller JSON
 * (`step`). PUT /api/v1/workflows/{name} is a wholesale replace, so the canvas
 * never rebuilds a step from typed fields — an edit produces a new object by
 * spreading the stored one and overriding only the keys the edit owns. A step
 * the canvas cannot edit graphically (parallel, loop, switch, try, ...) is an
 * "opaque" node whose whole JSON is edited as text and otherwise passed through
 * untouched, so unmodified steps serialise back identically.
 */
import type { WorkflowStep } from './useWorkflows.ts'

export type StepJSON = Record<string, unknown>

export interface BuilderNode {
  id: string
  step: StepJSON
}

export interface BuilderEdge {
  id: string
  source: string
  target: string
}

export interface BuilderGraph {
  nodes: BuilderNode[]
  edges: BuilderEdge[]
}

// ── Classification ────────────────────────────────────────────────────────────

// Step keys that hold child steps or control-flow blocks the canvas cannot draw.
const CONTAINER_KEYS = [
  'steps', 'switch', 'loop', 'try', 'fanout', 'fanin', 'workflow_call', 'composite',
] as const
const CONTAINER_TYPES = new Set([
  'parallel', 'sequential', 'conditional', 'loop', 'switch', 'try', 'fanout', 'fanin',
])

/* A step the canvas shows as an opaque node edited only through JSON. */
export function isOpaque(step: StepJSON): boolean {
  if (typeof step.type === 'string' && CONTAINER_TYPES.has(step.type)) return true
  const values = new Map(Object.entries(step))
  return CONTAINER_KEYS.some((k) => !isEmptyValue(values.get(k)))
}

/* A container that child steps could be dropped into (parallel branch, loop, ...). */
export function isContainer(step: StepJSON): boolean {
  return isOpaque(step)
}

function isEmptyValue(v: unknown): boolean {
  if (v === undefined || v === null || v === false || v === '') return true
  return Array.isArray(v) && v.length === 0
}

// ── Palette ───────────────────────────────────────────────────────────────────

export type PaletteKind = 'module' | 'http' | 'approval' | 'notify'

export interface PaletteItem {
  kind: PaletteKind
  label: string
  icon: string
  tone: 'module' | 'gate' | 'notify'
}

export const PALETTE: PaletteItem[] = [
  { kind: 'module', label: 'Module / script', icon: 'MD', tone: 'module' },
  { kind: 'http', label: 'HTTP call', icon: 'MD', tone: 'module' },
  { kind: 'approval', label: 'Approval gate', icon: 'AP', tone: 'gate' },
  { kind: 'notify', label: 'Notify', icon: 'NT', tone: 'notify' },
]

// time.Duration travels as integer nanoseconds in the controller's JSON.
const NS_PER_MINUTE = 60 * 1_000_000_000
export const DEFAULT_APPROVAL_TIMEOUT_NS = 24 * 60 * NS_PER_MINUTE

export function nsToMinutes(ns: unknown): number {
  return typeof ns === 'number' ? Math.round(ns / NS_PER_MINUTE) : 0
}

export function minutesToNs(minutes: number): number {
  return Math.round(minutes) * NS_PER_MINUTE
}

/* A fresh step for a palette kind, shaped as features/workflow/types.go Step. */
export function newStep(kind: PaletteKind, name: string): StepJSON {
  switch (kind) {
    case 'approval':
      return {
        name,
        type: 'approval',
        approval: { message: 'Approve to continue', timeout: DEFAULT_APPROVAL_TIMEOUT_NS },
      }
    case 'notify':
      return {
        name,
        type: 'notify',
        notify: { url: '', title: 'Workflow notification', severity: 'info' },
      }
    case 'http':
      return { name, type: 'http', http: { method: 'GET', url: '' } }
    default:
      return { name, type: 'script', config: {} }
  }
}

// ── Nested-approval rule ──────────────────────────────────────────────────────

/*
 * The engine resumes an approval gate by replaying the top-level step list, so
 * an approval inside any child block is rejected by the controller
 * (features/workflow/parser.go nestedApprovalIn). Mirror that walk here so the
 * canvas refuses it before a save is attempted.
 */
export function findNestedApproval(step: StepJSON): string {
  for (const block of childBlocks(step)) {
    for (const child of block) {
      if (child.type === 'approval') return String(child.name ?? '')
      const deeper = findNestedApproval(child)
      if (deeper !== '') return deeper
    }
  }
  return ''
}

function asSteps(v: unknown): StepJSON[] {
  return Array.isArray(v)
    ? v.filter((s): s is StepJSON => typeof s === 'object' && s !== null && !Array.isArray(s))
    : []
}

function childBlocks(step: StepJSON): StepJSON[][] {
  const blocks: StepJSON[][] = [asSteps(step.steps)]
  const tryBlock = step.try
  if (typeof tryBlock === 'object' && tryBlock !== null) {
    const t = tryBlock as StepJSON
    blocks.push(asSteps(t.try), asSteps(t.finally))
    if (Array.isArray(t.catch)) {
      for (const c of t.catch) {
        if (typeof c === 'object' && c !== null) blocks.push(asSteps((c as StepJSON).steps))
      }
    }
  }
  const sw = step.switch
  if (typeof sw === 'object' && sw !== null) {
    const s = sw as StepJSON
    blocks.push(asSteps(s.default))
    if (Array.isArray(s.cases)) {
      for (const c of s.cases) {
        if (typeof c === 'object' && c !== null) blocks.push(asSteps((c as StepJSON).steps))
      }
    }
  }
  const eh = step.error_handling
  if (typeof eh === 'object' && eh !== null) {
    const fb = (eh as StepJSON).fallback_step
    if (typeof fb === 'object' && fb !== null) blocks.push([fb as StepJSON])
  }
  return blocks
}

export const NESTED_APPROVAL_MESSAGE =
  'Approval gates must be top-level steps. They cannot sit inside a parallel branch, loop, or other block.'

/* Returns the refusal message when any top-level step nests an approval. */
export function validateSteps(steps: StepJSON[]): string | null {
  for (const s of steps) {
    if (findNestedApproval(s) !== '') return NESTED_APPROVAL_MESSAGE
  }
  return null
}

// ── WorkflowStep[] <-> graph ──────────────────────────────────────────────────

export function nodeIdFor(index: number): string {
  return `n${index}`
}

/* Build the chain graph from the workflow's steps, each carried verbatim. */
export function stepsToGraph(steps: WorkflowStep[]): BuilderGraph {
  const nodes: BuilderNode[] = steps.map((s, i) => ({
    id: nodeIdFor(i),
    step: s.raw !== undefined ? s.raw : { id: s.id, name: s.name, type: s.type, config: s.config },
  }))
  const edges: BuilderEdge[] = []
  let prev: BuilderNode | undefined
  for (const n of nodes) {
    if (prev !== undefined) edges.push(edgeBetween(prev.id, n.id))
    prev = n
  }
  return { nodes, edges }
}

export function edgeBetween(source: string, target: string): BuilderEdge {
  return { id: `${source}->${target}`, source, target }
}

/*
 * Order nodes by following edges. Chains start at nodes with no incoming edge
 * (taken in node-array order, so an unconnected node keeps its place) and run
 * to their end. Any node left over — only possible for a malformed cycle — is
 * appended so no step is ever dropped.
 */
export function orderNodes(graph: BuilderGraph): BuilderNode[] {
  const byId = new Map(graph.nodes.map((n) => [n.id, n]))
  const next = new Map(graph.edges.map((e) => [e.source, e.target]))
  const hasIncoming = new Set(graph.edges.map((e) => e.target))
  const seen = new Set<string>()
  const ordered: BuilderNode[] = []
  const walk = (start: BuilderNode) => {
    let cur: BuilderNode | undefined = start
    while (cur !== undefined && !seen.has(cur.id)) {
      seen.add(cur.id)
      ordered.push(cur)
      const nextId = next.get(cur.id)
      cur = nextId === undefined ? undefined : byId.get(nextId)
    }
  }
  for (const n of graph.nodes) if (!hasIncoming.has(n.id)) walk(n)
  for (const n of graph.nodes) walk(n)
  return ordered
}

export function graphToSteps(graph: BuilderGraph): StepJSON[] {
  return orderNodes(graph).map((n) => n.step)
}

// ── Graph edits ───────────────────────────────────────────────────────────────

function nextNodeId(graph: BuilderGraph): string {
  let max = -1
  for (const n of graph.nodes) {
    const m = /^n(\d+)$/.exec(n.id)
    if (m) max = Math.max(max, Number(m[1]))
  }
  return nodeIdFor(max + 1)
}

function uniqueName(graph: BuilderGraph, base: string): string {
  const taken = new Set(graph.nodes.map((n) => String(n.step.name ?? '')))
  if (!taken.has(base)) return base
  let i = 2
  while (taken.has(`${base}-${i}`)) i++
  return `${base}-${i}`
}

export type AddResult =
  | { ok: true; graph: BuilderGraph; nodeId: string }
  | { ok: false; reason: string }

/*
 * Add a palette node at the top level, appended to the end of the chain.
 * `intoContainer` is the node the operator dropped it onto, if any: an approval
 * dropped into a container node is refused, never added.
 */
export function addNode(graph: BuilderGraph, kind: PaletteKind, intoContainer?: string): AddResult {
  if (kind === 'approval' && intoContainer !== undefined) {
    const target = graph.nodes.find((n) => n.id === intoContainer)
    if (target !== undefined && isContainer(target.step)) {
      return { ok: false, reason: NESTED_APPROVAL_MESSAGE }
    }
  }
  const id = nextNodeId(graph)
  const base = kind === 'module' ? 'step' : kind
  const node: BuilderNode = { id, step: newStep(kind, uniqueName(graph, base)) }
  const tail = orderNodes(graph).at(-1)
  const edges = tail === undefined ? graph.edges : [...graph.edges, edgeBetween(tail.id, id)]
  return { ok: true, graph: { nodes: [...graph.nodes, node], edges }, nodeId: id }
}

/* True when `from` can already reach `to` by following edges. */
function reaches(graph: BuilderGraph, from: string, to: string): boolean {
  const next = new Map(graph.edges.map((e) => [e.source, e.target]))
  let cur: string | undefined = from
  const seen = new Set<string>()
  while (cur !== undefined && !seen.has(cur)) {
    if (cur === to) return true
    seen.add(cur)
    cur = next.get(cur)
  }
  return false
}

/*
 * Connect source -> target. The chain stays linear: an existing outgoing edge
 * of source and incoming edge of target are replaced. Self-loops and cycles
 * are refused (returns the graph unchanged).
 */
export function connectNodes(graph: BuilderGraph, source: string, target: string): BuilderGraph {
  if (source === target || reaches(graph, target, source)) return graph
  const edges = graph.edges.filter((e) => e.source !== source && e.target !== target)
  edges.push(edgeBetween(source, target))
  return { nodes: graph.nodes, edges }
}

export function removeEdge(graph: BuilderGraph, edgeId: string): BuilderGraph {
  return { nodes: graph.nodes, edges: graph.edges.filter((e) => e.id !== edgeId) }
}

/* Delete a node and bridge its neighbours so the rest of the chain stays joined. */
export function deleteNode(graph: BuilderGraph, nodeId: string): BuilderGraph {
  const incoming = graph.edges.find((e) => e.target === nodeId)
  const outgoing = graph.edges.find((e) => e.source === nodeId)
  const edges = graph.edges.filter((e) => e.source !== nodeId && e.target !== nodeId)
  if (incoming !== undefined && outgoing !== undefined) {
    edges.push(edgeBetween(incoming.source, outgoing.target))
  }
  return { nodes: graph.nodes.filter((n) => n.id !== nodeId), edges }
}

/* Replace one node's step JSON (the caller builds it from the stored step). */
export function updateStep(graph: BuilderGraph, nodeId: string, step: StepJSON): BuilderGraph {
  return {
    nodes: graph.nodes.map((n) => (n.id === nodeId ? { ...n, step } : n)),
    edges: graph.edges,
  }
}

/* Parse the inspector's JSON field for an opaque node. */
export function parseStepJSON(text: string): { ok: true; step: StepJSON } | { ok: false; reason: string } {
  let parsed: unknown
  try {
    parsed = JSON.parse(text)
  } catch {
    return { ok: false, reason: 'Step JSON is not valid JSON' }
  }
  if (typeof parsed !== 'object' || parsed === null || Array.isArray(parsed)) {
    return { ok: false, reason: 'Step JSON must be an object' }
  }
  const step = parsed as StepJSON
  if (findNestedApproval(step) !== '') return { ok: false, reason: NESTED_APPROVAL_MESSAGE }
  return { ok: true, step }
}

// ── Workflow-level fields a save cannot carry ─────────────────────────────────

/*
 * CreateWorkflowRequest (features/controller/api/handlers_workflows.go) decodes
 * only name, description, version, steps, variables and timeout, so anything
 * else stored on the workflow is dropped by PUT. Rather than silently deleting
 * them, editors refuse to save such a workflow.
 */
export const UNSAVEABLE_WORKFLOW_KEYS = [
  'on_failure', 'error_workflows', 'version_tags', 'deprecated',
  'deprecation_note', 'changelog',
] as const

function hasMeaningfulValue(value: unknown): boolean {
  if (value === undefined || value === null || value === false || value === '') return false
  if (Array.isArray(value)) return value.length > 0
  return true
}

export function unsaveableFields(source: Record<string, unknown> | undefined): string[] {
  if (!source) return []
  // Map.get(), not a computed `source[k]` index, so a key drawn from the fixed
  // list can't trip detect-object-injection.
  const values = new Map(Object.entries(source))
  return UNSAVEABLE_WORKFLOW_KEYS.filter((k) => hasMeaningfulValue(values.get(k)))
}
