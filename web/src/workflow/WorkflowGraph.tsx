// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz

/*
 * WorkflowGraph — read-only flowchart renderer (Story #3037).
 *
 * Renders a WorkflowStep[] block tree as a dagre-auto-laid-out React Flow
 * graph. Typed nodes (module/condition/wait/gate/notify + synthetic trigger),
 * edges derived from step nesting, run-state colorization from an optional
 * WorkflowExecution prop.
 *
 * No editing, no drag, no connect — strictly read-only. The caller owns
 * execution fetching via useExecutionStatus; this component only colors nodes
 * from an already-fetched execution value.
 *
 * Security A9.1: step names, types, and config-derived footer text originate
 * from user-authored workflow content. All strings are rendered as JSX text
 * nodes — never dangerouslySetInnerHTML.
 */
import { useMemo } from 'react'
import {
  ReactFlow,
  Handle,
  Position,
  Background,
  BackgroundVariant,
  type NodeProps,
  type Node as RFNode,
  type Edge as RFEdge,
} from '@xyflow/react'
import '@xyflow/react/dist/style.css'
import Dagre from '@dagrejs/dagre'
import type { WorkflowStep, WorkflowExecution } from './useWorkflows.ts'
import './WorkflowGraph.css'

// ── Constants ─────────────────────────────────────────────────────────────────

const NODE_W = 150
const NODE_H = 82
// Fixed id for the synthetic trigger node (no backing WorkflowStep)
export const TRIGGER_NODE_ID = '__trigger__'

// ── Node data ─────────────────────────────────────────────────────────────────

interface WFNodeData extends Record<string, unknown> {
  stepName: string
  stepType: string
  visualType: string
  runState: 'done' | 'running' | 'failed' | 'pending'
  footer: string
  isConditional: boolean
  switchCaseLabels: string[] | null
}

type WFNode = RFNode<WFNodeData, 'workflowNode'>

// ── Visual-type mapping ───────────────────────────────────────────────────────

function toVisualType(stepType: string): string {
  switch (stepType) {
    case 'trig':
    case 'trigger':
      return 'trig'
    case 'module':
    case 'script':
    case 'api':
    case 'http':
      return 'module'
    case 'condition':
    case 'conditional':
      return 'cond'
    case 'wait':
    case 'poll':
      return 'wait'
    case 'approval':
    case 'gate':
      return 'gate'
    case 'notify':
    case 'notification':
      return 'notify'
    default:
      return 'module'
  }
}

function iconLabel(vtype: string): string {
  switch (vtype) {
    case 'trig':
      return 'HK'
    case 'module':
      return 'MD'
    case 'cond':
      return 'IF'
    case 'wait':
      return 'WT'
    case 'gate':
      return 'AP'
    case 'notify':
      return 'NT'
    default:
      return 'MD'
  }
}

// ── Run-state resolution ──────────────────────────────────────────────────────

type RunState = 'done' | 'running' | 'failed' | 'pending'

/*
 * Step ids come from user-authored workflow content, so they are never used as
 * a computed key into a plain object: `step_results['__proto__'].status` would
 * read an inherited property rather than a real result. The execution is
 * flattened once into a Map keyed by own enumerable properties only
 * (Object.entries), which has no prototype chain to walk.
 */
interface ExecutionIndex {
  currentStep: string
  statuses: Map<string, string>
}

function indexExecution(execution: WorkflowExecution | undefined): ExecutionIndex | undefined {
  if (!execution) return undefined
  const statuses = new Map<string, string>()
  for (const [stepID, result] of Object.entries(execution.step_results ?? {})) {
    if (typeof result !== 'object' || result === null) continue
    const status = (result as Record<string, unknown>).status
    if (typeof status === 'string') statuses.set(stepID, status)
  }
  return { currentStep: execution.current_step ?? '', statuses }
}

function resolveRunState(stepId: string, index: ExecutionIndex | undefined): RunState {
  if (!index) return 'pending'
  if (index.currentStep !== '' && index.currentStep === stepId) return 'running'
  const status = index.statuses.get(stepId)
  if (status === 'completed') return 'done'
  if (status === 'failed') return 'failed'
  if (status === 'running') return 'running'
  return 'pending'
}

// ── Custom node component ─────────────────────────────────────────────────────

function WorkflowNode({ id, data }: NodeProps<WFNode>) {
  const { stepName, stepType, visualType, runState, footer, isConditional, switchCaseLabels } =
    data

  const badge =
    runState === 'done' ? '✓' : runState === 'running' ? '▸' : runState === 'failed' ? '✕' : null

  const nodeClass = `wfg-node ${runState}`

  // Source ports carry their own label so the render pass never indexes back
  // into switchCaseLabels by position.
  const ports: { id: string; label: string | null }[] = isConditional
    ? [
        { id: 'yes', label: 'yes' },
        { id: 'no', label: 'no' },
      ]
    : switchCaseLabels
      ? switchCaseLabels.map((label, i) => ({ id: `case-${i}`, label }))
      : [{ id: 'out', label: null }]

  return (
    <div className={nodeClass} data-testid={`node-${id}`}>
      {badge !== null && <span className="wfg-badge">{badge}</span>}
      <Handle type="target" position={Position.Left} id="in" />
      <div className="wfg-nhead">
        <span className={`wfg-nico ${visualType}`}>{iconLabel(visualType)}</span>
        <div>
          <div className="wfg-ntype">{stepType}</div>
          <div className="wfg-nttl">{stepName}</div>
        </div>
      </div>
      {footer && <div className="wfg-nfoot">{footer}</div>}
      {ports.map((port) => (
        <span key={port.id} className="wfg-port-wrap">
          {port.label !== null && <span className="wfg-plabel">{port.label}</span>}
          <Handle type="source" position={Position.Right} id={port.id} />
        </span>
      ))}
    </div>
  )
}

const nodeTypes = { workflowNode: WorkflowNode }

// ── Graph building ────────────────────────────────────────────────────────────

export interface GraphElements {
  nodes: WFNode[]
  edges: RFEdge[]
}

type ExitRef = { id: string; handle: string }

function makeStepNode(step: WorkflowStep, execution: ExecutionIndex | undefined): WFNode {
  const isConditional = step.type === 'condition' || step.type === 'conditional'
  const isSwitchStep = step.type === 'switch'
  const switchCaseLabels =
    isSwitchStep && step.switch ? step.switch.map((c) => c.label) : null

  const footer = extractFooter(step)
  const visualType = toVisualType(step.type)
  const runState = resolveRunState(step.id, execution)

  return {
    id: step.id,
    type: 'workflowNode',
    position: { x: 0, y: 0 },
    data: {
      stepName: step.name,
      stepType: step.type,
      visualType,
      runState,
      footer,
      isConditional,
      switchCaseLabels,
    },
  }
}

function extractFooter(step: WorkflowStep): string {
  const cfg = step.config ?? {}
  // Only extract safe scalar display values from config
  if (typeof cfg.module === 'string') return cfg.module
  if (typeof cfg.script === 'string') return cfg.script.substring(0, 40)
  if (typeof cfg.channel === 'string') return cfg.channel
  if (typeof cfg.until === 'string') return cfg.until
  return ''
}

function makeEdge(
  source: string,
  target: string,
  sourceHandle: string,
  edgeRunState: RunState,
): RFEdge {
  const edgeClass =
    edgeRunState === 'done' ? 'done' : edgeRunState === 'running' ? 'active' : 'pend'
  return {
    id: `${source}:${sourceHandle}->${target}`,
    source,
    target,
    sourceHandle,
    targetHandle: 'in',
    className: edgeClass,
    type: 'default',
  }
}

// Recursively build nodes and edges for a list of steps, returning exit refs
// so the caller can wire the next sibling's entry edges.
function processStepList(
  steps: WorkflowStep[],
  predExits: ExitRef[],
  elements: GraphElements,
  execution: ExecutionIndex | undefined,
): ExitRef[] {
  let currentExits = predExits

  for (const step of steps) {
    elements.nodes.push(makeStepNode(step, execution))

    // Wire predecessors → this step
    const entryState = resolveRunState(currentExits[0]?.id ?? TRIGGER_NODE_ID, execution)
    for (const pred of currentExits) {
      elements.edges.push(makeEdge(pred.id, step.id, pred.handle, entryState))
    }

    const type = step.type

    if ((type === 'condition' || type === 'conditional') && step.steps?.length) {
      // yes branch runs the nested steps; no branch exits unresolved from cond node
      const yesExits = processStepList(
        step.steps,
        [{ id: step.id, handle: 'yes' }],
        elements,
        execution,
      )
      currentExits = [...yesExits, { id: step.id, handle: 'no' }]
    } else if (type === 'switch' && step.switch?.length) {
      const allBranchExits: ExitRef[] = []
      step.switch.forEach((switchCase, i) => {
        if (switchCase.steps.length) {
          const exits = processStepList(
            switchCase.steps,
            [{ id: step.id, handle: `case-${i}` }],
            elements,
            execution,
          )
          allBranchExits.push(...exits)
        } else {
          allBranchExits.push({ id: step.id, handle: `case-${i}` })
        }
      })
      currentExits = allBranchExits
    } else if (
      (type === 'parallel' || type === 'fanout' || type === 'fan_out') &&
      step.steps?.length
    ) {
      // Fan-out: step node is the fan-out point; each child branch exits independently
      const allBranchExits: ExitRef[] = []
      for (const child of step.steps) {
        const exits = processStepList(
          [child],
          [{ id: step.id, handle: 'out' }],
          elements,
          execution,
        )
        allBranchExits.push(...exits)
      }
      currentExits = allBranchExits
    } else if (type === 'sequential' && step.steps?.length) {
      // Chain children sequentially under this container
      currentExits = processStepList(
        step.steps,
        [{ id: step.id, handle: 'out' }],
        elements,
        execution,
      )
    } else if (
      (type === 'for' || type === 'while' || type === 'foreach') &&
      step.steps?.length
    ) {
      // Render loop body once (no loop-back visual in read-only view)
      processStepList(
        step.steps,
        [{ id: step.id, handle: 'out' }],
        elements,
        execution,
      )
      currentExits = [{ id: step.id, handle: 'out' }]
    } else {
      currentExits = [{ id: step.id, handle: 'out' }]
    }
  }

  return currentExits
}

export function buildGraphElements(
  steps: WorkflowStep[],
  execution?: WorkflowExecution,
): GraphElements {
  const elements: GraphElements = { nodes: [], edges: [] }
  const index = indexExecution(execution)

  // Synthetic trigger node — no backing WorkflowStep
  const trigRunState: 'done' | 'pending' = execution ? 'done' : 'pending'
  elements.nodes.push({
    id: TRIGGER_NODE_ID,
    type: 'workflowNode',
    position: { x: 0, y: 0 },
    data: {
      stepName: 'start',
      stepType: 'trigger',
      visualType: 'trig',
      runState: trigRunState,
      footer: '',
      isConditional: false,
      switchCaseLabels: null,
    },
  })

  processStepList(steps, [{ id: TRIGGER_NODE_ID, handle: 'out' }], elements, index)

  return elements
}

// ── Dagre layout ──────────────────────────────────────────────────────────────

/*
 * graphlib keeps its node/edge tables in plain objects keyed by node id, so a
 * step id authored as "__proto__" (or "constructor") would write through the
 * prototype chain and corrupt Object.prototype for the whole page. Layout
 * therefore runs on opaque generated keys, and positions are mapped back onto
 * the real node ids afterwards — user-authored ids never reach graphlib.
 */
function applyDagreLayout(nodes: WFNode[], edges: RFEdge[]): WFNode[] {
  const layoutKeys = new Map<string, string>()
  nodes.forEach((n, i) => {
    if (!layoutKeys.has(n.id)) layoutKeys.set(n.id, `n${i}`)
  })

  const g = new Dagre.graphlib.Graph()
  g.setDefaultEdgeLabel(() => ({}))
  g.setGraph({ rankdir: 'LR', nodesep: 50, ranksep: 60, marginx: 20, marginy: 20 })

  for (const n of nodes) {
    const key = layoutKeys.get(n.id)
    if (key === undefined) continue
    g.setNode(key, { width: NODE_W, height: NODE_H })
  }
  for (const e of edges) {
    const source = layoutKeys.get(e.source)
    const target = layoutKeys.get(e.target)
    if (source === undefined || target === undefined) continue
    g.setEdge(source, target)
  }

  Dagre.layout(g)

  return nodes.map((n) => {
    const key = layoutKeys.get(n.id)
    const pos = key === undefined ? undefined : g.node(key)
    if (pos === undefined) return n
    return {
      ...n,
      position: { x: pos.x - NODE_W / 2, y: pos.y - NODE_H / 2 },
    }
  })
}

// ── WorkflowGraph component ───────────────────────────────────────────────────

export interface WorkflowGraphProps {
  steps: WorkflowStep[]
  execution?: WorkflowExecution
}

export default function WorkflowGraph({ steps, execution }: WorkflowGraphProps) {
  const { nodes: rawNodes, edges } = useMemo(
    () => buildGraphElements(steps, execution),
    [steps, execution],
  )

  const nodes = useMemo(() => applyDagreLayout(rawNodes, edges), [rawNodes, edges])

  return (
    <div className="wfg-root">
      <ReactFlow
        nodes={nodes}
        edges={edges}
        nodeTypes={nodeTypes}
        fitView
        nodesDraggable={false}
        nodesConnectable={false}
        elementsSelectable={false}
      >
        <Background variant={BackgroundVariant.Dots} gap={22} size={1.4} />
      </ReactFlow>
    </div>
  )
}
