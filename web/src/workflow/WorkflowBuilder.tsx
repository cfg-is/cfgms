// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz

/*
 * WorkflowBuilder — full-screen workflow editor (Issue #4615).
 *
 * Routes: /workflows/:name/builder (edit) and /workflows/new/builder (create).
 * Rendered outside the app shell so the canvas owns the viewport.
 *
 * The canvas is the top-level step chain from builderModel.ts: nodes are
 * steps, edges are execution order. Steps the canvas cannot draw (parallel,
 * loop, switch, try, ...) are opaque nodes edited as JSON in the inspector and
 * otherwise saved verbatim. Save issues PUT /api/v1/workflows/{name} (or POST
 * for a new workflow) — the same wholesale-replace path as the drawer's Steps
 * tab, so a workflow carrying fields CreateWorkflowRequest cannot hold has Save
 * disabled rather than silently losing them.
 *
 * Approval gates are top-level only (features/workflow/parser.go); dropping
 * one onto a container node, or authoring one inside an opaque node's JSON, is
 * refused with a message and never reaches the saved body.
 *
 * Security A9.1: workflow, step, and config strings are user-authored; they are
 * rendered as JSX text or controlled input values, never dangerouslySetInnerHTML.
 */
import { useCallback, useEffect, useMemo, useState, type DragEvent } from 'react'
import { useNavigate, useParams } from 'react-router'
import {
  ReactFlow,
  Handle,
  Position,
  Background,
  BackgroundVariant,
  Controls,
  type Connection,
  type NodeProps,
  type Node as RFNode,
  type Edge as RFEdge,
} from '@xyflow/react'
import '@xyflow/react/dist/style.css'
import Dagre from '@dagrejs/dagre'
import { apiFetch } from '../api/client.ts'
import { useWorkflowList, type VersionedWorkflow } from './useWorkflows.ts'
import {
  PALETTE,
  addNode,
  connectNodes,
  deleteNode,
  graphToSteps,
  isOpaque,
  minutesToNs,
  nsToMinutes,
  orderNodes,
  parseStepJSON,
  removeEdge,
  stepsToGraph,
  unsaveableFields,
  updateStep,
  validateSteps,
  type BuilderGraph,
  type PaletteKind,
  type StepJSON,
} from './builderModel.ts'
import './WorkflowGraph.css'
import './Workflow.css'
import './WorkflowBuilder.css'

const NODE_W = 150
const NODE_H = 82
const PALETTE_MIME = 'application/x-cfgms-palette'

// ── Canvas node ───────────────────────────────────────────────────────────────

interface BNodeData extends Record<string, unknown> {
  name: string
  type: string
  opaque: boolean
  tone: string
  icon: string
}
type BNode = RFNode<BNodeData, 'builderNode'>

function toneFor(step: StepJSON): { tone: string; icon: string } {
  if (isOpaque(step)) return { tone: 'cond', icon: 'IF' }
  switch (step.type) {
    case 'approval': return { tone: 'gate', icon: 'AP' }
    case 'notify': return { tone: 'notify', icon: 'NT' }
    default: return { tone: 'module', icon: 'MD' }
  }
}

function BuilderNodeCard({ id, data, selected }: NodeProps<BNode>) {
  return (
    <div
      className={`wfg-node bld-node${selected ? ' selected' : ''}`}
      data-testid={`node-${id}`}
      data-node-id={id}
      data-opaque={data.opaque ? 'true' : 'false'}
    >
      <Handle type="target" position={Position.Left} />
      <div className="wfg-nhead">
        <span className={`wfg-nico ${data.tone}`}>{data.icon}</span>
        <div>
          <div className="wfg-nttl">{data.name}</div>
          <div className="wfg-ntype">{data.type || 'step'}</div>
        </div>
      </div>
      {data.opaque && <div className="wfg-nfoot">edit in inspector</div>}
      <Handle type="source" position={Position.Right} />
    </div>
  )
}

const nodeTypes = { builderNode: BuilderNodeCard }

// ── Layout ────────────────────────────────────────────────────────────────────

type Positions = Map<string, { x: number; y: number }>

/* Deterministic dagre layout on opaque keys (see WorkflowGraph.applyDagreLayout). */
function layoutGraph(graph: BuilderGraph): Positions {
  const keys = new Map(graph.nodes.map((n, i) => [n.id, `k${i}`]))
  const g = new Dagre.graphlib.Graph()
  g.setDefaultEdgeLabel(() => ({}))
  g.setGraph({ rankdir: 'LR', nodesep: 50, ranksep: 60, marginx: 20, marginy: 20 })
  for (const k of keys.values()) g.setNode(k, { width: NODE_W, height: NODE_H })
  for (const e of graph.edges) {
    const s = keys.get(e.source)
    const t = keys.get(e.target)
    if (s !== undefined && t !== undefined) g.setEdge(s, t)
  }
  Dagre.layout(g)
  const out: Positions = new Map()
  for (const n of graph.nodes) {
    const k = keys.get(n.id)
    const p = k === undefined ? undefined : g.node(k)
    if (p !== undefined) out.set(n.id, { x: p.x - NODE_W / 2, y: p.y - NODE_H / 2 })
  }
  return out
}

// ── Inspector ─────────────────────────────────────────────────────────────────

function asRecord(v: unknown): Record<string, unknown> {
  return typeof v === 'object' && v !== null && !Array.isArray(v) ? (v as Record<string, unknown>) : {}
}

function Inspector({
  step,
  onChange,
  onDelete,
  onRefuse,
}: {
  step: StepJSON
  onChange: (next: StepJSON) => void
  onDelete: () => void
  onRefuse: (message: string) => void
}) {
  const opaque = isOpaque(step)
  // null = show the step's current JSON; a string = the operator's in-progress edit.
  const [draft, setDraft] = useState<string | null>(null)
  const jsonText = draft ?? JSON.stringify(step, null, 2)
  const setJsonText = setDraft

  function setBlock(key: 'approval' | 'notify', patch: Record<string, unknown>) {
    const current = key === 'approval' ? step.approval : step.notify
    onChange({ ...step, [key]: { ...asRecord(current), ...patch } })
  }

  const approval = asRecord(step.approval)
  const notify = asRecord(step.notify)
  const strOf = (v: unknown) => (typeof v === 'string' ? v : '')

  return (
    <aside className="bld-inspector" data-testid="builder-inspector" aria-label="Step inspector">
      <div className="bld-ph">Inspector</div>
      <label className="bld-field">
        <span className="lbl">Name</span>
        <input
          value={strOf(step.name)}
          onChange={(e) => onChange({ ...step, name: e.target.value })}
          data-testid="inspector-name"
        />
      </label>
      <div className="bld-field">
        <span className="lbl">Type</span>
        <span className="mono" data-testid="inspector-type">{strOf(step.type)}</span>
      </div>

      {opaque && (
        <div className="bld-field">
          <span className="lbl">Step JSON (edit in inspector)</span>
          <textarea
            className="mono"
            rows={12}
            value={jsonText}
            onChange={(e) => setJsonText(e.target.value)}
            data-testid="inspector-json"
          />
          <button
            type="button"
            className="wf-btn-sm"
            data-testid="inspector-json-apply"
            onClick={() => {
              const parsed = parseStepJSON(jsonText)
              if (!parsed.ok) onRefuse(parsed.reason)
              else {
                setDraft(null)
                onChange(parsed.step)
              }
            }}
          >
            Apply JSON
          </button>
        </div>
      )}

      {!opaque && step.type === 'approval' && (
        <>
          <label className="bld-field">
            <span className="lbl">Message</span>
            <input
              value={strOf(approval.message)}
              onChange={(e) => setBlock('approval', { message: e.target.value })}
              data-testid="inspector-approval-message"
            />
          </label>
          <label className="bld-field">
            <span className="lbl">Approver permission</span>
            <input
              value={strOf(approval.approver_permission)}
              onChange={(e) => {
                const rest = Object.fromEntries(
                  Object.entries(approval).filter(([k]) => k !== 'approver_permission'),
                )
                onChange({
                  ...step,
                  approval: e.target.value === '' ? rest : { ...rest, approver_permission: e.target.value },
                })
              }}
              data-testid="inspector-approval-permission"
            />
          </label>
          <label className="bld-field">
            <span className="lbl">Expires after (minutes)</span>
            <input
              type="number"
              min={1}
              value={nsToMinutes(approval.timeout)}
              onChange={(e) => setBlock('approval', { timeout: minutesToNs(Number(e.target.value)) })}
              data-testid="inspector-approval-timeout"
            />
          </label>
        </>
      )}

      {!opaque && step.type === 'notify' && (
        <>
          <label className="bld-field">
            <span className="lbl">URL</span>
            <input
              value={strOf(notify.url)}
              onChange={(e) => setBlock('notify', { url: e.target.value })}
              data-testid="inspector-notify-url"
            />
          </label>
          <label className="bld-field">
            <span className="lbl">Title</span>
            <input
              value={strOf(notify.title)}
              onChange={(e) => setBlock('notify', { title: e.target.value })}
              data-testid="inspector-notify-title"
            />
          </label>
          <label className="bld-field">
            <span className="lbl">Message</span>
            <input
              value={strOf(notify.message)}
              onChange={(e) => setBlock('notify', { message: e.target.value })}
              data-testid="inspector-notify-message"
            />
          </label>
          <label className="bld-field">
            <span className="lbl">Severity</span>
            <select
              value={strOf(notify.severity) || 'info'}
              onChange={(e) => setBlock('notify', { severity: e.target.value })}
              data-testid="inspector-notify-severity"
            >
              <option value="info">info</option>
              <option value="warning">warning</option>
              <option value="critical">critical</option>
            </select>
          </label>
        </>
      )}

      {!opaque && step.type !== 'approval' && step.type !== 'notify' && (
        <div className="bld-field">
          <span className="lbl">Config / step JSON</span>
          <textarea
            className="mono"
            rows={10}
            value={jsonText}
            onChange={(e) => setJsonText(e.target.value)}
            data-testid="inspector-json"
          />
          <button
            type="button"
            className="wf-btn-sm"
            data-testid="inspector-json-apply"
            onClick={() => {
              const parsed = parseStepJSON(jsonText)
              if (!parsed.ok) onRefuse(parsed.reason)
              else {
                setDraft(null)
                onChange(parsed.step)
              }
            }}
          >
            Apply JSON
          </button>
        </div>
      )}

      <button type="button" className="wf-btn-danger" onClick={onDelete} data-testid="inspector-delete">
        Delete node
      </button>
    </aside>
  )
}

// ── Editor ────────────────────────────────────────────────────────────────────

function BuilderEditor({ workflow, isNew }: { workflow: VersionedWorkflow; isNew: boolean }) {
  const navigate = useNavigate()
  const [graph, setGraph] = useState<BuilderGraph>(() => stepsToGraph(workflow.steps))
  const [positions, setPositions] = useState<Positions>(() => layoutGraph(stepsToGraph(workflow.steps)))
  const [selectedId, setSelectedId] = useState<string | null>(null)
  const [notice, setNotice] = useState<string | null>(null)
  const [dirty, setDirty] = useState(false)
  const [saving, setSaving] = useState(false)
  const [saveError, setSaveError] = useState<string | null>(null)
  const [saved, setSaved] = useState(false)
  const [newName, setNewName] = useState('')
  const blocked = unsaveableFields(workflow.raw)

  // Unsaved-changes guard for tab close / reload; in-app exits go through leave().
  useEffect(() => {
    if (!dirty) return
    const handler = (e: BeforeUnloadEvent) => {
      e.preventDefault()
      e.returnValue = ''
    }
    window.addEventListener('beforeunload', handler)
    return () => window.removeEventListener('beforeunload', handler)
  }, [dirty])

  function leave() {
    if (dirty && !window.confirm('You have unsaved changes. Leave the builder and discard them?')) return
    navigate('/workflows')
  }

  /* Apply a structural edit: re-run the deterministic layout and mark dirty. */
  const commit = useCallback((next: BuilderGraph) => {
    setGraph(next)
    setPositions(layoutGraph(next))
    setDirty(true)
    setSaved(false)
    setNotice(null)
  }, [])

  function handleAdd(kind: PaletteKind, intoContainer?: string) {
    const result = addNode(graph, kind, intoContainer)
    if (!result.ok) {
      setNotice(result.reason)
      return
    }
    commit(result.graph)
    setSelectedId(result.nodeId)
  }

  function handleDrop(e: DragEvent<HTMLDivElement>) {
    const kind = e.dataTransfer.getData(PALETTE_MIME) as PaletteKind
    if (!PALETTE.some((p) => p.kind === kind)) return
    e.preventDefault()
    const target = e.target instanceof Element ? e.target.closest('[data-node-id]') : null
    handleAdd(kind, target?.getAttribute('data-node-id') ?? undefined)
  }

  function handleConnect(c: Connection) {
    if (c.source === null || c.target === null) return
    commit(connectNodes(graph, c.source, c.target))
  }

  function handleDelete(nodeId: string) {
    commit(deleteNode(graph, nodeId))
    setSelectedId(null)
  }

  async function handleSave() {
    const steps = graphToSteps(graph)
    const refusal = validateSteps(steps)
    if (refusal !== null) {
      setNotice(refusal)
      return
    }
    const name = isNew ? newName.trim() : workflow.name
    if (name === '') {
      setSaveError('Workflow name is required')
      return
    }
    if (steps.length === 0) {
      setSaveError('Add at least one step before saving')
      return
    }
    setSaving(true)
    setSaveError(null)
    setSaved(false)
    try {
      const body: Record<string, unknown> = { name, steps }
      if (workflow.description) body.description = workflow.description
      if (workflow.version) body.version = workflow.version
      if (workflow.variables !== undefined) body.variables = workflow.variables
      // PUT rebuilds the workflow from the body; omitting timeout would turn a
      // bounded workflow into an unbounded one.
      if (typeof workflow.timeout === 'number') body.timeout = workflow.timeout
      const response = await apiFetch(
        isNew ? '/api/v1/workflows' : `/api/v1/workflows/${encodeURIComponent(name)}`,
        {
          method: isNew ? 'POST' : 'PUT',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify(body),
        },
      )
      if (!response.ok) {
        const errBody = (await response.json().catch(() => ({}))) as Record<string, unknown>
        throw new Error(typeof errBody.error === 'string' && errBody.error ? errBody.error : `Save failed — ${response.status}`)
      }
      setDirty(false)
      setSaved(true)
      if (isNew) navigate(`/workflows/${encodeURIComponent(name)}/builder`, { replace: true })
    } catch (cause: unknown) {
      setSaveError(cause instanceof Error && cause.message ? cause.message : 'Save failed')
    } finally {
      setSaving(false)
    }
  }

  const rfNodes: BNode[] = useMemo(
    () =>
      graph.nodes.map((n) => {
        const { tone, icon } = toneFor(n.step)
        return {
          id: n.id,
          type: 'builderNode',
          position: positions.get(n.id) ?? { x: 0, y: 0 },
          selected: n.id === selectedId,
          data: {
            name: typeof n.step.name === 'string' ? n.step.name : '',
            type: typeof n.step.type === 'string' ? n.step.type : '',
            opaque: isOpaque(n.step),
            tone,
            icon,
          },
        }
      }),
    [graph.nodes, positions, selectedId],
  )
  const rfEdges: RFEdge[] = useMemo(
    () => graph.edges.map((e) => ({ id: e.id, source: e.source, target: e.target })),
    [graph.edges],
  )

  const selected = graph.nodes.find((n) => n.id === selectedId)
  const stepCount = orderNodes(graph).length

  return (
    <div className="bld-root" data-testid="workflow-builder">
      <div className="bld-bar">
        <button type="button" className="icobtn" aria-label="Back to workflows" onClick={leave} data-testid="builder-back">
          ‹
        </button>
        {isNew ? (
          <input
            className="bld-name"
            placeholder="workflow-name"
            value={newName}
            onChange={(e) => { setNewName(e.target.value); setDirty(true) }}
            aria-label="Workflow name"
            data-testid="builder-name-input"
          />
        ) : (
          <span className="bld-wfname" data-testid="builder-name">{workflow.name}</span>
        )}
        {workflow.version && <span className="mut">v{workflow.version}</span>}
        <span className="mut" data-testid="builder-step-count">{stepCount} {stepCount === 1 ? 'step' : 'steps'}</span>
        {dirty && <span className="mut" data-testid="builder-dirty">Unsaved changes</span>}
        <div className="bld-spacer" />
        {blocked.length > 0 && (
          <span className="wf-form-error" data-testid="builder-save-blocked">
            Saving is disabled: this workflow declares {blocked.join(', ')}, which a save cannot carry.
          </span>
        )}
        {saveError && <span className="wf-form-error" data-testid="builder-save-error">{saveError}</span>}
        {saved && <span className="mut" data-testid="builder-save-success">Saved.</span>}
        <button
          type="button"
          className="wf-btn"
          onClick={handleSave}
          disabled={saving || blocked.length > 0}
          data-testid="builder-save"
        >
          {saving ? 'Saving…' : 'Save'}
        </button>
      </div>

      {notice !== null && (
        <div className="bld-notice" role="alert" data-testid="builder-notice">
          <span>{notice}</span>
          <button type="button" className="icobtn" aria-label="Dismiss" onClick={() => setNotice(null)}>✕</button>
        </div>
      )}

      <div className="bld-stage">
        <div
          className="bld-canvas wfg-root"
          data-testid="builder-canvas"
          onDragOver={(e) => e.preventDefault()}
          onDrop={handleDrop}
        >
          <div className="bld-palette" data-testid="builder-palette">
            <div className="bld-ph">Add node</div>
            {PALETTE.map((p) => (
              <button
                key={p.kind}
                type="button"
                className="bld-pitem"
                draggable
                onDragStart={(e) => e.dataTransfer.setData(PALETTE_MIME, p.kind)}
                onClick={() => handleAdd(p.kind)}
                data-testid={`palette-${p.kind}`}
              >
                <span className={`wfg-nico ${p.tone}`}>{p.icon}</span>
                {p.label}
              </button>
            ))}
          </div>
          {stepCount === 0 && (
            <div className="notice empty bld-empty" data-testid="builder-empty">
              <div className="ic">◍</div>
              <h3>No steps yet</h3>
              <p>Add a node from the palette to start building.</p>
            </div>
          )}
          <ReactFlow
            nodes={rfNodes}
            edges={rfEdges}
            nodeTypes={nodeTypes}
            fitView
            nodesConnectable
            onConnect={handleConnect}
            onNodeClick={(_, n) => setSelectedId(n.id)}
            onPaneClick={() => setSelectedId(null)}
            onNodeDragStop={(_, n) =>
              setPositions((prev) => new Map(prev).set(n.id, n.position))
            }
            onNodesDelete={(ns) => {
              let next = graph
              for (const n of ns) next = deleteNode(next, n.id)
              commit(next)
              setSelectedId(null)
            }}
            onEdgesDelete={(es) => {
              let next = graph
              for (const e of es) next = removeEdge(next, e.id)
              commit(next)
            }}
          >
            <Background variant={BackgroundVariant.Dots} gap={22} size={1.4} />
            <Controls showInteractive={false} position="bottom-right" />
          </ReactFlow>
        </div>
        {selected !== undefined && (
          <Inspector
            key={selected.id}
            step={selected.step}
            onChange={(next) => {
              setGraph((g) => updateStep(g, selected.id, next))
              setDirty(true)
              setSaved(false)
              setNotice(null)
            }}
            onDelete={() => handleDelete(selected.id)}
            onRefuse={setNotice}
          />
        )}
      </div>
    </div>
  )
}

// ── Route component ───────────────────────────────────────────────────────────

const BLANK_WORKFLOW: VersionedWorkflow = {
  name: '',
  description: '',
  version: '',
  steps: [],
  semantic_version: { major: 0, minor: 0, patch: 0, pre_release: '', build_meta: '' },
}

export default function WorkflowBuilder() {
  const { name } = useParams()
  const navigate = useNavigate()
  const isNew = name === undefined
  const { workflows, loading, error, retry } = useWorkflowList()

  if (isNew) return <BuilderEditor workflow={BLANK_WORKFLOW} isNew />

  if (loading) {
    return (
      <div className="bld-root bld-state" data-testid="builder-loading" aria-busy="true">
        <div className="notice"><h3>Loading workflow…</h3></div>
      </div>
    )
  }
  if (error !== null) {
    return (
      <div className="bld-root bld-state" data-testid="builder-error">
        <div className="notice error" role="alert">
          <h3>Couldn&apos;t load the workflow</h3>
          <p>{error}</p>
          <button type="button" className="wf-btn-secondary" onClick={retry}>Retry</button>
        </div>
      </div>
    )
  }
  const workflow = workflows.find((w) => w.name === name)
  if (workflow === undefined) {
    return (
      <div className="bld-root bld-state" data-testid="builder-not-found">
        <div className="notice empty">
          <h3>Workflow not found</h3>
          <p>No workflow named “{name}” exists in this scope.</p>
          <button type="button" className="wf-btn-secondary" onClick={() => navigate('/workflows')}>
            Back to workflows
          </button>
        </div>
      </div>
    )
  }
  return <BuilderEditor key={workflow.name} workflow={workflow} isNew={false} />
}
