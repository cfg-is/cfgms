// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz

/*
 * Overlay drawer shell for the /workflows browse view (Stories #3039, #3213).
 * Positioned absolute inside .workspace so the list table rows never
 * reflow when the drawer opens or closes.
 *
 * Tab slots: Run (F3), Schedule (#2986), Preview (F4) are placeholder panes;
 * sibling stories mount their content here. Steps tab (Story #3213) restores
 * the structured step authoring and variable editor lost in #3039.
 *
 * Last-run status pill: derived from useWorkflowExecutions(workflow.name) —
 * the same fetch the Run tab (F3) will also mount — picking whichever
 * execution has the latest start_time (the endpoint documents no ordering).
 * A workflow with no executions yet renders a neutral "Never run" pill.
 *
 * Saving the Steps tab issues PUT /api/v1/workflows/{name}, which is a
 * wholesale replace — handleUpdateWorkflow rebuilds the VersionedWorkflow from
 * the request body. The save therefore round-trips each step's verbatim
 * controller JSON (StepRow.source) with only name/type/config overridden, and
 * forwards workflow.timeout unchanged, so execution gating, concurrency
 * throttles and the workflow deadline survive an unrelated edit. Workflow-level
 * fields that CreateWorkflowRequest cannot carry at all disable Save outright
 * rather than being silently dropped (UNSAVEABLE_WORKFLOW_KEYS).
 *
 * Security A9.1: workflow.name, workflow.description, execution status, step
 * names, step values, and variable keys/values originate from user-supplied /
 * controller content and are rendered as JSX text nodes or controlled input
 * values — never dangerouslySetInnerHTML.
 */
import { useState } from 'react'
import { apiFetch } from '../api/client.ts'
import type { VersionedWorkflow, WorkflowExecution, WorkflowStep } from './useWorkflows.ts'
import { useWorkflowExecutions } from './useWorkflows.ts'
import { useTenantScope } from '../shell/TenantScopeContext.tsx'

type DrawerTab = 'run' | 'schedule' | 'preview' | 'steps'

interface WorkflowDrawerProps {
  workflow: VersionedWorkflow
  onClose: () => void
}

// ── Row ID counter (used only as React key, never surfaced to DOM) ────────────

let _rowId = 0
function mkid(): string {
  _rowId += 1
  return String(_rowId)
}

// ── Step builder types ────────────────────────────────────────────────────────

const STEP_TYPES = ['script', 'shell', 'http', 'notification', 'approval'] as const

interface StepRow {
  id: string
  name: string
  type: string
  scriptBody: string   // config.script for type === 'script'
  configJson: string   // raw config JSON (for non-script types or advanced mode)
  rawOpen: boolean     // whether the Raw config details panel is expanded
  /*
   * Verbatim step JSON the controller sent for this row (empty for rows the
   * operator added). PUT /api/v1/workflows/{id} replaces the whole workflow
   * (handleUpdateWorkflow builds a fresh VersionedWorkflow from the body), so
   * a save must echo this object back with only the builder-owned keys
   * overridden — otherwise condition, timeout, on_failure, nested steps, loop,
   * switch, try, semaphore, lock, barrier and error_handling are deleted from
   * the stored workflow by an unrelated rename.
   */
  source: Record<string, unknown>
}

// Keys of a step that the builder authors itself; everything else in `source`
// is echoed back untouched.
const BUILDER_OWNED_STEP_KEYS = new Set(['id', 'name', 'type', 'config'])

/*
 * Step keys that stay meaningful when the operator changes the step type.
 * Everything else (child steps, loop/switch/try/semaphore/... blocks, module,
 * transport configs) describes the *old* type and is dropped on a type change,
 * which is an explicit operator act rather than a silent strip.
 */
const TYPE_AGNOSTIC_STEP_KEYS = new Set([
  'id', 'name', 'type', 'config', 'condition', 'timeout', 'on_failure',
  'variables', 'error_handling',
])

function retainTypeAgnostic(source: Record<string, unknown>): Record<string, unknown> {
  return Object.fromEntries(
    Object.entries(source).filter(([k]) => TYPE_AGNOSTIC_STEP_KEYS.has(k)),
  )
}

/*
 * Workflow-level fields that a save cannot carry: CreateWorkflowRequest
 * (features/controller/api/handlers_workflows.go) decodes only name,
 * description, version, steps, variables and timeout, so anything else stored
 * on the workflow is dropped by PUT no matter what the body contains. Rather
 * than silently deleting them, the Steps tab refuses to save such a workflow.
 */
const UNSAVEABLE_WORKFLOW_KEYS = [
  'on_failure', 'error_workflows', 'version_tags', 'deprecated',
  'deprecation_note', 'changelog',
] as const

function hasMeaningfulValue(value: unknown): boolean {
  if (value === undefined || value === null || value === false || value === '') return false
  if (Array.isArray(value)) return value.length > 0
  return true
}

function unsaveableFields(source: Record<string, unknown> | undefined): string[] {
  if (!source) return []
  return UNSAVEABLE_WORKFLOW_KEYS.filter((k) => hasMeaningfulValue(source[k]))
}

// ── Variable editor types ─────────────────────────────────────────────────────

interface VarRow {
  id: string
  key: string
  value: string
}

// ── Conversion helpers ────────────────────────────────────────────────────────

function stepToRow(step: WorkflowStep): StepRow {
  const cfg = step.config ?? {}
  const scriptBody = step.type === 'script' && typeof cfg.script === 'string' ? cfg.script : ''
  const hasExtra = step.type === 'script'
    ? Object.keys(cfg).some((k) => k !== 'script')
    : Object.keys(cfg).length > 0
  return {
    id: mkid(),
    name: step.name,
    type: step.type,
    scriptBody,
    configJson: hasExtra ? JSON.stringify(cfg, null, 2) : '{}',
    rawOpen: hasExtra,
    source: step.raw ?? {},
  }
}

function defaultStep(): StepRow {
  return {
    id: mkid(),
    name: 'step-1',
    type: 'script',
    scriptBody: '',
    configJson: '{}',
    rawOpen: false,
    source: {},
  }
}

// ── Step builder row component ────────────────────────────────────────────────

function StepBuilderRow({
  step,
  index,
  canRemove,
  onChange,
  onRemove,
}: {
  step: StepRow
  index: number
  canRemove: boolean
  onChange: (updated: StepRow) => void
  onRemove: () => void
}) {
  const isScriptType = step.type === 'script'
  const isKnownType = (STEP_TYPES as readonly string[]).includes(step.type)
  // Fields carried on this step that the builder does not render but does
  // round-trip on save — surfaced so the operator knows they still apply.
  const preserved = Object.keys(step.source)
    .filter((k) => !BUILDER_OWNED_STEP_KEYS.has(k))
    .sort()

  return (
    <div className="wf-step-row" data-testid="step-row">
      <div className="wf-form-row">
        <div className="wf-form-field">
          <span className="wf-form-label">Step {index + 1} name *</span>
          <input
            type="text"
            aria-label={`Step ${index + 1} name`}
            placeholder={`step-${index + 1}`}
            value={step.name}
            onChange={(e) => onChange({ ...step, name: e.target.value })}
            data-testid="step-name-input"
          />
        </div>
        <div className="wf-form-field">
          <span className="wf-form-label">Type</span>
          <select
            aria-label={`Step ${index + 1} type`}
            value={step.type}
            onChange={(e) =>
              onChange({
                ...step,
                type: e.target.value,
                scriptBody: '',
                configJson: '{}',
                rawOpen: false,
                source: retainTypeAgnostic(step.source),
              })
            }
            data-testid="step-type-select"
          >
            {STEP_TYPES.map((t) => (
              <option key={t} value={t}>{t}</option>
            ))}
            {!isKnownType && (
              <option value={step.type}>{step.type}</option>
            )}
          </select>
        </div>
        {isScriptType && (
          <div className="wf-form-field">
            <span className="wf-form-label">Script</span>
            <textarea
              aria-label={`Step ${index + 1} script`}
              placeholder="echo hello"
              value={step.scriptBody}
              onChange={(e) => onChange({ ...step, scriptBody: e.target.value })}
              data-testid="step-script-input"
            />
          </div>
        )}
        {!isScriptType && (
          <div className="wf-form-field">
            <span className="wf-form-label">Config (JSON)</span>
            <textarea
              aria-label={`Step ${index + 1} config JSON`}
              placeholder="{}"
              value={step.configJson}
              onChange={(e) => onChange({ ...step, configJson: e.target.value })}
              data-testid="step-config-json"
            />
          </div>
        )}
        {canRemove && (
          <button
            type="button"
            className="wf-btn-sm-danger wf-step-remove"
            onClick={onRemove}
            aria-label={`Remove step ${index + 1}`}
            data-testid="step-remove-btn"
          >
            Remove
          </button>
        )}
      </div>
      {isScriptType && (
        <details
          open={step.rawOpen}
          onToggle={(e) =>
            onChange({ ...step, rawOpen: (e.currentTarget as HTMLDetailsElement).open })
          }
          className="wf-raw-config"
        >
          <summary className="wf-raw-config-toggle">Raw config JSON</summary>
          <div className="wf-form-row" style={{ marginTop: 6 }}>
            <div className="wf-form-field">
              <textarea
                aria-label={`Step ${index + 1} raw config JSON`}
                placeholder="{}"
                value={step.configJson}
                onChange={(e) => onChange({ ...step, configJson: e.target.value })}
                data-testid="step-config-json"
              />
            </div>
          </div>
        </details>
      )}
      {preserved.length > 0 && (
        <p className="wf-step-preserved mut" data-testid="step-preserved-note">
          Preserved on save (not editable here): {preserved.join(', ')}
        </p>
      )}
    </div>
  )
}

// ── Variable key/value row component ─────────────────────────────────────────

function VarBuilderRow({
  varRow,
  onChange,
  onRemove,
}: {
  varRow: VarRow
  onChange: (updated: VarRow) => void
  onRemove: () => void
}) {
  return (
    <div className="wf-var-row wf-form-row" data-testid="var-row">
      <div className="wf-form-field">
        <span className="wf-form-label">Key</span>
        <input
          type="text"
          aria-label="Variable key"
          placeholder="var-name"
          value={varRow.key}
          onChange={(e) => onChange({ ...varRow, key: e.target.value })}
          data-testid="var-key-input"
        />
      </div>
      <div className="wf-form-field">
        <span className="wf-form-label">Value</span>
        <input
          type="text"
          aria-label="Variable value"
          placeholder="value"
          value={varRow.value}
          onChange={(e) => onChange({ ...varRow, value: e.target.value })}
          data-testid="var-value-input"
        />
      </div>
      <button
        type="button"
        className="wf-btn-sm-danger wf-var-remove"
        onClick={onRemove}
        aria-label="Remove variable"
        data-testid="var-remove-btn"
      >
        Remove
      </button>
    </div>
  )
}

// ── Steps pane (step builder + variable editor) ───────────────────────────────

function StepsPane({ workflow }: { workflow: VersionedWorkflow }) {
  const [steps, setSteps] = useState<StepRow[]>(() =>
    workflow.steps.length > 0 ? workflow.steps.map(stepToRow) : [defaultStep()],
  )
  const [variables, setVariables] = useState<VarRow[]>(() =>
    workflow.variables
      ? Object.entries(workflow.variables).map(([k, v]) => ({
          id: mkid(),
          key: k,
          value: typeof v === 'string' ? v : JSON.stringify(v),
        }))
      : [],
  )
  const [saving, setSaving] = useState(false)
  const [saveError, setSaveError] = useState<string | null>(null)
  const [saved, setSaved] = useState(false)
  const unsaveable = unsaveableFields(workflow.raw)

  function addStep() {
    const num = steps.length + 1
    setSteps((prev) => [
      ...prev,
      { id: mkid(), name: `step-${num}`, type: 'script', scriptBody: '', configJson: '{}', rawOpen: false },
    ])
  }

  function removeStep(idx: number) {
    setSteps((prev) => prev.filter((_, i) => i !== idx))
  }

  function updateStep(idx: number, updated: StepRow) {
    setSteps((prev) => prev.map((s, i) => (i === idx ? updated : s)))
  }

  function addVar() {
    setVariables((prev) => [...prev, { id: mkid(), key: '', value: '' }])
  }

  function removeVar(idx: number) {
    setVariables((prev) => prev.filter((_, i) => i !== idx))
  }

  function updateVar(idx: number, updated: VarRow) {
    setVariables((prev) => prev.map((v, i) => (i === idx ? updated : v)))
  }

  async function handleSave() {
    // steps is never empty: it is seeded with at least one row and the Remove
    // control is only rendered while more than one row exists.
    for (const s of steps) {
      if (!s.name.trim()) {
        setSaveError('All steps must have a name')
        return
      }
    }
    for (const s of steps) {
      if (s.rawOpen || s.type !== 'script') {
        try {
          JSON.parse(s.configJson || '{}')
        } catch {
          setSaveError(`Step "${s.name}": config must be valid JSON`)
          return
        }
      }
    }

    // Start from the step as the controller stored it and override only the
    // builder-owned keys, so gating and concurrency fields the builder does not
    // render (condition, timeout, on_failure, nested steps, loop, switch, try,
    // semaphore, lock, barrier, error_handling) survive the wholesale replace.
    const builtSteps = steps.map((s) => {
      let config: Record<string, unknown> = {}
      if (s.rawOpen || s.type !== 'script') {
        config = JSON.parse(s.configJson || '{}') as Record<string, unknown>
      } else if (s.scriptBody.trim()) {
        config = { script: s.scriptBody }
      }
      const built: Record<string, unknown> = { ...s.source, name: s.name.trim(), type: s.type }
      if (Object.keys(config).length > 0) {
        built.config = config
      } else {
        delete built.config
      }
      return built
    })

    const varEntries = variables.filter((v) => v.key.trim())
    const builtVars: Record<string, unknown> | undefined =
      varEntries.length > 0
        ? Object.fromEntries(varEntries.map((v) => [v.key.trim(), v.value]))
        : undefined

    setSaving(true)
    setSaveError(null)
    setSaved(false)

    try {
      const body: Record<string, unknown> = {
        name: workflow.name,
        description: workflow.description,
        version: workflow.version,
        steps: builtSteps,
      }
      if (builtVars !== undefined) body.variables = builtVars
      // The engine only applies a deadline when Timeout > 0
      // (features/workflow/engine.go), and PUT rebuilds the workflow from the
      // body — omitting it here would turn a bounded workflow into an
      // unbounded one.
      if (typeof workflow.timeout === 'number') body.timeout = workflow.timeout

      const response = await apiFetch(
        `/api/v1/workflows/${encodeURIComponent(workflow.name)}`,
        {
          method: 'PUT',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify(body),
        },
      )
      if (!response.ok) {
        const errBody = (await response.json().catch(() => ({}))) as Record<string, unknown>
        throw new Error((errBody?.error as string) || `Save failed — ${response.status}`)
      }
      setSaved(true)
    } catch (cause: unknown) {
      setSaveError(
        cause instanceof Error && cause.message ? cause.message : 'Save failed',
      )
    } finally {
      setSaving(false)
    }
  }

  return (
    <div data-testid="drawer-pane-steps">
      <div className="wf-builder-section">
        <div className="wf-builder-header">
          <span className="wf-form-label">Steps *</span>
          <button
            type="button"
            className="wf-btn-sm"
            onClick={addStep}
            data-testid="add-step-btn"
          >
            + Add step
          </button>
        </div>
        {steps.map((step, idx) => (
          <StepBuilderRow
            key={step.id}
            step={step}
            index={idx}
            canRemove={steps.length > 1}
            onChange={(updated) => updateStep(idx, updated)}
            onRemove={() => removeStep(idx)}
          />
        ))}
      </div>

      <div className="wf-builder-section">
        <div className="wf-builder-header">
          <span className="wf-form-label">Variables</span>
          <button
            type="button"
            className="wf-btn-sm"
            onClick={addVar}
            data-testid="add-var-btn"
          >
            + Add variable
          </button>
        </div>
        {variables.length === 0 && (
          <p className="wf-var-empty">No variables defined.</p>
        )}
        {variables.map((v, idx) => (
          <VarBuilderRow
            key={v.id}
            varRow={v}
            onChange={(updated) => updateVar(idx, updated)}
            onRemove={() => removeVar(idx)}
          />
        ))}
      </div>

      <div className="wf-form-actions">
        {unsaveable.length > 0 && (
          <span className="wf-form-error" data-testid="steps-save-blocked">
            Saving is disabled: this workflow declares {unsaveable.join(', ')}, which the
            workflow update API cannot carry — saving here would delete it.
          </span>
        )}
        {saveError && (
          <span className="wf-form-error" data-testid="steps-save-error">{saveError}</span>
        )}
        {saved && (
          <span className="mut" data-testid="steps-save-success">Saved.</span>
        )}
        <button
          type="button"
          className="wf-btn"
          onClick={handleSave}
          disabled={saving || unsaveable.length > 0}
          data-testid="steps-save-btn"
        >
          {saving ? 'Saving…' : 'Save steps'}
        </button>
      </div>
    </div>
  )
}

// ── Drawer helpers ────────────────────────────────────────────────────────────

function lastRunTone(status: string): string {
  switch (status) {
    case 'completed':
      return 'ok'
    case 'failed':
    case 'cancelled':
      return 'crit'
    case 'running':
    case 'pending':
    case 'paused':
      return 'warn'
    default:
      return 'neutral'
  }
}

function mostRecentExecution(
  executions: WorkflowExecution[],
): WorkflowExecution | null {
  return executions.reduce<WorkflowExecution | null>((latest, ex) => {
    if (!latest) return ex
    return Date.parse(ex.start_time) > Date.parse(latest.start_time) ? ex : latest
  }, null)
}

export default function WorkflowDrawer({ workflow, onClose }: WorkflowDrawerProps) {
  const [activeTab, setActiveTab] = useState<DrawerTab>('run')
  const { scope } = useTenantScope()
  // Every workflow in a single GET /api/v1/workflows response belongs to the
  // request's scoped tenant (workflowStoreForRequest), so the current scope
  // is the correct tenant path for any workflow in this list.
  const tenantPath = scope || 'root'
  const { executions } = useWorkflowExecutions(workflow.name)
  const lastRun = mostRecentExecution(executions)

  return (
    <aside
      className="drawer"
      data-testid="workflow-drawer"
      aria-label={`${workflow.name} details`}
    >
      <div className="dhead">
        <div className="top">
          <h2 data-testid="drawer-name">{workflow.name}</h2>
          <div className="acts">
            <button
              type="button"
              className="wf-btn-sm"
              data-testid="drawer-open-builder"
            >
              ⤢ Open builder
            </button>
            <button
              type="button"
              className="icobtn"
              aria-label="Close"
              onClick={onClose}
              data-testid="drawer-close"
            >
              ✕
            </button>
          </div>
        </div>
        <div className="meta" data-testid="drawer-meta">
          {workflow.version && <>v{workflow.version} · </>}
          <span data-testid="drawer-tenant-path">{tenantPath}</span>
          {' · '}
          <span
            className={`pill ${lastRun ? lastRunTone(lastRun.status) : 'neutral'}`}
            data-testid="drawer-last-run-pill"
          >
            <span className="dot" />
            {lastRun ? lastRun.status : 'Never run'}
          </span>
        </div>
      </div>

      <div className="dtabs" role="tablist" aria-label="Workflow details tabs">
        <button
          type="button"
          role="tab"
          aria-selected={activeTab === 'run'}
          className={activeTab === 'run' ? 'on' : ''}
          onClick={() => setActiveTab('run')}
          data-testid="drawer-tab-run"
        >
          Run
        </button>
        <button
          type="button"
          role="tab"
          aria-selected={activeTab === 'schedule'}
          className={activeTab === 'schedule' ? 'on' : ''}
          onClick={() => setActiveTab('schedule')}
          data-testid="drawer-tab-schedule"
        >
          Schedule
        </button>
        <button
          type="button"
          role="tab"
          aria-selected={activeTab === 'preview'}
          className={activeTab === 'preview' ? 'on' : ''}
          onClick={() => setActiveTab('preview')}
          data-testid="drawer-tab-preview"
        >
          What it does
        </button>
        <button
          type="button"
          role="tab"
          aria-selected={activeTab === 'steps'}
          className={activeTab === 'steps' ? 'on' : ''}
          onClick={() => setActiveTab('steps')}
          data-testid="drawer-tab-steps"
        >
          Steps
        </button>
      </div>

      <div className="dbody" role="tabpanel">
        {activeTab === 'run' && (
          <div data-testid="drawer-pane-run">
            <p className="mut">Run and execution history — coming in a later story.</p>
          </div>
        )}
        {activeTab === 'schedule' && (
          <div data-testid="drawer-pane-schedule">
            <p className="mut">Triggers and schedule — coming in a later story.</p>
          </div>
        )}
        {activeTab === 'preview' && (
          <div data-testid="drawer-pane-preview">
            <p className="mut">Workflow preview — coming in a later story.</p>
          </div>
        )}
        {activeTab === 'steps' && (
          <StepsPane workflow={workflow} />
        )}
      </div>
    </aside>
  )
}
