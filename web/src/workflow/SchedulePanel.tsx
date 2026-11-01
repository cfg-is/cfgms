// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz

/*
 * SchedulePanel — the builder's "Schedule & inputs" drawer (Issue #4617).
 * Edits the workflow's typed input declarations (name, type, required,
 * default, options) and embeds TriggerPanel filtered to the workflow.
 * Declarations are held by the builder and written by its Save.
 *
 * Security A9.1: every value is a controlled input or JSX text.
 */
import { useRef, useState } from 'react'
import TriggerPanel from './TriggerPanel.tsx'
import type { InputSpec, InputType } from './useWorkflows.ts'

interface SchedulePanelProps {
  inputs: InputSpec[]
  onInputsChange: (inputs: InputSpec[]) => void
  /** Saved workflow name; null for an unsaved new workflow (triggers need one). */
  workflowName: string | null
  onClose: () => void
}

interface Row {
  id: number
  spec: InputSpec
  optionsText: string
}

function InputRow({
  row,
  onChange,
  onRemove,
}: {
  row: Row
  onChange: (next: Row) => void
  onRemove: () => void
}) {
  const { spec } = row
  const idx = row.id
  function patch(p: Partial<InputSpec>) {
    const next: InputSpec = { ...spec, ...p }
    if (next.required !== true) delete next.required
    if (next.default === undefined || next.default === '') delete next.default
    if (next.description === '') delete next.description
    onChange({ ...row, spec: next })
  }
  function setType(type: InputType) {
    const next: InputSpec = { ...spec, type }
    delete next.default
    if (type !== 'enum') delete next.options
    onChange({ ...row, spec: next, optionsText: type === 'enum' ? row.optionsText : '' })
  }
  function setOptions(text: string) {
    const options = text.split(',').map((o) => o.trim()).filter((o) => o !== '')
    const next: InputSpec = { ...spec, options }
    if (typeof next.default === 'string' && !options.includes(next.default)) delete next.default
    onChange({ ...row, spec: next, optionsText: text })
  }
  return (
    <div className="wf-decl-row" data-testid="input-row">
      <input
        type="text"
        placeholder="name"
        aria-label={`Input name ${idx}`}
        value={spec.name}
        onChange={(e) => patch({ name: e.target.value })}
        data-testid="input-name"
      />
      <select
        aria-label={`Input type ${idx}`}
        value={spec.type}
        onChange={(e) => setType(e.target.value as InputType)}
        data-testid="input-type"
      >
        <option value="string">string</option>
        <option value="enum">enum</option>
        <option value="bool">bool</option>
      </select>
      <label className="mut">
        <input
          type="checkbox"
          checked={spec.required === true}
          onChange={(e) => patch({ required: e.target.checked })}
          data-testid="input-required"
        />{' '}
        required
      </label>
      {spec.type === 'enum' && (
        <input
          type="text"
          placeholder="options, comma separated"
          aria-label={`Input options ${idx}`}
          value={row.optionsText}
          onChange={(e) => setOptions(e.target.value)}
          data-testid="input-options"
        />
      )}
      {spec.type === 'string' && (
        <input
          type="text"
          placeholder="default"
          aria-label={`Input default ${idx}`}
          value={typeof spec.default === 'string' ? spec.default : ''}
          onChange={(e) => patch({ default: e.target.value })}
          data-testid="input-default"
        />
      )}
      {spec.type === 'enum' && (
        <select
          aria-label={`Input default ${idx}`}
          value={typeof spec.default === 'string' ? spec.default : ''}
          onChange={(e) => patch({ default: e.target.value })}
          data-testid="input-default"
        >
          <option value="">(no default)</option>
          {(spec.options ?? []).map((o) => (
            <option key={o} value={o}>{o}</option>
          ))}
        </select>
      )}
      {spec.type === 'bool' && (
        <select
          aria-label={`Input default ${idx}`}
          value={spec.default === true ? 'true' : spec.default === false ? 'false' : ''}
          onChange={(e) => {
            const v = e.target.value
            const next: InputSpec = { ...spec }
            if (v === '') delete next.default
            else next.default = v === 'true'
            onChange({ ...row, spec: next })
          }}
          data-testid="input-default"
        >
          <option value="">(no default)</option>
          <option value="true">true</option>
          <option value="false">false</option>
        </select>
      )}
      <input
        type="text"
        placeholder="description"
        aria-label={`Input description ${idx}`}
        value={spec.description ?? ''}
        onChange={(e) => patch({ description: e.target.value })}
      />
      <button
        type="button"
        className="wf-btn-sm-danger"
        aria-label={`Remove input ${idx}`}
        onClick={onRemove}
        data-testid="input-remove"
      >
        ✕
      </button>
    </div>
  )
}

export default function SchedulePanel({ inputs, onInputsChange, workflowName, onClose }: SchedulePanelProps) {
  const nextId = useRef(inputs.length)
  const [rows, setRows] = useState<Row[]>(() =>
    inputs.map((spec, i) => ({ id: i, spec, optionsText: (spec.options ?? []).join(', ') })),
  )

  function commit(next: Row[]) {
    setRows(next)
    onInputsChange(next.map((r) => r.spec))
  }

  return (
    <div className="wf-schedule-panel" data-testid="schedule-panel">
      <section>
        <div className="wf-trigger-header">
          <h3>Inputs</h3>
          <button
            type="button"
            className="wf-btn-sm"
            onClick={() =>
              commit([...rows, { id: nextId.current++, spec: { name: '', type: 'string' }, optionsText: '' }])
            }
            data-testid="add-input"
          >
            + Add input
          </button>
        </div>
        {rows.length === 0 ? (
          <div className="notice empty" data-testid="inputs-empty">
            <p>No inputs declared. A run takes no parameters.</p>
          </div>
        ) : (
          rows.map((row) => (
            <InputRow
              key={row.id}
              row={row}
              onChange={(next) => commit(rows.map((r) => (r.id === row.id ? next : r)))}
              onRemove={() => commit(rows.filter((r) => r.id !== row.id))}
            />
          ))
        )}
      </section>
      <section>
        {workflowName === null ? (
          <div className="notice empty" data-testid="triggers-need-save">
            <p>Save the workflow before adding triggers.</p>
          </div>
        ) : (
          <TriggerPanel onClose={onClose} workflowName={workflowName} />
        )}
      </section>
    </div>
  )
}
