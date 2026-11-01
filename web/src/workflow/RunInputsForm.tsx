// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz

/*
 * RunInputsForm — renders a workflow's declared inputs for a run (Issue #4617).
 * Controlled: the parent owns values and field errors (local required checks
 * and the server's 400 `fields`), so the builder Run form and the drawer Run
 * tab share one rendering.
 *
 * Security A9.1: names, descriptions, options and error messages are
 * workflow-author or controller text; they reach the DOM as JSX text only.
 */
import type { InputSpec } from './useWorkflows.ts'
import type { FieldErrors, InputValues } from './runInputs.ts'

interface RunInputsFormProps {
  inputs: InputSpec[]
  values: InputValues
  errors: FieldErrors
  onChange: (name: string, value: string | boolean) => void
}

export default function RunInputsForm({ inputs, values, errors, onChange }: RunInputsFormProps) {
  if (inputs.length === 0) return null
  return (
    <div className="wf-run-inputs" data-testid="run-inputs-form">
      {inputs.map((spec) => {
        const id = `run-input-${spec.name}`
        const error = Object.prototype.hasOwnProperty.call(errors, spec.name) ? errors[spec.name] : undefined
        const value = values[spec.name]
        return (
          <div className="wf-run-input" key={spec.name} data-testid={`run-input-${spec.name}`}>
            <label className="wf-form-label" htmlFor={id}>
              {spec.name}
              {spec.required && (
                <span className="wf-required" aria-hidden="true" data-testid={`run-input-required-${spec.name}`}> *</span>
              )}
            </label>
            {spec.type === 'bool' ? (
              <input
                id={id}
                type="checkbox"
                checked={value === true}
                onChange={(e) => onChange(spec.name, e.target.checked)}
                aria-invalid={error !== undefined}
              />
            ) : spec.type === 'enum' ? (
              <select
                id={id}
                value={typeof value === 'string' ? value : ''}
                required={spec.required}
                onChange={(e) => onChange(spec.name, e.target.value)}
                aria-invalid={error !== undefined}
              >
                <option value="">{spec.required ? 'Select…' : '(default)'}</option>
                {(spec.options ?? []).map((o) => (
                  <option key={o} value={o}>{o}</option>
                ))}
              </select>
            ) : (
              <input
                id={id}
                type="text"
                value={typeof value === 'string' ? value : ''}
                required={spec.required}
                onChange={(e) => onChange(spec.name, e.target.value)}
                aria-invalid={error !== undefined}
              />
            )}
            {spec.description && <span className="mut">{spec.description}</span>}
            {error !== undefined && (
              <span className="wf-form-error" role="alert" data-testid={`run-input-error-${spec.name}`}>{error}</span>
            )}
          </div>
        )
      })}
    </div>
  )
}
