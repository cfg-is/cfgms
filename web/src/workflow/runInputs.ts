// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz

/*
 * Run-input helpers (Issue #4617): form state, payload building and the
 * execute call shared by the builder Run form and the drawer Run tab.
 *
 * The payload is built from the declared inputs only — a value the operator
 * never saw a control for can never be sent. The engine stays the authority
 * (features/workflow/inputs.go); the local checks only save a round trip.
 */
import { apiFetch } from '../api/client.ts'
import type { InputSpec } from './useWorkflows.ts'

export type InputValues = Record<string, string | boolean>
export type FieldErrors = Record<string, string>

export function initialValues(inputs: InputSpec[]): InputValues {
  const values: InputValues = {}
  for (const spec of inputs) {
    if (spec.type === 'bool') values[spec.name] = spec.default === true
    else values[spec.name] = typeof spec.default === 'string' ? spec.default : ''
  }
  return values
}

/* Typed payload of the declared inputs. Empty string/enum values are omitted so the engine applies the default. */
export function buildPayload(inputs: InputSpec[], values: InputValues): Record<string, string | boolean> {
  const payload: Record<string, string | boolean> = {}
  for (const spec of inputs) {
    const v = values[spec.name]
    if (spec.type === 'bool') payload[spec.name] = v === true
    else if (typeof v === 'string' && v !== '') payload[spec.name] = v
  }
  return payload
}

/* Immutable updates via Map, so a user-authored input name is never an object index. */
export function withValue(values: InputValues, name: string, value: string | boolean): InputValues {
  return Object.fromEntries(new Map(Object.entries(values)).set(name, value))
}

export function withoutError(errors: FieldErrors, name: string): FieldErrors {
  return Object.fromEntries(Object.entries(errors).filter(([k]) => k !== name))
}

export function requiredErrors(inputs: InputSpec[], values: InputValues): FieldErrors {
  const errors: FieldErrors = {}
  for (const spec of inputs) {
    const v = values[spec.name]
    if (spec.required && spec.type !== 'bool' && (typeof v !== 'string' || v.trim() === '')) {
      errors[spec.name] = 'This input is required'
    }
  }
  return errors
}

/* Why a set of input declarations cannot be saved, or null when it can. */
export function declarationProblem(inputs: InputSpec[]): string | null {
  const seen = new Set<string>()
  for (const spec of inputs) {
    const name = spec.name.trim()
    if (name === '') return 'Every input needs a name'
    if (seen.has(name)) return `Input "${name}" is declared more than once`
    seen.add(name)
    if (spec.type === 'enum' && (spec.options ?? []).length === 0) {
      return `Enum input "${name}" needs at least one option`
    }
  }
  return null
}

export class RunError extends Error {
  readonly fieldErrors: FieldErrors
  constructor(message: string, fieldErrors: FieldErrors = {}) {
    super(message)
    this.fieldErrors = fieldErrors
  }
}

/*
 * POST /api/v1/workflows/{name}/execute. A 400 carrying `fields` (the engine's
 * per-input errors) throws a RunError whose fieldErrors maps input name to
 * message; any other failure throws a RunError with no field errors.
 */
export async function startWorkflowRun(
  workflowName: string,
  inputs: Record<string, string | boolean>,
  variables: Record<string, string> = {},
): Promise<string | null> {
  const body: Record<string, unknown> = { variables }
  if (Object.keys(inputs).length > 0) body.inputs = inputs
  const response = await apiFetch(`/api/v1/workflows/${encodeURIComponent(workflowName)}/execute`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(body),
  })
  if (!response.ok) {
    const errBody = (await response.json().catch(() => ({}))) as Record<string, unknown>
    const fieldErrors: FieldErrors = {}
    if (Array.isArray(errBody.fields)) {
      for (const f of errBody.fields) {
        if (typeof f === 'object' && f !== null) {
          const r = f as Record<string, unknown>
          if (typeof r.field === 'string' && typeof r.message === 'string') fieldErrors[r.field] = r.message
        }
      }
    }
    const message = typeof errBody.error === 'string' && errBody.error ? errBody.error : `Run failed — ${response.status}`
    throw new RunError(message, fieldErrors)
  }
  const result = (await response.json()) as Record<string, unknown>
  return typeof result.execution_id === 'string' && result.execution_id ? result.execution_id : null
}
