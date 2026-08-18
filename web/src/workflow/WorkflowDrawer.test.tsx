// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz

/*
 * WorkflowDrawer test suite (Stories #3039, #3213): drawer renders correctly,
 * tabs switch visible pane, close button fires onClose, the last-run status
 * pill reflects the most recent execution, user content is rendered as safe
 * text nodes (Security A9.1), and the Steps tab hosts the structured step
 * type selector and variable row editor (Story #3213).
 */
import { beforeEach, describe, expect, it, vi } from 'vitest'
import { cleanup, fireEvent, render, screen, waitFor } from '@testing-library/react'
import { afterEach } from 'vitest'
import WorkflowDrawer from './WorkflowDrawer.tsx'
import type { VersionedWorkflow } from './useWorkflows.ts'
import { parseVersionedWorkflow } from './useWorkflows.ts'
import { TenantScopeProvider } from '../shell/TenantScopeContext.tsx'

/*
 * Test transport (no CFGMS component is substituted).
 *
 * jsdom has no network, so the browser's fetch boundary is replaced with a
 * router that speaks the same HTTP contract as
 * features/controller/api/handlers_workflows.go: it validates a PUT the way
 * handleUpdateWorkflow does (400 {"error": ...} on an empty step list or an
 * unparseable version), then stores the submitted workflow and serves it back.
 * State is real — a PUT changes what a following GET returns. Everything on the
 * app side (WorkflowDrawer, useWorkflowExecutions, apiFetch) is the real
 * implementation exercised end to end against that transport.
 */

function jsonResponse(status: number, body: unknown): Response {
  return new Response(JSON.stringify(body), {
    status,
    headers: { 'Content-Type': 'application/json' },
  })
}

const SEMVER = /^(\d+)\.(\d+)\.(\d+)(?:-([0-9A-Za-z.-]+))?(?:\+([0-9A-Za-z.-]+))?$/

interface WorkflowApi {
  executions: Record<string, unknown>[]
  stored: Record<string, unknown> | null
  puts: Record<string, unknown>[]
  offline: boolean
  storeFails: boolean
  handle: typeof fetch
}

function createWorkflowApi(): WorkflowApi {
  function route(input: RequestInfo | URL, init?: RequestInit): Promise<Response> {
    if (api.offline) {
      // Browser-level transport failure, not a controller response.
      return Promise.reject(new TypeError('Failed to fetch'))
    }
    const url =
      typeof input === 'string' ? input : input instanceof URL ? input.href : input.url
    const method = (init?.method ?? 'GET').toUpperCase()

    if (method === 'GET' && /\/api\/v1\/workflows\/[^/]+\/executions$/.test(url)) {
      return Promise.resolve(
        jsonResponse(200, { executions: api.executions, count: api.executions.length }),
      )
    }
    if (method === 'PUT' && /\/api\/v1\/workflows\/[^/]+$/.test(url)) {
      return Promise.resolve(updateWorkflow(api, url, init))
    }
    return Promise.resolve(jsonResponse(404, { error: `no route for ${method} ${url}` }))
  }

  const api: WorkflowApi = {
    executions: [],
    stored: null,
    puts: [],
    offline: false,
    storeFails: false,
    handle: route as typeof fetch,
  }
  return api
}

// Mirrors handleUpdateWorkflow: decode, validate, store, echo the stored form.
function updateWorkflow(
  api: WorkflowApi,
  url: string,
  init?: RequestInit,
): Response {
  let body: Record<string, unknown>
  try {
    body = JSON.parse((init?.body as string) ?? '') as Record<string, unknown>
  } catch {
    return jsonResponse(400, { error: 'invalid JSON payload' })
  }
  api.puts.push(body)

  const name = decodeURIComponent(url.slice(url.lastIndexOf('/') + 1))
  const steps = body.steps
  if (!Array.isArray(steps) || steps.length === 0) {
    return jsonResponse(400, { error: 'workflow must have at least one step' })
  }
  const version = typeof body.version === 'string' && body.version ? body.version : '1.0.0'
  const match = SEMVER.exec(version)
  if (match === null) {
    return jsonResponse(400, {
      error: `invalid version format: invalid semantic version: ${version}`,
    })
  }
  if (api.storeFails) {
    return jsonResponse(500, { error: 'failed to update workflow' })
  }
  api.stored = {
    ...body,
    name,
    version,
    semantic_version: {
      major: Number(match[1]),
      minor: Number(match[2]),
      patch: Number(match[3]),
      pre_release: match[4] ?? '',
      build_meta: match[5] ?? '',
    },
  }
  return jsonResponse(200, api.stored)
}

let api: WorkflowApi

function makeExecution(overrides: Partial<Record<string, unknown>> = {}) {
  return {
    id: 'exec-1',
    workflow_name: 'onboard-user',
    status: 'completed',
    start_time: '2026-01-01T00:00:00Z',
    ...overrides,
  }
}

beforeEach(() => {
  api = createWorkflowApi()
  vi.stubGlobal('fetch', api.handle)
})

afterEach(() => {
  vi.unstubAllGlobals()
  cleanup()
})

/*
 * Fixtures go through the real parseVersionedWorkflow so a test workflow has
 * exactly the shape the drawer sees in production — including the verbatim
 * `raw` JSON the save path round-trips.
 */
function workflowFromApi(overrides: Record<string, unknown> = {}): VersionedWorkflow {
  const parsed = parseVersionedWorkflow({
    name: 'onboard-user',
    description: 'Create a user on the DC',
    version: '1.5.0',
    steps: [{ id: 'step-1', name: 'step-1', type: 'script' }],
    semantic_version: { major: 1, minor: 5, patch: 0, pre_release: '', build_meta: '' },
    ...overrides,
  })
  if (parsed === null) throw new Error('fixture did not parse as a workflow')
  return parsed
}

function makeWorkflow(overrides: Partial<VersionedWorkflow> = {}): VersionedWorkflow {
  return { ...workflowFromApi(), ...overrides }
}

/** The single PUT body the drawer sent; fails the test if there was not exactly one. */
function onlyPut(): Record<string, unknown> {
  expect(api.puts).toHaveLength(1)
  return api.puts[0]!
}

function putSteps(body: Record<string, unknown>): Record<string, unknown>[] {
  return body.steps as Record<string, unknown>[]
}

function renderDrawer(
  workflow = makeWorkflow(),
  onClose = vi.fn(),
  rootPath = 'root/msp-a/client-1',
) {
  return render(
    <TenantScopeProvider rootPath={rootPath}>
      <WorkflowDrawer workflow={workflow} onClose={onClose} />
    </TenantScopeProvider>,
  )
}

describe('WorkflowDrawer — header', () => {
  it('renders the drawer with the workflow name in the header', () => {
    renderDrawer()
    expect(screen.getByTestId('workflow-drawer')).toBeInTheDocument()
    expect(screen.getByTestId('drawer-name')).toHaveTextContent('onboard-user')
  })

  it('shows the version in the meta line', () => {
    renderDrawer()
    expect(screen.getByTestId('drawer-meta')).toHaveTextContent('v1.5.0')
  })

  it('shows the current tenant scope path in the meta line', () => {
    renderDrawer(makeWorkflow(), vi.fn(), 'root/msp-a/client-1')
    expect(screen.getByTestId('drawer-tenant-path')).toHaveTextContent(
      'root/msp-a/client-1',
    )
  })

  it('falls back to "root" for an empty (unnarrowed) tenant scope', () => {
    renderDrawer(makeWorkflow(), vi.fn(), '')
    expect(screen.getByTestId('drawer-tenant-path')).toHaveTextContent('root')
  })

  it('renders "Open builder" affordance as a stub button', () => {
    renderDrawer()
    expect(screen.getByTestId('drawer-open-builder')).toBeInTheDocument()
  })

  it('close button calls onClose', () => {
    const onClose = vi.fn()
    renderDrawer(makeWorkflow(), onClose)
    fireEvent.click(screen.getByTestId('drawer-close'))
    expect(onClose).toHaveBeenCalledTimes(1)
  })
})

describe('WorkflowDrawer — tab bar', () => {
  it('renders Run, Schedule, and What-it-does tabs', () => {
    renderDrawer()
    expect(screen.getByTestId('drawer-tab-run')).toBeInTheDocument()
    expect(screen.getByTestId('drawer-tab-schedule')).toBeInTheDocument()
    expect(screen.getByTestId('drawer-tab-preview')).toBeInTheDocument()
    expect(screen.getByTestId('drawer-tab-preview')).toHaveTextContent(/what it does/i)
  })

  it('Run tab is active by default', () => {
    renderDrawer()
    expect(screen.getByTestId('drawer-tab-run')).toHaveClass('on')
    expect(screen.getByTestId('drawer-tab-schedule')).not.toHaveClass('on')
    expect(screen.getByTestId('drawer-tab-preview')).not.toHaveClass('on')
    expect(screen.getByTestId('drawer-pane-run')).toBeInTheDocument()
  })

  it('clicking Schedule tab activates it and shows the schedule pane', () => {
    renderDrawer()
    fireEvent.click(screen.getByTestId('drawer-tab-schedule'))
    expect(screen.getByTestId('drawer-tab-schedule')).toHaveClass('on')
    expect(screen.getByTestId('drawer-tab-run')).not.toHaveClass('on')
    expect(screen.getByTestId('drawer-pane-schedule')).toBeInTheDocument()
    expect(screen.queryByTestId('drawer-pane-run')).toBeNull()
  })

  it('clicking Preview tab activates it and shows the preview pane', () => {
    renderDrawer()
    fireEvent.click(screen.getByTestId('drawer-tab-preview'))
    expect(screen.getByTestId('drawer-tab-preview')).toHaveClass('on')
    expect(screen.getByTestId('drawer-pane-preview')).toBeInTheDocument()
    expect(screen.queryByTestId('drawer-pane-run')).toBeNull()
    expect(screen.queryByTestId('drawer-pane-schedule')).toBeNull()
  })

  it('switching back to Run tab from another tab shows the run pane', () => {
    renderDrawer()
    fireEvent.click(screen.getByTestId('drawer-tab-schedule'))
    fireEvent.click(screen.getByTestId('drawer-tab-run'))
    expect(screen.getByTestId('drawer-tab-run')).toHaveClass('on')
    expect(screen.getByTestId('drawer-pane-run')).toBeInTheDocument()
    expect(screen.queryByTestId('drawer-pane-schedule')).toBeNull()
  })
})

describe('WorkflowDrawer — last-run status pill', () => {
  it('shows a neutral "Never run" pill when the workflow has no executions', async () => {
    api.executions = []
    renderDrawer()
    const pill = await screen.findByTestId('drawer-last-run-pill')
    expect(pill).toHaveClass('pill', 'neutral')
    expect(pill).toHaveTextContent('Never run')
  })

  it('shows the most recent execution status, chosen by start_time not array order', async () => {
    api.executions = [
      makeExecution({
        id: 'exec-newer',
        status: 'completed',
        start_time: '2026-01-03T00:00:00Z',
      }),
      makeExecution({
        id: 'exec-older',
        status: 'failed',
        start_time: '2026-01-01T00:00:00Z',
      }),
    ]
    renderDrawer()
    const pill = await screen.findByTestId('drawer-last-run-pill')
    expect(pill).toHaveClass('pill', 'ok')
    expect(pill).toHaveTextContent('completed')
  })

  it('maps a failed last run to the crit tone', async () => {
    api.executions = [
      makeExecution({ status: 'failed', start_time: '2026-01-01T00:00:00Z' }),
    ]
    renderDrawer()
    const pill = await screen.findByTestId('drawer-last-run-pill')
    expect(pill).toHaveClass('pill', 'crit')
    expect(pill).toHaveTextContent('failed')
  })
})

describe('WorkflowDrawer — security (A9.1)', () => {
  it('renders workflow name as a text node, not HTML', () => {
    const xss = '<img src=x onerror="window.__xss_drawer=1">'
    renderDrawer(makeWorkflow({ name: xss }))
    expect(screen.getByTestId('drawer-name')).toHaveTextContent(xss)
    expect((window as unknown as Record<string, unknown>).__xss_drawer).toBeUndefined()
  })
})

// ── Story #3213: Steps tab — structured step authoring ────────────────────────

function openStepsTab(workflow = makeWorkflow()) {
  renderDrawer(workflow)
  fireEvent.click(screen.getByTestId('drawer-tab-steps'))
  expect(screen.getByTestId('drawer-pane-steps')).toBeInTheDocument()
}

describe('WorkflowDrawer — Steps tab (Story #3213)', () => {
  it('renders the Steps tab button', () => {
    renderDrawer()
    expect(screen.getByTestId('drawer-tab-steps')).toBeInTheDocument()
  })

  it('clicking the Steps tab shows the steps pane and hides run pane', () => {
    renderDrawer()
    fireEvent.click(screen.getByTestId('drawer-tab-steps'))
    expect(screen.getByTestId('drawer-pane-steps')).toBeInTheDocument()
    expect(screen.queryByTestId('drawer-pane-run')).toBeNull()
  })

  it('renders step type selector and variable editor', () => {
    openStepsTab()
    // Step-type selector is present
    expect(screen.getByTestId('step-type-select')).toBeInTheDocument()
    // Add variable button is present and adds a row with a readable value
    fireEvent.click(screen.getByTestId('add-var-btn'))
    const valueInput = screen.getByTestId('var-value-input') as HTMLInputElement
    fireEvent.change(valueInput, { target: { value: 'hello' } })
    expect(valueInput.value).toBe('hello')
  })

  it('pre-populates step rows from the workflow prop', () => {
    const wf = makeWorkflow({
      steps: [
        { id: 's1', name: 'run-task', type: 'script', config: { script: 'echo hi' } },
        { id: 's2', name: 'notify', type: 'notification', config: {} },
      ],
    })
    openStepsTab(wf)
    const nameInputs = screen.getAllByTestId('step-name-input') as HTMLInputElement[]
    expect(nameInputs).toHaveLength(2)
    expect(nameInputs[0]!.value).toBe('run-task')
    expect(nameInputs[1]!.value).toBe('notify')
  })

  it('pre-populates script body from config.script for script steps', () => {
    const wf = makeWorkflow({
      steps: [{ id: 's1', name: 'run', type: 'script', config: { script: 'echo hello' } }],
    })
    openStepsTab(wf)
    const scriptInput = screen.getByTestId('step-script-input') as HTMLTextAreaElement
    expect(scriptInput.value).toBe('echo hello')
  })

  it('pre-populates variable rows from the workflow prop', () => {
    const wf = makeWorkflow({ variables: { ENV: 'production', TIMEOUT: '30' } })
    openStepsTab(wf)
    const keyInputs = screen.getAllByTestId('var-key-input') as HTMLInputElement[]
    const valInputs = screen.getAllByTestId('var-value-input') as HTMLInputElement[]
    expect(keyInputs).toHaveLength(2)
    const pairs = keyInputs.map((k, i) => `${k.value}=${valInputs.at(i)?.value ?? ''}`)
    expect(pairs).toContain('ENV=production')
    expect(pairs).toContain('TIMEOUT=30')
  })

  it('step type selector is a constrained control — not a free-text field', () => {
    openStepsTab()
    const select = screen.getByTestId('step-type-select')
    expect(select.tagName.toLowerCase()).toBe('select')
  })

  it('Add step button appends a new step row', () => {
    openStepsTab()
    expect(screen.getAllByTestId('step-row')).toHaveLength(1)
    fireEvent.click(screen.getByTestId('add-step-btn'))
    expect(screen.getAllByTestId('step-row')).toHaveLength(2)
  })

  it('Remove step button removes that row (only shown when >1 step)', () => {
    openStepsTab()
    expect(screen.queryByTestId('step-remove-btn')).toBeNull()
    fireEvent.click(screen.getByTestId('add-step-btn'))
    expect(screen.getAllByTestId('step-remove-btn')).toHaveLength(2)
    fireEvent.click(screen.getAllByTestId('step-remove-btn')[0]!)
    expect(screen.getAllByTestId('step-row')).toHaveLength(1)
  })

  it('Add variable button adds a key/value row', () => {
    openStepsTab()
    expect(screen.queryByTestId('var-row')).toBeNull()
    fireEvent.click(screen.getByTestId('add-var-btn'))
    expect(screen.getAllByTestId('var-row')).toHaveLength(1)
    expect(screen.getByTestId('var-key-input')).toBeInTheDocument()
    expect(screen.getByTestId('var-value-input')).toBeInTheDocument()
  })

  it('Remove variable button removes that row', () => {
    openStepsTab()
    fireEvent.click(screen.getByTestId('add-var-btn'))
    expect(screen.getAllByTestId('var-row')).toHaveLength(1)
    fireEvent.click(screen.getByTestId('var-remove-btn'))
    expect(screen.queryByTestId('var-row')).toBeNull()
  })

  it('saves updated steps and variables via PUT and shows success state', async () => {
    openStepsTab(workflowFromApi())

    fireEvent.change(screen.getByTestId('step-name-input'), {
      target: { value: 'renamed-step' },
    })
    fireEvent.click(screen.getByTestId('add-var-btn'))
    fireEvent.change(screen.getByTestId('var-key-input'), { target: { value: 'FOO' } })
    fireEvent.change(screen.getByTestId('var-value-input'), { target: { value: 'bar' } })

    fireEvent.click(screen.getByTestId('steps-save-btn'))

    expect(await screen.findByTestId('steps-save-success')).toBeInTheDocument()
    expect(screen.queryByTestId('steps-save-error')).toBeNull()
    expect(onlyPut()).toMatchObject({
      name: 'onboard-user',
      version: '1.5.0',
      steps: [{ name: 'renamed-step', type: 'script' }],
      variables: { FOO: 'bar' },
    })
    // The endpoint stored what was sent — a following read sees the rename.
    expect(putSteps(api.stored as Record<string, unknown>)[0]).toMatchObject({
      name: 'renamed-step',
    })
  })
})

// ── Save: destructive-write protection (security review of Story #3213) ───────

describe('WorkflowDrawer — Steps tab save preserves unmodeled workflow content', () => {
  it('round-trips per-step gating and concurrency fields the builder does not render', async () => {
    const wf = workflowFromApi({
      steps: [
        {
          id: 's0',
          name: 'gated-step',
          type: 'conditional',
          config: {},
          condition: { expression: 'vars.env == "prod"' },
          timeout: 30000000000,
          on_failure: 'stop',
          semaphore: { name: 'patch-window', limit: 25 },
          lock: { name: 'dc-lock' },
          error_handling: { retry: { max_attempts: 3 } },
          steps: [{ id: 's0.s0', name: 'child', type: 'script', config: { script: 'echo hi' } }],
        },
      ],
    })
    openStepsTab(wf)

    fireEvent.change(screen.getByTestId('step-name-input'), {
      target: { value: 'gated-step-renamed' },
    })
    fireEvent.click(screen.getByTestId('steps-save-btn'))
    await screen.findByTestId('steps-save-success')

    const sent = putSteps(onlyPut())[0]!
    expect(sent).toMatchObject({
      name: 'gated-step-renamed',
      type: 'conditional',
      condition: { expression: 'vars.env == "prod"' },
      timeout: 30000000000,
      on_failure: 'stop',
      semaphore: { name: 'patch-window', limit: 25 },
      lock: { name: 'dc-lock' },
      error_handling: { retry: { max_attempts: 3 } },
      steps: [{ name: 'child', type: 'script', config: { script: 'echo hi' } }],
    })
  })

  it('names the preserved fields in the step row so the operator can see them', () => {
    openStepsTab(
      workflowFromApi({
        steps: [
          {
            id: 's0',
            name: 'gated-step',
            type: 'script',
            condition: { expression: 'true' },
            semaphore: { name: 'patch-window', limit: 5 },
          },
        ],
      }),
    )
    expect(screen.getByTestId('step-preserved-note')).toHaveTextContent(
      'condition, semaphore',
    )
  })

  it('shows no preserved-fields note for a step with nothing beyond name/type/config', () => {
    openStepsTab(workflowFromApi())
    expect(screen.queryByTestId('step-preserved-note')).toBeNull()
  })

  it('sends the workflow timeout unchanged so a bounded workflow stays bounded', async () => {
    openStepsTab(workflowFromApi({ timeout: 900000000000 }))
    fireEvent.click(screen.getByTestId('steps-save-btn'))
    await screen.findByTestId('steps-save-success')
    expect(onlyPut().timeout).toBe(900000000000)
  })

  it('omits timeout entirely for a workflow that never had one', async () => {
    openStepsTab(workflowFromApi())
    fireEvent.click(screen.getByTestId('steps-save-btn'))
    await screen.findByTestId('steps-save-success')
    expect(Object.keys(onlyPut())).not.toContain('timeout')
  })

  it('drops type-specific fields when the operator changes a step type, keeping gating', async () => {
    openStepsTab(
      workflowFromApi({
        steps: [
          {
            id: 's0',
            name: 'branch',
            type: 'conditional',
            condition: { expression: 'true' },
            steps: [{ id: 's0.s0', name: 'child', type: 'script' }],
          },
        ],
      }),
    )
    fireEvent.change(screen.getByTestId('step-type-select'), { target: { value: 'script' } })
    fireEvent.click(screen.getByTestId('steps-save-btn'))
    await screen.findByTestId('steps-save-success')

    const sent = putSteps(onlyPut())[0]!
    expect(sent.type).toBe('script')
    expect(sent.condition).toEqual({ expression: 'true' })
    expect(sent.steps).toBeUndefined()
  })

  it('disables save for a workflow whose stored fields the update API cannot carry', () => {
    openStepsTab(workflowFromApi({ on_failure: 'rollback' }))
    expect(screen.getByTestId('steps-save-blocked')).toHaveTextContent('on_failure')
    expect(screen.getByTestId('steps-save-btn')).toBeDisabled()
    fireEvent.click(screen.getByTestId('steps-save-btn'))
    expect(api.puts).toHaveLength(0)
  })

  it('leaves save enabled for a workflow with no unsaveable fields', () => {
    openStepsTab(workflowFromApi())
    expect(screen.queryByTestId('steps-save-blocked')).toBeNull()
    expect(screen.getByTestId('steps-save-btn')).toBeEnabled()
  })
})

// ── Save: error paths ─────────────────────────────────────────────────────────

describe('WorkflowDrawer — Steps tab save error paths', () => {
  it('refuses to save a blank step name and issues no request', async () => {
    openStepsTab(workflowFromApi())
    fireEvent.change(screen.getByTestId('step-name-input'), { target: { value: '   ' } })
    fireEvent.click(screen.getByTestId('steps-save-btn'))

    expect(await screen.findByTestId('steps-save-error')).toHaveTextContent(
      'All steps must have a name',
    )
    expect(api.puts).toHaveLength(0)
    expect(screen.queryByTestId('steps-save-success')).toBeNull()
  })

  it('refuses to save an unparseable step config and names the offending step', async () => {
    openStepsTab(
      workflowFromApi({
        steps: [{ id: 's0', name: 'call-api', type: 'http', config: { url: 'https://x' } }],
      }),
    )
    fireEvent.change(screen.getByTestId('step-config-json'), {
      target: { value: '{ not json' },
    })
    fireEvent.click(screen.getByTestId('steps-save-btn'))

    expect(await screen.findByTestId('steps-save-error')).toHaveTextContent(
      'Step "call-api": config must be valid JSON',
    )
    expect(api.puts).toHaveLength(0)
  })

  it('refuses to save unparseable raw config on a script step', async () => {
    openStepsTab(
      workflowFromApi({
        steps: [
          { id: 's0', name: 'run', type: 'script', config: { script: 'echo hi', shell: 'bash' } },
        ],
      }),
    )
    // config carries a key beyond `script`, so the raw panel is open and owns the config
    fireEvent.change(screen.getByTestId('step-config-json'), { target: { value: '[' } })
    fireEvent.click(screen.getByTestId('steps-save-btn'))

    expect(await screen.findByTestId('steps-save-error')).toHaveTextContent(
      'config must be valid JSON',
    )
    expect(api.puts).toHaveLength(0)
  })

  it('surfaces the controller error message when the endpoint rejects the save', async () => {
    // The stored version is not semver, so handleUpdateWorkflow answers 400.
    openStepsTab(workflowFromApi({ version: 'not-a-semver' }))
    fireEvent.click(screen.getByTestId('steps-save-btn'))

    expect(await screen.findByTestId('steps-save-error')).toHaveTextContent(
      'invalid version format',
    )
    expect(api.puts).toHaveLength(1)
    expect(api.stored).toBeNull()
    expect(screen.queryByTestId('steps-save-success')).toBeNull()
  })

  it('surfaces a server-side store failure without claiming success', async () => {
    api.storeFails = true
    openStepsTab(workflowFromApi())
    fireEvent.click(screen.getByTestId('steps-save-btn'))

    expect(await screen.findByTestId('steps-save-error')).toHaveTextContent(
      'failed to update workflow',
    )
    expect(api.stored).toBeNull()
  })

  it('reports a network failure instead of silently doing nothing', async () => {
    openStepsTab(workflowFromApi())
    api.offline = true
    fireEvent.click(screen.getByTestId('steps-save-btn'))

    expect(await screen.findByTestId('steps-save-error')).toHaveTextContent(/failed to fetch/i)
    expect(screen.queryByTestId('steps-save-success')).toBeNull()
  })

  it('re-enables the save button after a failed save so the operator can retry', async () => {
    api.storeFails = true
    openStepsTab(workflowFromApi())
    fireEvent.click(screen.getByTestId('steps-save-btn'))
    await screen.findByTestId('steps-save-error')
    expect(screen.getByTestId('steps-save-btn')).toBeEnabled()

    api.storeFails = false
    fireEvent.click(screen.getByTestId('steps-save-btn'))
    expect(await screen.findByTestId('steps-save-success')).toBeInTheDocument()
    expect(screen.queryByTestId('steps-save-error')).toBeNull()
  })
})

describe('WorkflowDrawer — Steps tab security (A9.1)', () => {
  it('renders an operator-supplied step name containing markup as escaped text, not HTML', () => {
    const xssName = '<img src=x onerror="window.__xss_step=1">'
    const wf = makeWorkflow({
      steps: [{ id: 's1', name: xssName, type: 'script', config: {} }],
    })
    openStepsTab(wf)
    // The step name input should contain the raw string value — never interpreted
    const nameInput = screen.getByTestId('step-name-input') as HTMLInputElement
    expect(nameInput.value).toBe(xssName)
    expect((window as unknown as Record<string, unknown>).__xss_step).toBeUndefined()
  })
})
