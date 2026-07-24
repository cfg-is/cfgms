// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz

/*
 * ConfigListView test suite (Story #2730): list rendering, data states,
 * push-panel toggle, and steward selection opening ConfigEditor.
 */
import { beforeEach, afterEach, describe, expect, it, vi } from 'vitest'
import { cleanup, fireEvent, render, screen, waitFor } from '@testing-library/react'
import { MemoryRouter } from 'react-router-dom'
import { AuthProvider } from '../auth/AuthContext.tsx'
import ConfigListView from './ConfigListView.tsx'

const fetchMock = vi.fn<typeof fetch>()

beforeEach(() => {
  vi.stubGlobal('fetch', fetchMock)
  fetchMock.mockReset()
})

afterEach(() => {
  vi.unstubAllGlobals()
  cleanup()
})

function makeConfigEnvelope(configs: object[], status = 200) {
  return new Response(
    JSON.stringify({
      data: configs,
      timestamp: new Date().toISOString(),
    }),
    { status, headers: { 'Content-Type': 'application/json' } },
  )
}

function makeStewardConfig(overrides: Partial<Record<string, unknown>> = {}) {
  return {
    tenant_id: 'root',
    steward_id: 'sw-1',
    version: 1,
    updated_at: '2026-01-01T00:00:00Z',
    updated_by: 'admin',
    source: 'git',
    checksum: 'abc123',
    tags: [],
    ...overrides,
  }
}

function makePerStewardConfigResponse(stewardId = 'sw-1') {
  return new Response(
    JSON.stringify({
      data: {
        steward_id: stewardId,
        version: '1',
        config: { resources: [] },
        updated_at: '2026-01-01T00:00:00Z',
      },
      timestamp: new Date().toISOString(),
    }),
    { status: 200, headers: { 'Content-Type': 'application/json' } },
  )
}

function renderConfigListView() {
  return render(
    <MemoryRouter>
      <AuthProvider>
        <ConfigListView />
      </AuthProvider>
    </MemoryRouter>,
  )
}

describe('ConfigListView — heading and page structure', () => {
  it('shows the Configuration heading', () => {
    fetchMock.mockReturnValue(new Promise(() => {}))
    renderConfigListView()
    expect(
      screen.getByRole('heading', { name: /configuration/i, level: 1 }),
    ).toBeInTheDocument()
  })

  it('shows the Push config button', () => {
    fetchMock.mockResolvedValue(makeConfigEnvelope([]))
    renderConfigListView()
    expect(screen.getByTestId('toggle-push-btn')).toBeInTheDocument()
  })
})

describe('ConfigListView — data states', () => {
  it('shows loading state before the response', () => {
    fetchMock.mockReturnValue(new Promise(() => {}))
    renderConfigListView()
    expect(screen.getByTestId('config-loading')).toBeInTheDocument()
  })

  it('shows empty state when no configs exist', async () => {
    fetchMock.mockResolvedValue(makeConfigEnvelope([]))
    renderConfigListView()
    await waitFor(() => expect(screen.getByTestId('config-empty')).toBeInTheDocument())
  })

  it('shows error notice when the request fails', async () => {
    fetchMock.mockResolvedValue(makeConfigEnvelope([], 500))
    renderConfigListView()
    await waitFor(() => expect(screen.getByRole('alert')).toBeInTheDocument())
    expect(screen.getByRole('button', { name: /retry/i })).toBeInTheDocument()
  })

  it('renders a table with config rows when configs exist', async () => {
    fetchMock.mockResolvedValue(
      makeConfigEnvelope([
        makeStewardConfig({ steward_id: 'sw-1' }),
        makeStewardConfig({ steward_id: 'sw-2' }),
      ]),
    )
    renderConfigListView()
    await waitFor(() => expect(screen.getByTestId('config-table')).toBeInTheDocument())
    expect(screen.getAllByTestId('config-row')).toHaveLength(2)
    expect(screen.getByText('sw-1')).toBeInTheDocument()
    expect(screen.getByText('sw-2')).toBeInTheDocument()
  })

  it('shows the config count in the toolbar', async () => {
    fetchMock.mockResolvedValue(
      makeConfigEnvelope([makeStewardConfig(), makeStewardConfig({ steward_id: 'sw-2' })]),
    )
    renderConfigListView()
    await waitFor(() => expect(screen.getByTestId('config-count')).toBeInTheDocument())
    expect(screen.getByTestId('config-count')).toHaveTextContent('2 configs')
  })
})

describe('ConfigListView — steward selection', () => {
  it('opens ConfigEditor when a config row is clicked', async () => {
    fetchMock.mockResolvedValueOnce(makeConfigEnvelope([makeStewardConfig()]))
    fetchMock.mockResolvedValue(makePerStewardConfigResponse())

    renderConfigListView()
    await waitFor(() => expect(screen.getByTestId('config-table')).toBeInTheDocument())

    fireEvent.click(screen.getByTestId('config-row'))

    await waitFor(() => expect(screen.getByTestId('config-editor')).toBeInTheDocument())
  })

  it('closes ConfigEditor when clicking the same row again', async () => {
    fetchMock.mockResolvedValueOnce(makeConfigEnvelope([makeStewardConfig()]))
    fetchMock.mockResolvedValue(makePerStewardConfigResponse())

    renderConfigListView()
    await waitFor(() => expect(screen.getByTestId('config-table')).toBeInTheDocument())

    // Open editor
    fireEvent.click(screen.getByTestId('config-row'))
    await waitFor(() => expect(screen.getByTestId('config-editor')).toBeInTheDocument())

    // Click same row to close
    fireEvent.click(screen.getByTestId('config-row'))
    expect(screen.queryByTestId('config-editor')).toBeNull()
  })
})

describe('ConfigListView — push panel toggle', () => {
  it('shows push panel when Push config is toggled on', async () => {
    fetchMock.mockResolvedValue(makeConfigEnvelope([]))
    renderConfigListView()
    await waitFor(() => expect(screen.getByTestId('config-empty')).toBeInTheDocument())

    fireEvent.click(screen.getByTestId('toggle-push-btn'))
    expect(screen.getByTestId('push-panel')).toBeInTheDocument()
  })

  it('hides push panel when toggled off', async () => {
    fetchMock.mockResolvedValue(makeConfigEnvelope([]))
    renderConfigListView()
    await waitFor(() => expect(screen.getByTestId('config-empty')).toBeInTheDocument())

    fireEvent.click(screen.getByTestId('toggle-push-btn'))
    expect(screen.getByTestId('push-panel')).toBeInTheDocument()

    fireEvent.click(screen.getByTestId('toggle-push-btn'))
    expect(screen.queryByTestId('push-panel')).toBeNull()
  })

  it('hides push panel when Cancel is clicked inside the panel', async () => {
    fetchMock.mockResolvedValue(makeConfigEnvelope([]))
    renderConfigListView()
    await waitFor(() => expect(screen.getByTestId('config-empty')).toBeInTheDocument())

    fireEvent.click(screen.getByTestId('toggle-push-btn'))
    expect(screen.getByTestId('push-panel')).toBeInTheDocument()

    fireEvent.click(screen.getByRole('button', { name: /cancel/i }))
    expect(screen.queryByTestId('push-panel')).toBeNull()
  })
})

function makeStewardsPageEnvelope(stewards: object[], status = 200) {
  return new Response(
    JSON.stringify({
      data: { stewards, total: stewards.length, limit: 500, offset: 0 },
      timestamp: new Date().toISOString(),
    }),
    { status, headers: { 'Content-Type': 'application/json' } },
  )
}

describe('ConfigListView — STEWARD column hostname display', () => {
  it('shows hostname from the stewards list when available', async () => {
    fetchMock.mockResolvedValueOnce(
      makeConfigEnvelope([makeStewardConfig({ steward_id: 'sw-1' })]),
    )
    fetchMock.mockResolvedValueOnce(
      makeStewardsPageEnvelope([{ id: 'sw-1', dna: { hostname: 'CFG-AB-01' } }]),
    )
    renderConfigListView()
    await waitFor(() => expect(screen.getByTestId('config-table')).toBeInTheDocument())
    expect(screen.getByText('CFG-AB-01')).toBeInTheDocument()
    expect(screen.queryByText('sw-1')).toBeNull()
  })

  it('falls back to steward ID when hostname is absent from DNA', async () => {
    fetchMock.mockResolvedValueOnce(
      makeConfigEnvelope([makeStewardConfig({ steward_id: 'sw-2' })]),
    )
    fetchMock.mockResolvedValueOnce(
      makeStewardsPageEnvelope([{ id: 'sw-2', dna: null }]),
    )
    renderConfigListView()
    await waitFor(() => expect(screen.getByTestId('config-table')).toBeInTheDocument())
    expect(screen.getByText('sw-2')).toBeInTheDocument()
  })

  it('falls back to steward ID when steward is not in the hostname map', async () => {
    fetchMock.mockResolvedValueOnce(
      makeConfigEnvelope([makeStewardConfig({ steward_id: 'sw-3' })]),
    )
    fetchMock.mockResolvedValueOnce(makeStewardsPageEnvelope([]))
    renderConfigListView()
    await waitFor(() => expect(screen.getByTestId('config-table')).toBeInTheDocument())
    expect(screen.getByText('sw-3')).toBeInTheDocument()
  })

  it('shows ID when stewards fetch fails (graceful degradation)', async () => {
    fetchMock.mockResolvedValueOnce(
      makeConfigEnvelope([makeStewardConfig({ steward_id: 'sw-4' })]),
    )
    fetchMock.mockRejectedValueOnce(new Error('network down'))
    renderConfigListView()
    await waitFor(() => expect(screen.getByTestId('config-table')).toBeInTheDocument())
    expect(screen.getByText('sw-4')).toBeInTheDocument()
  })
})

function make404Response() {
  return new Response('{}', { status: 404, headers: { 'Content-Type': 'application/json' } })
}

describe('ConfigListView — create new config', () => {
  it('shows + New config button in toolbar', async () => {
    fetchMock.mockResolvedValue(makeConfigEnvelope([]))
    renderConfigListView()
    await waitFor(() => expect(screen.getByTestId('config-empty')).toBeInTheDocument())
    expect(screen.getByTestId('toggle-create-btn')).toBeInTheDocument()
    expect(screen.getByTestId('toggle-create-btn')).toHaveTextContent('+ New config')
  })

  it('clicking + New config shows the steward ID input form', async () => {
    fetchMock.mockResolvedValue(makeConfigEnvelope([]))
    renderConfigListView()
    await waitFor(() => expect(screen.getByTestId('config-empty')).toBeInTheDocument())
    fireEvent.click(screen.getByTestId('toggle-create-btn'))
    expect(screen.getByTestId('create-config-form')).toBeInTheDocument()
    expect(screen.getByTestId('create-steward-id-input')).toBeInTheDocument()
  })

  it('clicking + New config again closes the form', async () => {
    fetchMock.mockResolvedValue(makeConfigEnvelope([]))
    renderConfigListView()
    await waitFor(() => expect(screen.getByTestId('config-empty')).toBeInTheDocument())
    fireEvent.click(screen.getByTestId('toggle-create-btn'))
    expect(screen.getByTestId('create-config-form')).toBeInTheDocument()
    fireEvent.click(screen.getByTestId('toggle-create-btn'))
    expect(screen.queryByTestId('create-config-form')).toBeNull()
  })

  it('submitting the form opens ConfigEditor for the entered steward ID without an existing row', async () => {
    fetchMock.mockResolvedValueOnce(makeConfigEnvelope([]))
    fetchMock.mockResolvedValueOnce(
      new Response(
        JSON.stringify({ data: { stewards: [], total: 0, limit: 500, offset: 0 } }),
        { status: 200, headers: { 'Content-Type': 'application/json' } },
      ),
    )
    fetchMock.mockResolvedValue(make404Response())

    renderConfigListView()
    await waitFor(() => expect(screen.getByTestId('config-empty')).toBeInTheDocument())

    fireEvent.click(screen.getByTestId('toggle-create-btn'))
    fireEvent.change(screen.getByTestId('create-steward-id-input'), {
      target: { value: 'new-steward-id' },
    })
    fireEvent.click(screen.getByTestId('create-open-btn'))

    await waitFor(() => expect(screen.getByTestId('config-editor')).toBeInTheDocument())
    await waitFor(() => expect(screen.getByTestId('editor-textarea')).toBeInTheDocument())
  })

  it('create-open-btn is disabled when steward ID input is empty', async () => {
    fetchMock.mockResolvedValue(makeConfigEnvelope([]))
    renderConfigListView()
    await waitFor(() => expect(screen.getByTestId('config-empty')).toBeInTheDocument())
    fireEvent.click(screen.getByTestId('toggle-create-btn'))
    expect(screen.getByTestId('create-open-btn')).toBeDisabled()
  })
})

describe('ConfigListView — security (A9.1)', () => {
  it('renders steward_id and tenant_id as plain text, not HTML', async () => {
    const xss = '<img src=x onerror="window.__xss=1">'
    fetchMock.mockResolvedValue(
      makeConfigEnvelope([makeStewardConfig({ steward_id: xss, tenant_id: xss })]),
    )
    renderConfigListView()
    await waitFor(() => expect(screen.getByTestId('config-table')).toBeInTheDocument())

    // The payload appears as literal text (not parsed as HTML)
    expect(screen.getAllByText(xss).length).toBeGreaterThan(0)
    expect((window as unknown as Record<string, unknown>).__xss).toBeUndefined()
  })
})

// ── Deployment affordance ─────────────────────────────────────────────────────

function makeDeploymentsEnvelope(configId: string, stewards: object[], status = 200) {
  return new Response(
    JSON.stringify({
      data: {
        config_id: configId,
        summary: { applied: stewards.length, pending: 0, failed: 0, halted: 0, total: stewards.length },
        stewards,
        push_history: [],
      },
      timestamp: new Date().toISOString(),
    }),
    { status, headers: { 'Content-Type': 'application/json' } },
  )
}

describe('ConfigListView — deployment affordance', () => {
  it('shows a Deployments button on each config row', async () => {
    fetchMock.mockResolvedValueOnce(makeConfigEnvelope([makeStewardConfig()]))
    fetchMock.mockResolvedValue(makeStewardsPageEnvelope([]))
    renderConfigListView()
    await waitFor(() => expect(screen.getByTestId('config-table')).toBeInTheDocument())
    expect(screen.getByTestId('view-deployments-btn')).toBeInTheDocument()
  })

  it('clicking Deployments button opens the deployment panel', async () => {
    fetchMock.mockResolvedValueOnce(makeConfigEnvelope([makeStewardConfig({ steward_id: 'sw-1' })]))
    fetchMock.mockImplementation((url: unknown) => {
      const u = String(url)
      if (u.includes('/deployments')) {
        return Promise.resolve(
          makeDeploymentsEnvelope('sw-1', [
            { steward_id: 'sw-1', status: 'applied', last_updated: '2026-01-01T00:00:00Z' },
          ]),
        )
      }
      return Promise.resolve(makeStewardsPageEnvelope([]))
    })
    renderConfigListView()
    await waitFor(() => expect(screen.getByTestId('config-table')).toBeInTheDocument())

    fireEvent.click(screen.getByTestId('view-deployments-btn'))
    await waitFor(() => expect(screen.getByTestId('deployment-panel')).toBeInTheDocument())
    await waitFor(() => expect(screen.getByTestId('deployment-steward-row')).toBeInTheDocument())
  })

  it('clicking Deployments button again closes the deployment panel', async () => {
    fetchMock.mockResolvedValueOnce(makeConfigEnvelope([makeStewardConfig({ steward_id: 'sw-1' })]))
    fetchMock.mockImplementation((url: unknown) => {
      const u = String(url)
      if (u.includes('/deployments')) {
        return Promise.resolve(makeDeploymentsEnvelope('sw-1', []))
      }
      return Promise.resolve(makeStewardsPageEnvelope([]))
    })
    renderConfigListView()
    await waitFor(() => expect(screen.getByTestId('config-table')).toBeInTheDocument())

    fireEvent.click(screen.getByTestId('view-deployments-btn'))
    await waitFor(() => expect(screen.getByTestId('deployment-panel')).toBeInTheDocument())

    fireEvent.click(screen.getByTestId('view-deployments-btn'))
    expect(screen.queryByTestId('deployment-panel')).toBeNull()
  })

  it('clicking Deployments button does not open the ConfigEditor', async () => {
    fetchMock.mockResolvedValueOnce(makeConfigEnvelope([makeStewardConfig({ steward_id: 'sw-1' })]))
    fetchMock.mockImplementation((url: unknown) => {
      const u = String(url)
      if (u.includes('/deployments')) {
        return Promise.resolve(makeDeploymentsEnvelope('sw-1', []))
      }
      return Promise.resolve(makeStewardsPageEnvelope([]))
    })
    renderConfigListView()
    await waitFor(() => expect(screen.getByTestId('config-table')).toBeInTheDocument())

    fireEvent.click(screen.getByTestId('view-deployments-btn'))
    expect(screen.queryByTestId('config-editor')).toBeNull()
  })

  it('shows service-unavailable message when deployments returns 503', async () => {
    fetchMock.mockResolvedValueOnce(makeConfigEnvelope([makeStewardConfig({ steward_id: 'sw-1' })]))
    fetchMock.mockImplementation((url: unknown) => {
      const u = String(url)
      if (u.includes('/deployments')) {
        return Promise.resolve(
          makeDeploymentsEnvelope('sw-1', [], 503),
        )
      }
      return Promise.resolve(makeStewardsPageEnvelope([]))
    })
    renderConfigListView()
    await waitFor(() => expect(screen.getByTestId('config-table')).toBeInTheDocument())

    fireEvent.click(screen.getByTestId('view-deployments-btn'))
    await waitFor(() => expect(screen.getByTestId('deployment-panel')).toBeInTheDocument())
    await waitFor(() => expect(screen.getByText(/unavailable/i)).toBeInTheDocument())
  })

  it('Close button in deployment panel hides the panel', async () => {
    fetchMock.mockResolvedValueOnce(makeConfigEnvelope([makeStewardConfig({ steward_id: 'sw-1' })]))
    fetchMock.mockImplementation((url: unknown) => {
      const u = String(url)
      if (u.includes('/deployments')) {
        return Promise.resolve(makeDeploymentsEnvelope('sw-1', []))
      }
      return Promise.resolve(makeStewardsPageEnvelope([]))
    })
    renderConfigListView()
    await waitFor(() => expect(screen.getByTestId('config-table')).toBeInTheDocument())

    fireEvent.click(screen.getByTestId('view-deployments-btn'))
    await waitFor(() => expect(screen.getByTestId('deployment-panel')).toBeInTheDocument())

    fireEvent.click(screen.getByRole('button', { name: /close/i }))
    expect(screen.queryByTestId('deployment-panel')).toBeNull()
  })
})
