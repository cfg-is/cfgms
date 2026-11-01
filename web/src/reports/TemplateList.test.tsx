// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz

/*
 * TemplateList suite (Story #3271): list/empty/error states.
 * Fetch mocking via vi.stubGlobal, same convention as ReportsDashboardView.test.tsx.
 * Clicks use fireEvent (consistent with the existing test suite — user-event
 * is not installed in this project's test dependencies).
 */
import { beforeEach, afterEach, describe, expect, it, vi } from 'vitest'
import { cleanup, fireEvent, render, screen, waitFor } from '@testing-library/react'
import { MemoryRouter } from 'react-router'
import { AuthProvider } from '../auth/AuthContext.tsx'
import TemplateList from './TemplateList.tsx'

const fetchMock = vi.fn<typeof fetch>()

beforeEach(() => {
  fetchMock.mockReset()
  vi.stubGlobal('fetch', fetchMock)
})

afterEach(() => {
  vi.unstubAllGlobals()
  cleanup()
})

const TEMPLATES_BODY = {
  templates: [
    {
      name: 'compliance-summary',
      type: 'compliance',
      description: 'Summarises compliance posture across all enrolled devices.',
      parameters: [],
      supported_formats: ['json', 'csv'],
    },
    {
      name: 'executive-dashboard',
      type: 'executive',
      description: 'High-level executive overview with KPI metrics.',
      parameters: [
        { name: 'include_charts', type: 'boolean', required: false, default: true },
      ],
      supported_formats: ['json', 'pdf', 'html'],
    },
    {
      name: 'drift-report',
      type: 'drift',
      description: 'Detailed drift event log with per-device breakdown.',
      parameters: [],
      supported_formats: ['json', 'csv', 'xlsx'],
    },
  ],
  count: 3,
}

function mockTemplates(body = TEMPLATES_BODY) {
  fetchMock.mockImplementation((input) => {
    const url = String(input)
    if (url.includes('/api/v1/reports/templates')) {
      return Promise.resolve(
        new Response(JSON.stringify(body), {
          status: 200,
          headers: { 'Content-Type': 'application/json' },
        }),
      )
    }
    return Promise.resolve(new Response('{}', { status: 404 }))
  })
}

function mockError(status = 503) {
  fetchMock.mockImplementation(() =>
    Promise.resolve(
      new Response(JSON.stringify({ error: 'service unavailable' }), {
        status,
        headers: { 'Content-Type': 'application/json' },
      }),
    ),
  )
}

function renderList(onSelect?: (name: string) => void) {
  return render(
    <MemoryRouter>
      <AuthProvider>
        <TemplateList onSelectTemplate={onSelect ?? (() => {})} />
      </AuthProvider>
    </MemoryRouter>,
  )
}

describe('loading state', () => {
  it('shows loading indicator while request is pending', () => {
    fetchMock.mockImplementation(() => new Promise<Response>(() => {}))
    renderList()
    expect(screen.getByTestId('template-list-loading')).toBeInTheDocument()
    expect(screen.queryByTestId('template-list-table')).not.toBeInTheDocument()
  })
})

describe('error state', () => {
  it('shows error notice when request fails', async () => {
    mockError(503)
    renderList()
    await screen.findByRole('alert')
    expect(screen.getByText(/Could not load report templates/i)).toBeInTheDocument()
    expect(screen.getByText(/503/)).toBeInTheDocument()
    expect(screen.queryByTestId('template-list-table')).not.toBeInTheDocument()
  })

  it('retries on clicking Retry and renders table on success', async () => {
    mockError(503)
    renderList()
    await screen.findByRole('alert')

    mockTemplates()
    fireEvent.click(screen.getByRole('button', { name: /retry/i }))
    await screen.findByTestId('template-list-table')
    expect(screen.queryByRole('alert')).not.toBeInTheDocument()
  })
})

describe('empty state', () => {
  it('shows empty notice when templates array is empty', async () => {
    mockTemplates({ templates: [], count: 0 })
    renderList()
    await screen.findByTestId('template-list-empty')
    expect(screen.getByText(/No report templates available/i)).toBeInTheDocument()
    expect(screen.queryByTestId('template-list-table')).not.toBeInTheDocument()
  })
})

describe('list state', () => {
  it('renders a row for each template returned by the API', async () => {
    mockTemplates()
    renderList()
    await screen.findByTestId('template-list-table')

    expect(screen.getByText('compliance-summary')).toBeInTheDocument()
    expect(screen.getByText('executive-dashboard')).toBeInTheDocument()
    expect(screen.getByText('drift-report')).toBeInTheDocument()
  })

  it('renders template description in each row', async () => {
    mockTemplates()
    renderList()
    await screen.findByTestId('template-list-table')
    expect(
      screen.getByText('Summarises compliance posture across all enrolled devices.'),
    ).toBeInTheDocument()
  })

  it('renders template type in each row', async () => {
    mockTemplates()
    renderList()
    await screen.findByTestId('template-list-table')
    expect(screen.getByText('compliance')).toBeInTheDocument()
    expect(screen.getByText('executive')).toBeInTheDocument()
  })

  it('calls onSelectTemplate with template name when a row is clicked', async () => {
    mockTemplates()
    const onSelect = vi.fn()
    renderList(onSelect)
    await screen.findByTestId('template-list-table')

    fireEvent.click(screen.getByText('compliance-summary'))
    expect(onSelect).toHaveBeenCalledWith('compliance-summary')
  })

  it('calls onSelectTemplate with the correct template name for each row', async () => {
    mockTemplates()
    const onSelect = vi.fn()
    renderList(onSelect)
    await screen.findByTestId('template-list-table')

    fireEvent.click(screen.getByText('executive-dashboard'))
    expect(onSelect).toHaveBeenCalledWith('executive-dashboard')
  })

  it('fetches from GET /api/v1/reports/templates', async () => {
    mockTemplates()
    renderList()
    await screen.findByTestId('template-list-table')

    const calls = fetchMock.mock.calls.map((c) => String(c[0]))
    expect(calls.some((u) => u.includes('/api/v1/reports/templates'))).toBe(true)
  })
})

describe('sortable headers', () => {
  it('renders sortable Name and Type columns', async () => {
    mockTemplates()
    renderList()
    await screen.findByTestId('template-list-table')

    expect(screen.getByRole('columnheader', { name: /name/i })).toBeInTheDocument()
    expect(screen.getByRole('columnheader', { name: /type/i })).toBeInTheDocument()
  })

  it('sorts rows ascending by name on first Name header click', async () => {
    mockTemplates()
    renderList()
    await screen.findByTestId('template-list-table')

    fireEvent.click(screen.getByRole('columnheader', { name: /name/i }))

    await waitFor(() => {
      const rows = screen.getAllByRole('row')
      const names = rows
        .slice(1)
        .map((r) => r.querySelector('.nm')?.textContent ?? '')
        .filter(Boolean)
      const sorted = [...names].sort()
      expect(names).toEqual(sorted)
    })
  })
})
