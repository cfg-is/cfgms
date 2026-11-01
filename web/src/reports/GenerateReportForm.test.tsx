// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz

/*
 * GenerateReportForm suite (Story #3271): covers successful generate-and-download
 * flow and error states. Fetch mocking via vi.stubGlobal, same convention as
 * ReportsDashboardView.test.tsx.
 *
 * Browser download mechanics (createObjectURL / revokeObjectURL / anchor.click)
 * are not exercisable in jsdom — we assert the fetch call shape instead.
 * Clicks use fireEvent (consistent with the existing test suite).
 */
import { beforeEach, afterEach, describe, expect, it, vi } from 'vitest'
import { cleanup, fireEvent, render, screen, waitFor } from '@testing-library/react'
import { MemoryRouter } from 'react-router'
import { AuthProvider } from '../auth/AuthContext.tsx'
import GenerateReportForm from './GenerateReportForm.tsx'

const fetchMock = vi.fn<typeof fetch>()

beforeEach(() => {
  fetchMock.mockReset()
  vi.stubGlobal('fetch', fetchMock)
  vi.spyOn(URL, 'createObjectURL').mockReturnValue('blob:mock-url')
  vi.spyOn(URL, 'revokeObjectURL').mockImplementation(() => {})
})

afterEach(() => {
  vi.restoreAllMocks()
  vi.unstubAllGlobals()
  cleanup()
})

const TEMPLATE_INFO = {
  name: 'compliance-summary',
  type: 'compliance',
  description: 'Summarises compliance posture across all enrolled devices.',
  parameters: [],
  supported_formats: ['json', 'csv'],
}

function mockGenerateSuccess() {
  fetchMock.mockImplementation((input) => {
    const url = String(input)
    if (url.includes('/api/v1/reports/generate')) {
      return Promise.resolve(
        new Response('{"report":"data"}', {
          status: 200,
          headers: {
            'Content-Type': 'application/json',
            'Content-Disposition': 'attachment; filename="compliance-summary.json"',
          },
        }),
      )
    }
    return Promise.resolve(new Response('{}', { status: 404 }))
  })
}

function mockGenerateError(status = 500) {
  fetchMock.mockImplementation(() =>
    Promise.resolve(
      new Response(JSON.stringify({ error: 'generation failed' }), {
        status,
        headers: { 'Content-Type': 'application/json' },
      }),
    ),
  )
}

function renderForm(template = TEMPLATE_INFO) {
  return render(
    <MemoryRouter>
      <AuthProvider>
        <GenerateReportForm template={template} onBack={() => {}} />
      </AuthProvider>
    </MemoryRouter>,
  )
}

describe('form renders', () => {
  it('shows the template name as the form heading', () => {
    renderForm()
    expect(screen.getByText('compliance-summary')).toBeInTheDocument()
  })

  it('shows the template description', () => {
    renderForm()
    expect(
      screen.getByText('Summarises compliance posture across all enrolled devices.'),
    ).toBeInTheDocument()
  })

  it('shows a Generate button', () => {
    renderForm()
    expect(screen.getByRole('button', { name: /generate/i })).toBeInTheDocument()
  })

  it('shows a Back button', () => {
    renderForm()
    expect(screen.getByRole('button', { name: /back/i })).toBeInTheDocument()
  })

  it('defaults format selector to json', () => {
    renderForm()
    const select = screen.getByRole('combobox', { name: /format/i })
    expect((select as HTMLSelectElement).value).toBe('json')
  })
})

describe('successful generate', () => {
  it('POSTs to /api/v1/reports/generate with the correct shape', async () => {
    mockGenerateSuccess()
    renderForm()

    fireEvent.click(screen.getByRole('button', { name: /generate/i }))

    await waitFor(() => {
      const call = fetchMock.mock.calls.find((c) =>
        String(c[0]).includes('/api/v1/reports/generate'),
      )
      expect(call).toBeDefined()
      expect(call![1]?.method).toBe('POST')
      const body = JSON.parse(call![1]?.body as string)
      expect(body.template).toBe('compliance-summary')
      expect(body.format).toBe('json')
    })
  })

  it('shows a success message after successful generation', async () => {
    mockGenerateSuccess()
    renderForm()
    fireEvent.click(screen.getByRole('button', { name: /generate/i }))
    await screen.findByTestId('generate-success')
  })

  it('disables the Generate button while request is in flight', async () => {
    let resolveResponse!: (r: Response) => void
    fetchMock.mockImplementation(
      () => new Promise<Response>((res) => { resolveResponse = res }),
    )
    renderForm()
    fireEvent.click(screen.getByRole('button', { name: /generate/i }))
    expect(screen.getByRole('button', { name: /generating/i })).toBeDisabled()
    // Resolve and drain async work so teardown is clean.
    resolveResponse(
      new Response('{}', {
        status: 200,
        headers: { 'Content-Disposition': 'attachment; filename="r.json"' },
      }),
    )
    await screen.findByTestId('generate-success')
  })
})

describe('error state', () => {
  it('shows an error notice when generation fails', async () => {
    mockGenerateError(500)
    renderForm()
    fireEvent.click(screen.getByRole('button', { name: /generate/i }))
    await screen.findByRole('alert')
    expect(screen.getByText(/Report generation failed/i)).toBeInTheDocument()
    expect(screen.getByText(/500/)).toBeInTheDocument()
  })

  it('allows retrying after an error', async () => {
    mockGenerateError(500)
    renderForm()
    fireEvent.click(screen.getByRole('button', { name: /generate/i }))
    await screen.findByRole('alert')

    mockGenerateSuccess()
    fireEvent.click(screen.getByRole('button', { name: /generate/i }))
    await screen.findByTestId('generate-success')
    expect(screen.queryByRole('alert')).not.toBeInTheDocument()
  })
})

describe('back navigation', () => {
  it('calls onBack when the Back button is clicked', () => {
    const onBack = vi.fn()
    render(
      <MemoryRouter>
        <AuthProvider>
          <GenerateReportForm template={TEMPLATE_INFO} onBack={onBack} />
        </AuthProvider>
      </MemoryRouter>,
    )
    fireEvent.click(screen.getByRole('button', { name: /back/i }))
    expect(onBack).toHaveBeenCalledTimes(1)
  })
})
