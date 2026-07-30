// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz

/*
 * BulkActionBar suite (Story #2939): bar-mode display, tag editor mode
 * transitions, and per-item result reporting for mixed-outcome bulk tag edits.
 *
 * Required test: bulk tag edit against a mixed-outcome mock (some stewards
 * succeed, some 403) surfaces per-item results — never a single aggregate
 * pass/fail for the whole batch.
 */
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'
import { cleanup, fireEvent, render, screen, waitFor } from '@testing-library/react'
import BulkActionBar from './BulkActionBar.tsx'

const fetchMock = vi.fn<typeof fetch>()

beforeEach(() => {
  fetchMock.mockReset()
  vi.stubGlobal('fetch', fetchMock)
})

afterEach(() => {
  cleanup()
  vi.unstubAllGlobals()
})

function mockAllOk() {
  fetchMock.mockResolvedValue(
    new Response('{}', { status: 200, headers: { 'Content-Type': 'application/json' } }),
  )
}

// ---------------------------------------------------------------------------
// Bar mode
// ---------------------------------------------------------------------------

describe('bar mode', () => {
  it('shows selected count', () => {
    render(<BulkActionBar selectedIds={new Set(['s1', 's2', 's3'])} onClear={vi.fn()} />)
    const countEl = screen.getByText('3')
    expect(countEl).toBeInTheDocument()
    // parentElement is the .bulk-sel span whose textContent is "3 selected"
    expect(countEl.parentElement?.textContent).toContain('selected')
  })

  it('renders "Edit tags" button', () => {
    render(<BulkActionBar selectedIds={new Set(['s1'])} onClear={vi.fn()} />)
    expect(screen.getByRole('button', { name: 'Edit tags' })).toBeInTheDocument()
  })

  it('"Clear" calls onClear', () => {
    const onClear = vi.fn()
    render(<BulkActionBar selectedIds={new Set(['s1'])} onClear={onClear} />)
    fireEvent.click(screen.getByRole('button', { name: 'Clear' }))
    expect(onClear).toHaveBeenCalledTimes(1)
  })

  it('"Edit tags" opens the tag editor with a tag input', () => {
    render(<BulkActionBar selectedIds={new Set(['s1'])} onClear={vi.fn()} />)
    fireEvent.click(screen.getByRole('button', { name: 'Edit tags' }))
    expect(screen.getByRole('textbox', { name: 'Tag name' })).toBeInTheDocument()
    expect(screen.queryByRole('button', { name: 'Edit tags' })).not.toBeInTheDocument()
  })
})

// ---------------------------------------------------------------------------
// Tag editor mode
// ---------------------------------------------------------------------------

describe('tag editor mode', () => {
  it('"Add to selected" is disabled while the tag input is empty', () => {
    render(<BulkActionBar selectedIds={new Set(['s1'])} onClear={vi.fn()} />)
    fireEvent.click(screen.getByRole('button', { name: 'Edit tags' }))
    expect(screen.getByRole('button', { name: 'Add to selected' })).toBeDisabled()
  })

  it('"Remove from selected" is disabled while the tag input is empty', () => {
    render(<BulkActionBar selectedIds={new Set(['s1'])} onClear={vi.fn()} />)
    fireEvent.click(screen.getByRole('button', { name: 'Edit tags' }))
    expect(screen.getByRole('button', { name: 'Remove from selected' })).toBeDisabled()
  })

  it('"Cancel" returns to bar mode', () => {
    render(<BulkActionBar selectedIds={new Set(['s1'])} onClear={vi.fn()} />)
    fireEvent.click(screen.getByRole('button', { name: 'Edit tags' }))
    expect(screen.getByRole('textbox', { name: 'Tag name' })).toBeInTheDocument()

    fireEvent.click(screen.getByRole('button', { name: 'Cancel' }))
    expect(screen.queryByRole('textbox')).not.toBeInTheDocument()
    expect(screen.getByRole('button', { name: 'Edit tags' })).toBeInTheDocument()
  })

  it('Escape in the tag input returns to bar mode', () => {
    render(<BulkActionBar selectedIds={new Set(['s1'])} onClear={vi.fn()} />)
    fireEvent.click(screen.getByRole('button', { name: 'Edit tags' }))
    fireEvent.keyDown(screen.getByRole('textbox', { name: 'Tag name' }), { key: 'Escape' })
    expect(screen.queryByRole('textbox')).not.toBeInTheDocument()
    expect(screen.getByRole('button', { name: 'Edit tags' })).toBeInTheDocument()
  })
})

// ---------------------------------------------------------------------------
// Bulk tag operations — per-item result reporting
// ---------------------------------------------------------------------------

describe('bulk tag operations', () => {
  it('[REQUIRED] mixed-outcome add: some succeed (200), some fail (403) — surfaces per-item results', async () => {
    // s1 → 200, s2 → 200, s3-fail → 403
    fetchMock.mockImplementation((url: RequestInfo | URL) => {
      if (String(url).includes('s3-fail')) {
        return Promise.resolve(
          new Response('{}', { status: 403, headers: { 'Content-Type': 'application/json' } }),
        )
      }
      return Promise.resolve(
        new Response('{}', { status: 200, headers: { 'Content-Type': 'application/json' } }),
      )
    })

    render(
      <BulkActionBar selectedIds={new Set(['s1', 's2', 's3-fail'])} onClear={vi.fn()} />,
    )
    fireEvent.click(screen.getByRole('button', { name: 'Edit tags' }))
    fireEvent.change(screen.getByRole('textbox', { name: 'Tag name' }), {
      target: { value: 'prod' },
    })
    fireEvent.click(screen.getByRole('button', { name: 'Add to selected' }))

    const summary = await screen.findByTestId('bulk-result-summary')
    expect(summary.textContent).toContain('2 of 3 succeeded')
    expect(summary.textContent).toContain('1 failed')
    expect(summary.textContent).toContain('s3-fail')
  })

  it('all succeed: shows full-success message with no failure mention', async () => {
    mockAllOk()
    render(<BulkActionBar selectedIds={new Set(['s1', 's2'])} onClear={vi.fn()} />)
    fireEvent.click(screen.getByRole('button', { name: 'Edit tags' }))
    fireEvent.change(screen.getByRole('textbox', { name: 'Tag name' }), {
      target: { value: 'env' },
    })
    fireEvent.click(screen.getByRole('button', { name: 'Add to selected' }))

    const summary = await screen.findByTestId('bulk-result-summary')
    expect(summary.textContent).toContain('2 of 2 succeeded')
    expect(summary.textContent).not.toContain('failed')
  })

  it('"Add to selected" issues one POST /stewards/:id/tags per selected steward', async () => {
    mockAllOk()
    render(
      <BulkActionBar selectedIds={new Set(['stw-a', 'stw-b'])} onClear={vi.fn()} />,
    )
    fireEvent.click(screen.getByRole('button', { name: 'Edit tags' }))
    fireEvent.change(screen.getByRole('textbox', { name: 'Tag name' }), {
      target: { value: 'env:prod' },
    })
    fireEvent.click(screen.getByRole('button', { name: 'Add to selected' }))

    await screen.findByTestId('bulk-result-summary')

    const postCalls = fetchMock.mock.calls.filter(
      (c) => (c[1]?.method ?? '').toUpperCase() === 'POST',
    )
    expect(postCalls).toHaveLength(2)
    const urls = postCalls.map((c) => String(c[0]))
    expect(urls).toContain('/api/v1/stewards/stw-a/tags')
    expect(urls).toContain('/api/v1/stewards/stw-b/tags')

    const bodies = postCalls.map((c) => JSON.parse(String(c[1]?.body)) as { tags: string[] })
    for (const body of bodies) {
      expect(body.tags).toContain('env:prod')
    }
  })

  it('"Remove from selected" issues one DELETE /stewards/:id/tags per selected steward', async () => {
    mockAllOk()
    render(<BulkActionBar selectedIds={new Set(['stw-x'])} onClear={vi.fn()} />)
    fireEvent.click(screen.getByRole('button', { name: 'Edit tags' }))
    fireEvent.change(screen.getByRole('textbox', { name: 'Tag name' }), {
      target: { value: 'old-tag' },
    })
    fireEvent.click(screen.getByRole('button', { name: 'Remove from selected' }))

    await screen.findByTestId('bulk-result-summary')

    const delCalls = fetchMock.mock.calls.filter(
      (c) => (c[1]?.method ?? '').toUpperCase() === 'DELETE',
    )
    expect(delCalls).toHaveLength(1)
    expect(String(delCalls[0]?.[0])).toBe('/api/v1/stewards/stw-x/tags')
    const body = JSON.parse(String(delCalls[0]?.[1]?.body)) as { tags: string[] }
    expect(body.tags).toContain('old-tag')
  })

  it('network error for a steward counts as a failure in per-item results', async () => {
    fetchMock.mockImplementation((url: RequestInfo | URL) => {
      if (String(url).includes('stw-net-err')) {
        return Promise.reject(new Error('network failure'))
      }
      return Promise.resolve(
        new Response('{}', { status: 200, headers: { 'Content-Type': 'application/json' } }),
      )
    })

    render(
      <BulkActionBar selectedIds={new Set(['stw-ok', 'stw-net-err'])} onClear={vi.fn()} />,
    )
    fireEvent.click(screen.getByRole('button', { name: 'Edit tags' }))
    fireEvent.change(screen.getByRole('textbox', { name: 'Tag name' }), {
      target: { value: 'tag' },
    })
    fireEvent.click(screen.getByRole('button', { name: 'Add to selected' }))

    const summary = await screen.findByTestId('bulk-result-summary')
    expect(summary.textContent).toContain('1 of 2 succeeded')
    expect(summary.textContent).toContain('stw-net-err')
  })

  it('encodes special characters in steward IDs when building the request URL', async () => {
    mockAllOk()
    render(<BulkActionBar selectedIds={new Set(['stw/sp ec'])} onClear={vi.fn()} />)
    fireEvent.click(screen.getByRole('button', { name: 'Edit tags' }))
    fireEvent.change(screen.getByRole('textbox', { name: 'Tag name' }), {
      target: { value: 'tag' },
    })
    fireEvent.click(screen.getByRole('button', { name: 'Add to selected' }))

    await screen.findByTestId('bulk-result-summary')
    expect(String(fetchMock.mock.calls[0]?.[0])).toBe('/api/v1/stewards/stw%2Fsp%20ec/tags')
  })
})

// ---------------------------------------------------------------------------
// Results mode
// ---------------------------------------------------------------------------

describe('results mode', () => {
  it('"Done" returns to bar mode (selection preserved)', async () => {
    mockAllOk()
    render(<BulkActionBar selectedIds={new Set(['s1'])} onClear={vi.fn()} />)
    fireEvent.click(screen.getByRole('button', { name: 'Edit tags' }))
    fireEvent.change(screen.getByRole('textbox', { name: 'Tag name' }), {
      target: { value: 'tag' },
    })
    fireEvent.click(screen.getByRole('button', { name: 'Add to selected' }))

    await screen.findByTestId('bulk-result-summary')
    fireEvent.click(screen.getByRole('button', { name: 'Done' }))

    expect(screen.queryByTestId('bulk-result-summary')).not.toBeInTheDocument()
    expect(screen.getByRole('button', { name: 'Edit tags' })).toBeInTheDocument()
  })

  it('shows the tag that was applied in the results phase', async () => {
    mockAllOk()
    render(<BulkActionBar selectedIds={new Set(['s1'])} onClear={vi.fn()} />)
    fireEvent.click(screen.getByRole('button', { name: 'Edit tags' }))
    fireEvent.change(screen.getByRole('textbox', { name: 'Tag name' }), {
      target: { value: 'env:prod' },
    })
    fireEvent.click(screen.getByRole('button', { name: 'Add to selected' }))

    await waitFor(() =>
      expect(screen.getByTestId('bulk-result-summary').textContent).toContain('1 of 1 succeeded'),
    )
  })
})

// ---------------------------------------------------------------------------
// Bulk move to tenant (Story #2972)
// ---------------------------------------------------------------------------

describe('bulk move to tenant', () => {
  it('bar renders "Move to tenant" button', () => {
    render(<BulkActionBar selectedIds={new Set(['s1'])} onClear={vi.fn()} />)
    expect(screen.getByRole('button', { name: 'Move to tenant' })).toBeInTheDocument()
  })

  it('"Move to tenant" opens the tenant ID input', () => {
    render(<BulkActionBar selectedIds={new Set(['s1'])} onClear={vi.fn()} />)
    fireEvent.click(screen.getByRole('button', { name: 'Move to tenant' }))
    expect(screen.getByRole('textbox', { name: 'Target tenant ID' })).toBeInTheDocument()
  })

  it('"Move selected" is disabled while the tenant input is empty', () => {
    render(<BulkActionBar selectedIds={new Set(['s1'])} onClear={vi.fn()} />)
    fireEvent.click(screen.getByRole('button', { name: 'Move to tenant' }))
    expect(screen.getByRole('button', { name: 'Move selected' })).toBeDisabled()
  })

  it('"Cancel" returns to bar mode from the move tenant panel', () => {
    render(<BulkActionBar selectedIds={new Set(['s1'])} onClear={vi.fn()} />)
    fireEvent.click(screen.getByRole('button', { name: 'Move to tenant' }))
    expect(screen.getByRole('textbox', { name: 'Target tenant ID' })).toBeInTheDocument()

    fireEvent.click(screen.getByRole('button', { name: 'Cancel' }))
    expect(screen.queryByRole('textbox')).not.toBeInTheDocument()
    expect(screen.getByRole('button', { name: 'Move to tenant' })).toBeInTheDocument()
  })

  it('Escape in the tenant input returns to bar mode', () => {
    render(<BulkActionBar selectedIds={new Set(['s1'])} onClear={vi.fn()} />)
    fireEvent.click(screen.getByRole('button', { name: 'Move to tenant' }))
    fireEvent.keyDown(screen.getByRole('textbox', { name: 'Target tenant ID' }), { key: 'Escape' })
    expect(screen.queryByRole('textbox')).not.toBeInTheDocument()
    expect(screen.getByRole('button', { name: 'Move to tenant' })).toBeInTheDocument()
  })

  it('[REQUIRED] mixed-outcome move: some succeed (200), some fail (403) — surfaces per-item results', async () => {
    fetchMock.mockImplementation((url: RequestInfo | URL) => {
      if (String(url).includes('s3-fail')) {
        return Promise.resolve(
          new Response('{}', { status: 403, headers: { 'Content-Type': 'application/json' } }),
        )
      }
      return Promise.resolve(
        new Response('{}', { status: 200, headers: { 'Content-Type': 'application/json' } }),
      )
    })

    render(
      <BulkActionBar selectedIds={new Set(['s1', 's2', 's3-fail'])} onClear={vi.fn()} />,
    )
    fireEvent.click(screen.getByRole('button', { name: 'Move to tenant' }))
    fireEvent.change(screen.getByRole('textbox', { name: 'Target tenant ID' }), {
      target: { value: 'tenant-b' },
    })
    fireEvent.click(screen.getByRole('button', { name: 'Move selected' }))

    const summary = await screen.findByTestId('bulk-result-summary')
    expect(summary.textContent).toContain('2 of 3 succeeded')
    expect(summary.textContent).toContain('1 failed')
    expect(summary.textContent).toContain('s3-fail')
  })

  it('"Move selected" issues one POST /stewards/:id/move per selected steward', async () => {
    fetchMock.mockResolvedValue(
      new Response('{}', { status: 200, headers: { 'Content-Type': 'application/json' } }),
    )
    render(
      <BulkActionBar selectedIds={new Set(['stw-a', 'stw-b'])} onClear={vi.fn()} />,
    )
    fireEvent.click(screen.getByRole('button', { name: 'Move to tenant' }))
    fireEvent.change(screen.getByRole('textbox', { name: 'Target tenant ID' }), {
      target: { value: 'tenant-b' },
    })
    fireEvent.click(screen.getByRole('button', { name: 'Move selected' }))

    await screen.findByTestId('bulk-result-summary')

    const postCalls = fetchMock.mock.calls.filter(
      (c) => (c[1]?.method ?? '').toUpperCase() === 'POST',
    )
    expect(postCalls).toHaveLength(2)
    const urls = postCalls.map((c) => String(c[0]))
    expect(urls).toContain('/api/v1/stewards/stw-a/move')
    expect(urls).toContain('/api/v1/stewards/stw-b/move')

    for (const call of postCalls) {
      const body = JSON.parse(String(call[1]?.body)) as { new_tenant_id: string }
      expect(body.new_tenant_id).toBe('tenant-b')
    }
  })

  it('encodes special characters in steward IDs for move requests', async () => {
    fetchMock.mockResolvedValue(
      new Response('{}', { status: 200, headers: { 'Content-Type': 'application/json' } }),
    )
    render(<BulkActionBar selectedIds={new Set(['stw/sp ec'])} onClear={vi.fn()} />)
    fireEvent.click(screen.getByRole('button', { name: 'Move to tenant' }))
    fireEvent.change(screen.getByRole('textbox', { name: 'Target tenant ID' }), {
      target: { value: 'tid' },
    })
    fireEvent.click(screen.getByRole('button', { name: 'Move selected' }))

    await screen.findByTestId('bulk-result-summary')
    expect(String(fetchMock.mock.calls[0]?.[0])).toBe('/api/v1/stewards/stw%2Fsp%20ec/move')
  })

  it('"Done" in move results returns to bar mode', async () => {
    fetchMock.mockResolvedValue(
      new Response('{}', { status: 200, headers: { 'Content-Type': 'application/json' } }),
    )
    render(<BulkActionBar selectedIds={new Set(['s1'])} onClear={vi.fn()} />)
    fireEvent.click(screen.getByRole('button', { name: 'Move to tenant' }))
    fireEvent.change(screen.getByRole('textbox', { name: 'Target tenant ID' }), {
      target: { value: 'tid' },
    })
    fireEvent.click(screen.getByRole('button', { name: 'Move selected' }))

    await screen.findByTestId('bulk-result-summary')
    fireEvent.click(screen.getByRole('button', { name: 'Done' }))

    expect(screen.queryByTestId('bulk-result-summary')).not.toBeInTheDocument()
    expect(screen.getByRole('button', { name: 'Move to tenant' })).toBeInTheDocument()
  })
})

// ---------------------------------------------------------------------------
// Bulk decommission (Story #2972)
// ---------------------------------------------------------------------------

describe('bulk decommission', () => {
  it('bar renders "Decommission selected" button', () => {
    render(<BulkActionBar selectedIds={new Set(['s1'])} onClear={vi.fn()} />)
    expect(screen.getByRole('button', { name: 'Decommission selected' })).toBeInTheDocument()
  })

  it('"Decommission selected" opens the confirmation dialog', () => {
    render(<BulkActionBar selectedIds={new Set(['s1', 's2'])} onClear={vi.fn()} />)
    fireEvent.click(screen.getByRole('button', { name: 'Decommission selected' }))
    expect(screen.getByRole('button', { name: 'Confirm decommission' })).toBeInTheDocument()
  })

  it('"Cancel" returns to bar mode from the decommission confirmation', () => {
    render(<BulkActionBar selectedIds={new Set(['s1'])} onClear={vi.fn()} />)
    fireEvent.click(screen.getByRole('button', { name: 'Decommission selected' }))
    fireEvent.click(screen.getByRole('button', { name: 'Cancel' }))
    expect(screen.queryByRole('button', { name: 'Confirm decommission' })).not.toBeInTheDocument()
    expect(screen.getByRole('button', { name: 'Decommission selected' })).toBeInTheDocument()
  })

  it('[REQUIRED] mixed-outcome decommission: some succeed (200), some fail (403) — surfaces per-item results', async () => {
    fetchMock.mockImplementation((url: RequestInfo | URL) => {
      if (String(url).includes('s3-fail')) {
        return Promise.resolve(
          new Response('{}', { status: 403, headers: { 'Content-Type': 'application/json' } }),
        )
      }
      return Promise.resolve(
        new Response('{}', { status: 200, headers: { 'Content-Type': 'application/json' } }),
      )
    })

    render(
      <BulkActionBar selectedIds={new Set(['s1', 's2', 's3-fail'])} onClear={vi.fn()} />,
    )
    fireEvent.click(screen.getByRole('button', { name: 'Decommission selected' }))
    fireEvent.click(screen.getByRole('button', { name: 'Confirm decommission' }))

    const summary = await screen.findByTestId('bulk-result-summary')
    expect(summary.textContent).toContain('2 of 3 succeeded')
    expect(summary.textContent).toContain('1 failed')
    expect(summary.textContent).toContain('s3-fail')
  })

  it('confirming decommission issues one DELETE /stewards/:id per selected steward', async () => {
    fetchMock.mockResolvedValue(
      new Response('{}', { status: 200, headers: { 'Content-Type': 'application/json' } }),
    )
    render(
      <BulkActionBar selectedIds={new Set(['stw-a', 'stw-b'])} onClear={vi.fn()} />,
    )
    fireEvent.click(screen.getByRole('button', { name: 'Decommission selected' }))
    fireEvent.click(screen.getByRole('button', { name: 'Confirm decommission' }))

    await screen.findByTestId('bulk-result-summary')

    const deleteCalls = fetchMock.mock.calls.filter(
      (c) => (c[1]?.method ?? '').toUpperCase() === 'DELETE',
    )
    expect(deleteCalls).toHaveLength(2)
    const urls = deleteCalls.map((c) => String(c[0]))
    expect(urls).toContain('/api/v1/stewards/stw-a')
    expect(urls).toContain('/api/v1/stewards/stw-b')
  })

  it('network error for a steward counts as a failure in decommission results', async () => {
    fetchMock.mockImplementation((url: RequestInfo | URL) => {
      if (String(url).includes('stw-net-err')) {
        return Promise.reject(new Error('network failure'))
      }
      return Promise.resolve(
        new Response('{}', { status: 200, headers: { 'Content-Type': 'application/json' } }),
      )
    })

    render(
      <BulkActionBar selectedIds={new Set(['stw-ok', 'stw-net-err'])} onClear={vi.fn()} />,
    )
    fireEvent.click(screen.getByRole('button', { name: 'Decommission selected' }))
    fireEvent.click(screen.getByRole('button', { name: 'Confirm decommission' }))

    const summary = await screen.findByTestId('bulk-result-summary')
    expect(summary.textContent).toContain('1 of 2 succeeded')
    expect(summary.textContent).toContain('stw-net-err')
  })

  it('"Done" in decommission results returns to bar mode', async () => {
    fetchMock.mockResolvedValue(
      new Response('{}', { status: 200, headers: { 'Content-Type': 'application/json' } }),
    )
    render(<BulkActionBar selectedIds={new Set(['s1'])} onClear={vi.fn()} />)
    fireEvent.click(screen.getByRole('button', { name: 'Decommission selected' }))
    fireEvent.click(screen.getByRole('button', { name: 'Confirm decommission' }))

    await screen.findByTestId('bulk-result-summary')
    fireEvent.click(screen.getByRole('button', { name: 'Done' }))

    expect(screen.queryByTestId('bulk-result-summary')).not.toBeInTheDocument()
    expect(screen.getByRole('button', { name: 'Decommission selected' })).toBeInTheDocument()
  })
})
