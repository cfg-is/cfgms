// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz

/*
 * FleetTable suite (Story #2917): asserts that rows render as real anchor
 * elements so that native browser modifier-key / middle-click / context-menu
 * "Open in new tab" behavior applies without synthetic workarounds.
 *
 * AC: a plain left-click calls the onRowSelect handler (drawer opens);
 *     modified clicks (Ctrl, Meta, Shift) do NOT call onRowSelect and do NOT
 *     call preventDefault — native anchor behavior takes over.
 */
import { afterEach, describe, expect, it, vi } from 'vitest'
import { cleanup, fireEvent, render, screen, within } from '@testing-library/react'
import { MemoryRouter } from 'react-router'
import FleetTable from './FleetTable.tsx'
import type { Steward } from './columns.ts'
import { COLUMNS, DEFAULT_VISIBLE } from './columns.ts'

afterEach(cleanup)

const NOW_MS = Date.now()

function makeSteward(id: string, hostname = `host-${id}`): Steward {
  return {
    id,
    status: 'active',
    last_seen: new Date(NOW_MS - 10_000).toISOString(),
    version: 'v0.42',
    dna: { hostname, os: 'linux', architecture: 'amd64', attributes: {} },
  }
}

const defaultColumns = COLUMNS.filter((c) => (DEFAULT_VISIBLE as readonly string[]).includes(c.key))

function renderTable(
  stewards: Steward[],
  onRowSelect?: (s: Steward) => void,
) {
  return render(
    <MemoryRouter>
      <FleetTable
        stewards={stewards}
        columns={defaultColumns}
        sort={null}
        onSort={() => {}}
        nowMs={NOW_MS}
        onRowSelect={onRowSelect}
      />
    </MemoryRouter>,
  )
}

describe('row anchor (Story #2917 AC)', () => {
  it('each row contains an <a href="/stewards/:id"> anchor when onRowSelect is provided', () => {
    renderTable([makeSteward('stw-42', 'web-ingest-04')], vi.fn())

    const anchor = screen.getByRole('link', { name: 'web-ingest-04' })
    expect(anchor).toBeInTheDocument()
    expect(anchor.tagName).toBe('A')
    expect(anchor).toHaveAttribute('href', '/stewards/stw-42')
  })

  it('encodes special characters in the anchor href', () => {
    renderTable([makeSteward('stw/spec ial', 'host')], vi.fn())

    const anchor = screen.getByRole('link', { name: 'host' })
    expect(anchor).toHaveAttribute('href', '/stewards/stw%2Fspec%20ial')
  })

  it('plain left-click calls onRowSelect (drawer opens)', () => {
    const onRowSelect = vi.fn()
    renderTable([makeSteward('stw-1', 'myhost')], onRowSelect)

    const anchor = screen.getByRole('link', { name: 'myhost' })
    fireEvent.click(anchor, { button: 0 })

    expect(onRowSelect).toHaveBeenCalledTimes(1)
    expect(onRowSelect.mock.calls[0]?.[0].id).toBe('stw-1')
  })

  it('Ctrl+click does NOT call onRowSelect — native new-tab behavior', () => {
    const onRowSelect = vi.fn()
    renderTable([makeSteward('stw-2', 'myhost2')], onRowSelect)

    const anchor = screen.getByRole('link', { name: 'myhost2' })
    fireEvent.click(anchor, { ctrlKey: true, button: 0 })

    expect(onRowSelect).not.toHaveBeenCalled()
  })

  it('Meta+click (Cmd on Mac) does NOT call onRowSelect — native new-tab behavior', () => {
    const onRowSelect = vi.fn()
    renderTable([makeSteward('stw-3', 'myhost3')], onRowSelect)

    const anchor = screen.getByRole('link', { name: 'myhost3' })
    fireEvent.click(anchor, { metaKey: true, button: 0 })

    expect(onRowSelect).not.toHaveBeenCalled()
  })

  it('Shift+click does NOT call onRowSelect — native behavior', () => {
    const onRowSelect = vi.fn()
    renderTable([makeSteward('stw-4', 'myhost4')], onRowSelect)

    const anchor = screen.getByRole('link', { name: 'myhost4' })
    fireEvent.click(anchor, { shiftKey: true, button: 0 })

    expect(onRowSelect).not.toHaveBeenCalled()
  })

  it('clicking a non-name cell also calls onRowSelect (drawer opens)', () => {
    const onRowSelect = vi.fn()
    renderTable([makeSteward('stw-5', 'myhost5')], onRowSelect)

    const table = screen.getByRole('table')
    const rows = within(table).getAllByRole('row').slice(1)
    const firstRow = rows[0]
    if (!firstRow) throw new Error('expected data row')

    // Find a non-name cell and click it.
    const cells = within(firstRow).getAllByRole('cell')
    // Health or seen cell (not the first/name cell)
    const notNameCell = cells[1]
    if (!notNameCell) throw new Error('expected a second cell')
    fireEvent.click(notNameCell)

    expect(onRowSelect).toHaveBeenCalledTimes(1)
  })

  it('no anchor when onRowSelect is not provided', () => {
    renderTable([makeSteward('stw-6', 'noselect')])

    expect(screen.queryByRole('link')).not.toBeInTheDocument()
  })
})

describe('row action menu (Story #2938 AC)', () => {
  it('each interactive row has a kebab action button', () => {
    renderTable([makeSteward('stw-1', 'host1')], vi.fn())

    expect(screen.getByRole('button', { name: 'Actions' })).toBeInTheDocument()
  })

  it('no action button when table is not interactive (no onRowSelect)', () => {
    renderTable([makeSteward('stw-1', 'host1')])

    expect(screen.queryByRole('button', { name: 'Actions' })).not.toBeInTheDocument()
  })

  it('clicking the kebab does NOT call onRowSelect — navigation unchanged', () => {
    const onRowSelect = vi.fn()
    renderTable([makeSteward('stw-1', 'host1')], onRowSelect)

    fireEvent.click(screen.getByRole('button', { name: 'Actions' }))

    expect(onRowSelect).not.toHaveBeenCalled()
  })

  it('a direct row click still calls onRowSelect after kebab is present', () => {
    const onRowSelect = vi.fn()
    renderTable([makeSteward('stw-1', 'host1')], onRowSelect)

    fireEvent.click(screen.getByRole('link', { name: 'host1' }), { button: 0 })

    expect(onRowSelect).toHaveBeenCalledTimes(1)
    expect(onRowSelect.mock.calls[0]?.[0].id).toBe('stw-1')
  })
})
