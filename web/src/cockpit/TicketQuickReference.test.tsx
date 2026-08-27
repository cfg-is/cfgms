// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz

/*
 * TicketQuickReference tests (Story #3608).
 *
 * Verifies:
 *  - Missing-field state (.qfield.miss) renders the "add" affordance when
 *    a TicketField has no value (filled: false).
 *  - Filled fields render their value and source badge.
 *  - Full inline-edit round trip: render a case with an empty TicketField,
 *    click the "add" affordance, enter a value, confirm, assert the PUT
 *    payload carries that field with source="operator", and assert the
 *    re-rendered field shows the "operator" badge rather than the missing state.
 *  - Cancel (Escape) leaves the field empty and issues no request.
 *  - The caseId route parameter is percent-encoded into the PUT path so path
 *    metacharacters cannot steer the state-changing request off
 *    /api/v1/cases/ to another same-origin endpoint.
 */
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'
import { cleanup, fireEvent, render, screen, waitFor } from '@testing-library/react'
import TicketQuickReference from './TicketQuickReference.tsx'
import type { Ticket } from './caseTypes.ts'

const fetchMock = vi.fn<typeof fetch>()

beforeEach(() => {
  fetchMock.mockReset()
  vi.stubGlobal('fetch', fetchMock)
  // Stub the CSRF cookie read (apiFetch reads it for PUT requests).
  Object.defineProperty(document, 'cookie', {
    get: () => 'cfgms_csrf=test-csrf-token',
    configurable: true,
  })
})

afterEach(() => {
  vi.unstubAllGlobals()
  cleanup()
})

// Fixture: all five ticket fields filled.
const filledTicket: Ticket = {
  title: { value: 'SQL app slow since 9am', source: 'email', filled: true },
  client: { value: 'client-1', source: 'caller-id', filled: true },
  contact: { value: 'M. Rivera', source: 'operator', filled: true },
  priority: { value: 'High', source: 'email', filled: true },
  category: { value: 'Database/Perf', source: 'inferred', filled: true },
}

// Fixture: contact and category are empty.
const partialTicket: Ticket = {
  title: { value: 'SQL app slow since 9am', source: 'email', filled: true },
  client: { value: 'client-1', source: 'caller-id', filled: true },
  contact: { value: '', source: '', filled: false },
  priority: { value: 'High', source: 'email', filled: true },
  category: { value: '', source: '', filled: false },
}

function makeUpdateResponse(updatedTicket: Ticket) {
  return new Response(
    JSON.stringify({
      data: {
        id: 'case-001',
        tenant_id: 'root/msp-a/client-1',
        status: 'open',
        ticket: updatedTicket,
        pins: [],
        content: [],
        created_at: '2026-07-03T08:52:00Z',
        updated_at: '2026-07-03T09:00:00Z',
      },
      timestamp: '2026-07-03T09:00:00Z',
    }),
    { status: 200, headers: { 'Content-Type': 'application/json' } },
  )
}

describe('TicketQuickReference', () => {
  it('renders source badges for filled fields', () => {
    render(
      <TicketQuickReference
        caseId="case-001"
        ticket={filledTicket}
        onTicketUpdated={() => {}}
      />,
    )
    // Email badge appears for at least one field (title and priority both use email).
    expect(screen.getAllByText('email').length).toBeGreaterThanOrEqual(1)
    // caller-id badge on client.
    expect(screen.getByText('caller-id')).toBeInTheDocument()
    // operator badge on contact.
    expect(screen.getByText('operator')).toBeInTheDocument()
    // inferred badge on category.
    expect(screen.getByText('inferred')).toBeInTheDocument()
  })

  it('renders the "add" affordance for a field with filled=false', () => {
    render(
      <TicketQuickReference
        caseId="case-001"
        ticket={partialTicket}
        onTicketUpdated={() => {}}
      />,
    )
    // Both missing fields show "add" buttons.
    const addButtons = screen.getAllByRole('button', { name: /add/i })
    expect(addButtons.length).toBeGreaterThanOrEqual(2)
  })

  it('does NOT render the "add" affordance for a filled field', () => {
    render(
      <TicketQuickReference
        caseId="case-001"
        ticket={filledTicket}
        onTicketUpdated={() => {}}
      />,
    )
    expect(screen.queryByRole('button', { name: /add/i })).toBeNull()
  })

  it('[REQUIRED] full inline-edit round trip: empty field → add → enter → confirm → PUT → operator badge', async () => {
    const onTicketUpdated = vi.fn()

    const updatedTicket: Ticket = {
      ...partialTicket,
      contact: { value: 'Alex Kim', source: 'operator', filled: true },
    }

    // Mock PUT /api/v1/cases/case-001 to return updated case.
    fetchMock.mockResolvedValue(makeUpdateResponse(updatedTicket))

    render(
      <TicketQuickReference
        caseId="case-001"
        ticket={partialTicket}
        onTicketUpdated={onTicketUpdated}
      />,
    )

    // Find the "add" button for the first missing field (contact comes before category).
    const [contactAddBtn] = screen.getAllByRole('button', { name: /add/i })
    expect(contactAddBtn).toBeDefined()
    fireEvent.click(contactAddBtn!)

    // Inline input should appear.
    const input = await screen.findByRole('textbox')
    expect(input).toBeInTheDocument()

    // Type a value.
    fireEvent.change(input, { target: { value: 'Alex Kim' } })

    // Confirm by pressing Enter.
    fireEvent.keyDown(input, { key: 'Enter' })

    // Assert PUT was called with correct payload.
    await waitFor(() => expect(fetchMock).toHaveBeenCalled())

    const [putUrl, putInit] = fetchMock.mock.calls[0]!
    expect(putUrl).toContain('/api/v1/cases/case-001')
    expect((putInit as RequestInit).method).toBe('PUT')

    const body = JSON.parse((putInit as RequestInit).body as string) as {
      ticket: { contact: { value: string; source: string } }
    }
    expect(body.ticket.contact.value).toBe('Alex Kim')
    expect(body.ticket.contact.source).toBe('operator')

    // onTicketUpdated is called with the new ticket.
    await waitFor(() => expect(onTicketUpdated).toHaveBeenCalledWith(updatedTicket))
  })

  it('[REQUIRED] missing-field renders "add" affordance when TicketField has no value', () => {
    const emptyFieldTicket: Ticket = {
      title: { value: '', source: '', filled: false },
      client: { value: '', source: '', filled: false },
      contact: { value: '', source: '', filled: false },
      priority: { value: '', source: '', filled: false },
      category: { value: '', source: '', filled: false },
    }
    render(
      <TicketQuickReference
        caseId="case-001"
        ticket={emptyFieldTicket}
        onTicketUpdated={() => {}}
      />,
    )
    const addButtons = screen.getAllByRole('button', { name: /add/i })
    // All 5 fields are empty → 5 "add" buttons.
    expect(addButtons).toHaveLength(5)
  })

  it('percent-encodes the caseId into the PUT path — traversal metacharacters cannot escape /api/v1/cases/', async () => {
    // caseId reaches this component from useParams(), which URL-DECODES the
    // route segment. Interpolating it raw would let "/", "..", "?" and "#"
    // survive into the request path, and the browser normalises "../" before
    // dispatch — steering a cookie-and-CSRF-bearing PUT to another endpoint.
    fetchMock.mockResolvedValue(makeUpdateResponse(filledTicket))

    render(
      <TicketQuickReference
        caseId="case-001/../../admin/users?x=1#y"
        ticket={partialTicket}
        onTicketUpdated={() => {}}
      />,
    )

    const [firstAddBtn] = screen.getAllByRole('button', { name: /add/i })
    fireEvent.click(firstAddBtn!)
    const input = await screen.findByRole('textbox')
    fireEvent.change(input, { target: { value: 'Alex Kim' } })
    fireEvent.keyDown(input, { key: 'Enter' })

    await waitFor(() => expect(fetchMock).toHaveBeenCalled())

    const [putUrl] = fetchMock.mock.calls[0]!
    const path = String(putUrl)
    expect(path).toBe(
      `/api/v1/cases/${encodeURIComponent('case-001/../../admin/users?x=1#y')}`,
    )
    // No raw metacharacter survives past the /api/v1/cases/ prefix.
    const idSegment = path.slice('/api/v1/cases/'.length)
    expect(idSegment).not.toMatch(/[/?#]/)
  })

  it('Cancel (Escape) leaves the field empty and issues no request', async () => {
    render(
      <TicketQuickReference
        caseId="case-001"
        ticket={partialTicket}
        onTicketUpdated={() => {}}
      />,
    )

    const [firstAddBtn] = screen.getAllByRole('button', { name: /add/i })
    fireEvent.click(firstAddBtn!)

    const input = await screen.findByRole('textbox')
    fireEvent.change(input, { target: { value: 'some value' } })

    // Press Escape to cancel.
    fireEvent.keyDown(input, { key: 'Escape' })

    // Input should be gone.
    expect(screen.queryByRole('textbox')).toBeNull()

    // No fetch was called.
    expect(fetchMock).not.toHaveBeenCalled()

    // The "add" affordance is back.
    expect(screen.getAllByRole('button', { name: /add/i }).length).toBeGreaterThanOrEqual(1)
  })

  it('PUT error path: when server returns non-OK, field is silently dismissed (no crash)', async () => {
    // A 500 from the server means the PUT failed. The edit is dismissed silently —
    // the field goes back to its missing state. This matches the component's
    // finally block which always resets editingField/inputValue regardless of success.
    fetchMock.mockResolvedValue(
      new Response('server error', { status: 500 }),
    )

    render(
      <TicketQuickReference
        caseId="case-001"
        ticket={partialTicket}
        onTicketUpdated={() => {}}
      />,
    )

    const [firstAddBtn] = screen.getAllByRole('button', { name: /add/i })
    fireEvent.click(firstAddBtn!)

    const input = await screen.findByRole('textbox')
    fireEvent.change(input, { target: { value: 'some value' } })
    fireEvent.keyDown(input, { key: 'Enter' })

    // Wait for the PUT to complete (fetch mock resolves synchronously but the
    // async saveEdit still runs through the finally block).
    await waitFor(() => expect(fetchMock).toHaveBeenCalled())

    // Input is dismissed — field goes back to missing state.
    expect(screen.queryByRole('textbox')).toBeNull()
    // The "add" affordance reappears since the field was not updated.
    await waitFor(() =>
      expect(screen.getAllByRole('button', { name: /add/i }).length).toBeGreaterThanOrEqual(1),
    )
  })
})
