// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz

/*
 * CaseBar tests (Story #3608).
 *
 * Verifies:
 *  - Case ID renders as "CASE <id>".
 *  - Asset label is extracted from the first eid pin's EID last segment.
 *  - No asset label renders when no eid pin is present.
 *  - Tenant path renders with " / " separators.
 *  - Status "open" renders as warn-class pill.
 *  - Status "closed" renders as ok-class pill.
 *  - Unknown status renders as neu-class pill.
 */
import { afterEach, describe, expect, it } from 'vitest'
import { cleanup, render, screen } from '@testing-library/react'
import CaseBar from './CaseBar.tsx'
import type { Case } from './caseTypes.ts'

afterEach(() => {
  cleanup()
})

function makeCase(overrides: Partial<Case> = {}): Case {
  return {
    id: 'case-001',
    tenant_id: 'root/msp-a/client-1',
    status: 'open',
    ticket: {
      title: { value: '', source: '', filled: false },
      client: { value: '', source: '', filled: false },
      contact: { value: '', source: '', filled: false },
      priority: { value: '', source: '', filled: false },
      category: { value: '', source: '', filled: false },
    },
    pins: [
      {
        id: 'pin-001',
        case_id: 'case-001',
        ref: { kind: 'eid', eid: 'eid:root/msp-a/client-1/sql-primary' },
        annotation: '',
        author: 'operator',
        pinned_at: '2026-07-03T08:52:00Z',
      },
    ],
    content: [],
    created_at: '2026-07-03T08:52:00Z',
    updated_at: '2026-07-03T08:52:00Z',
    ...overrides,
  }
}

describe('CaseBar', () => {
  it('renders the case ID as "CASE <id>"', () => {
    render(<CaseBar caseData={makeCase()} />)
    expect(screen.getByText('CASE case-001')).toBeInTheDocument()
  })

  it('renders the asset label from the first eid pin last segment', () => {
    render(<CaseBar caseData={makeCase()} />)
    expect(screen.getByText('sql-primary')).toBeInTheDocument()
  })

  it('renders no asset label when the case has no pins at all', () => {
    const noPinsCase = makeCase({ pins: [] })
    const { container } = render(<CaseBar caseData={noPinsCase} />)
    expect(screen.queryByText('sql-primary')).toBeNull()
    expect(container.querySelector('.cid__asset')).toBeNull()
  })

  it('renders no asset label when pins exist but none are of kind "eid"', () => {
    const noEidCase = makeCase({
      pins: [
        {
          id: 'pin-drift',
          case_id: 'case-001',
          ref: { kind: 'drift-record', drift_record: 'drift-2291' },
          annotation: '',
          author: 'cfgms',
          pinned_at: '2026-07-03T08:52:00Z',
        },
      ],
    })
    const { container } = render(<CaseBar caseData={noEidCase} />)
    expect(container.querySelector('.cid__asset')).toBeNull()
  })

  it('skips non-eid pins and extracts the asset from the first eid pin', () => {
    const mixedCase = makeCase({
      pins: [
        {
          id: 'pin-drift',
          case_id: 'case-001',
          ref: { kind: 'drift-record', drift_record: 'drift-2291' },
          annotation: '',
          author: 'cfgms',
          pinned_at: '2026-07-03T08:52:00Z',
        },
        {
          id: 'pin-eid-a',
          case_id: 'case-001',
          ref: { kind: 'eid', eid: 'eid:root/msp-a/client-1/sql-primary' },
          annotation: '',
          author: 'operator',
          pinned_at: '2026-07-03T08:53:00Z',
        },
        {
          id: 'pin-eid-b',
          case_id: 'case-001',
          ref: { kind: 'eid', eid: 'eid:root/msp-a/client-1/web-frontend' },
          annotation: '',
          author: 'operator',
          pinned_at: '2026-07-03T08:54:00Z',
        },
      ],
    })
    render(<CaseBar caseData={mixedCase} />)
    // First eid pin wins; the later one is not rendered.
    expect(screen.getByText('sql-primary')).toBeInTheDocument()
    expect(screen.queryByText('web-frontend')).toBeNull()
  })

  it('renders no asset label when an eid pin carries an empty eid string', () => {
    const emptyEidCase = makeCase({
      pins: [
        {
          id: 'pin-empty',
          case_id: 'case-001',
          ref: { kind: 'eid', eid: '' },
          annotation: '',
          author: 'operator',
          pinned_at: '2026-07-03T08:52:00Z',
        },
      ],
    })
    const { container } = render(<CaseBar caseData={emptyEidCase} />)
    expect(container.querySelector('.cid__asset')).toBeNull()
  })

  it('renders the tenant path with " / " separators', () => {
    render(<CaseBar caseData={makeCase()} />)
    expect(screen.getByText('root / msp-a / client-1')).toBeInTheDocument()
  })

  it('renders an open status pill with warn styling', () => {
    render(<CaseBar caseData={makeCase({ status: 'open' })} />)
    const pill = screen.getByText('Open').closest('.pill')
    expect(pill).toHaveClass('pill--warn')
  })

  it('renders a closed status pill with ok styling', () => {
    render(<CaseBar caseData={makeCase({ status: 'closed' })} />)
    const pill = screen.getByText('Closed').closest('.pill')
    expect(pill).toHaveClass('pill--ok')
  })

  it('renders an unknown status with neutral styling', () => {
    render(<CaseBar caseData={makeCase({ status: 'pending' })} />)
    const pill = screen.getByText('pending').closest('.pill')
    expect(pill).toHaveClass('pill--neu')
  })

  it('extracts the correct asset from a deeply nested EID path', () => {
    const deepCase = makeCase({
      pins: [
        {
          id: 'pin-deep',
          case_id: 'case-001',
          ref: { kind: 'eid', eid: 'eid:root/msp-a/client-1/servers/db-01' },
          annotation: '',
          author: 'operator',
          pinned_at: '2026-07-03T08:52:00Z',
        },
      ],
    })
    render(<CaseBar caseData={deepCase} />)
    expect(screen.getByText('db-01')).toBeInTheDocument()
  })
})
