// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz

/*
 * Tests for RemediationCard (Story #3612).
 *
 * Fixture pin shapes are drawn from handlers_cases.go pinResponse/pinRefResponse
 * (Issue #3605), the same fixtures DriftDiffCard.test.tsx uses. API response
 * shapes mirror the Go structs serialised by writeEntityJSON / respondJSON:
 *   EntityView → pkg/entitygraph/types/entity.go (handlers_entities.go handleGetEntity)
 *   DriftState → pkg/entitygraph/interfaces/provider.go (handleGetDriftState)
 * Both structs lack json tags, so field names are PascalCase in the JSON response.
 *
 * fetch is stubbed globally per test; stubs are restored in afterEach.
 */
import { describe, expect, it, vi, afterEach } from 'vitest'
import { render, screen, waitFor, fireEvent } from '@testing-library/react'
import RemediationCard from './RemediationCard.tsx'
import type { Pin } from '../evidenceTypes.ts'

// ── Fixture data ──────────────────────────────────────────────────────────────

const MOCK_ENTITY_HOST = {
  Entity: {
    EID: 'eid:root/msp-a/client-1/sql-primary',
    Kind: 'host',
    OwningTenant: 'root/msp-a/client-1',
  },
}

const MOCK_ENTITY_CLUSTER = {
  Entity: {
    EID: 'eid:root/msp-a/client-1/sql-cluster',
    Kind: 'cluster',
    OwningTenant: 'root/msp-a/client-1',
  },
}

const MOCK_DRIFT_ACTIVE = {
  EID: 'eid:root/msp-a/client-1/sql-primary',
  Fields: [
    { Attribute: 'max_server_memory', Matching: false },
    { Attribute: 'max_worker_threads', Matching: true },
  ],
  ConfigRevision: 'r2291',
  LifecycleStatus: 'detected',
}

const MOCK_DRIFT_RESOLVED = {
  EID: 'eid:root/msp-a/client-1/sql-primary',
  Fields: [
    { Attribute: 'max_server_memory', Matching: true },
    { Attribute: 'max_worker_threads', Matching: true },
  ],
  ConfigRevision: 'r2291',
  LifecycleStatus: 'resolved',
}

// Pins drawn from handlers_cases.go pinResponse/pinRefResponse shapes (Issue #3605),
// same fixtures as DriftDiffCard.test.tsx.
const pinDriftRecord: Pin = {
  id: 'pin-drift-001',
  case_id: 'case-001',
  ref: { kind: 'drift-record', drift_record: 'drift:r2291:sql-primary:memory' },
  annotation: 'Memory section of r2291 failed to apply',
  author: 'cfgms',
  pinned_at: '2026-07-03T08:44:00Z',
}

const pinEID: Pin = {
  id: 'pin-eid-001',
  case_id: 'case-001',
  ref: { kind: 'eid', eid: 'eid:root/msp-a/client-1/sql-primary' },
  annotation: 'Primary entity under investigation',
  author: 'operator',
  pinned_at: '2026-07-03T08:52:00Z',
}

const pinEIDCluster: Pin = {
  id: 'pin-eid-002',
  case_id: 'case-001',
  ref: { kind: 'eid', eid: 'eid:root/msp-a/client-1/sql-cluster' },
  annotation: 'Cluster under investigation',
  author: 'operator',
  pinned_at: '2026-07-03T08:52:00Z',
}

const pinEdgeIdentity: Pin = {
  id: 'pin-edge-001',
  case_id: 'case-001',
  ref: { kind: 'edge-identity', edge_identity: 'edge:sql-primary->api-02' },
  annotation: 'Dependent at ×4 latency',
  author: 'cfgms',
  pinned_at: '2026-07-03T08:50:00Z',
}

// Authority names that carry a fleet-selector separator. ParseEID forbids only
// '/' in the authority-name segment, so each of these reaches the card intact:
//   ','  → pkg/fleet/selector/selector.go splits an `id:` value into an OR set,
//          fanning a "1 host" plan out across several stewards
//   ' '  → terminates the unquoted `id:` term, so the remainder parses as an
//          additional selector term (here a tag: match over the whole fleet)
const pinEIDCommaAuthority: Pin = {
  id: 'pin-eid-003',
  case_id: 'case-001',
  ref: { kind: 'eid', eid: 'eid:root,other/msp-a/client-1/sql-primary' },
  annotation: 'Authority name carrying a selector OR separator',
  author: 'operator',
  pinned_at: '2026-07-03T08:52:00Z',
}

const pinEIDSpaceAuthority: Pin = {
  id: 'pin-eid-004',
  case_id: 'case-001',
  ref: { kind: 'eid', eid: 'eid:root tag:prod/msp-a/client-1/sql-primary' },
  annotation: 'Authority name carrying a selector term separator',
  author: 'operator',
  pinned_at: '2026-07-03T08:52:00Z',
}

afterEach(() => {
  vi.unstubAllGlobals()
})

// ── Tests ─────────────────────────────────────────────────────────────────────

describe('RemediationCard', () => {
  it('renders nothing when no eid-resolvable pin is present', () => {
    render(<RemediationCard pins={[pinEdgeIdentity]} />)
    expect(document.querySelector('.remediation-card')).toBeNull()
  })

  it('shows a loading state while fetching', () => {
    vi.stubGlobal('fetch', vi.fn(() => new Promise(() => {})))
    render(<RemediationCard pins={[pinEID]} />)
    expect(screen.getByText('Loading…')).toBeInTheDocument()
  })

  // ── REQUIRED TEST (AC5) ───────────────────────────────────────────────────
  it('[REQUIRED] Approve & run issues config-push with the correct entity/module payload for a host-kind pin', async () => {
    // Routes /entities/{eid} (entity Kind lookup), /entities/{eid}/drift (active-drift
    // check), and /api/v1/config/push (the button's action) each to their own fixture.
    const preciseFetch = vi.fn((url: string) => {
      const path = typeof url === 'string' ? url : ''
      if (path.endsWith('/drift')) {
        return Promise.resolve({
          ok: true,
          status: 200,
          headers: new Headers(),
          json: () => Promise.resolve(MOCK_DRIFT_ACTIVE),
        })
      }
      if (path.includes('/entities/')) {
        return Promise.resolve({
          ok: true,
          status: 200,
          headers: new Headers(),
          json: () => Promise.resolve(MOCK_ENTITY_HOST),
        })
      }
      if (path === '/api/v1/config/push') {
        return Promise.resolve({
          ok: true,
          status: 202,
          headers: new Headers(),
          json: () => Promise.resolve({ push_id: 'push-1', status: 'in_progress', queued_at: '2026-07-03T09:00:00Z' }),
        })
      }
      return Promise.resolve({
        ok: false,
        status: 404,
        headers: new Headers(),
        json: () => Promise.reject(new Error('404')),
      })
    })
    vi.stubGlobal('fetch', preciseFetch)

    render(<RemediationCard pins={[pinDriftRecord, pinEID]} />)

    await waitFor(() => {
      expect(screen.getByRole('button', { name: /approve & run/i })).toBeInTheDocument()
    })

    // Plan facts derived from data: module parsed from the drift-record pin ref.
    expect(screen.getByText(/module: memory/i)).toBeInTheDocument()

    fireEvent.click(screen.getByRole('button', { name: /approve & run/i }))

    await waitFor(() => {
      const pushCall = preciseFetch.mock.calls.find((c) => c[0] === '/api/v1/config/push')
      expect(pushCall).toBeDefined()
    })

    const pushCall = preciseFetch.mock.calls.find((c) => c[0] === '/api/v1/config/push')
    const body = JSON.parse(((pushCall as unknown as [string, RequestInit])[1]).body as string)
    expect(body.selector).toBe('id:root')
    expect(body.config_id).toBe('memory')
    expect(body.version).toBe('r2291')
    expect(body.tenant_id).toBe('root/msp-a/client-1')
    expect(body.modules).toEqual(['memory'])

    // Neither the rollback-preview endpoint nor a second push call happened.
    expect(preciseFetch.mock.calls.some((c) => c[0] === '/api/v1/rollback/preview')).toBe(false)

    await waitFor(() => {
      expect(screen.getByText('applied')).toBeInTheDocument()
    })
  })

  // ── REQUIRED TEST (AC5) ───────────────────────────────────────────────────
  it('[REQUIRED] renders no-remediation-available for a non-host/device-kind pin without calling push or rollback-preview', async () => {
    const fetchStub = vi.fn((url: string) => {
      const path = typeof url === 'string' ? url : ''
      if (path.includes('/entities/') && !path.endsWith('/drift')) {
        return Promise.resolve({
          ok: true,
          status: 200,
          headers: new Headers(),
          json: () => Promise.resolve(MOCK_ENTITY_CLUSTER),
        })
      }
      return Promise.resolve({
        ok: false,
        status: 404,
        headers: new Headers(),
        json: () => Promise.reject(new Error('404')),
      })
    })
    vi.stubGlobal('fetch', fetchStub)

    render(<RemediationCard pins={[pinEIDCluster]} />)

    await waitFor(() => {
      expect(screen.getByText(/no remediation available/i)).toBeInTheDocument()
    })

    // Only the entity lookup happened — no drift fetch, no push, no rollback-preview.
    expect(fetchStub.mock.calls.some((c) => String(c[0]).endsWith('/drift'))).toBe(false)
    expect(fetchStub.mock.calls.some((c) => c[0] === '/api/v1/config/push')).toBe(false)
    expect(fetchStub.mock.calls.some((c) => c[0] === '/api/v1/rollback/preview')).toBe(false)

    // No action buttons rendered in the no-remediation-available state.
    expect(screen.queryByRole('button', { name: /approve & run/i })).toBeNull()
    expect(screen.queryByRole('button', { name: /preview diff/i })).toBeNull()
  })

  it('renders no-remediation-available when the host-kind pin has no active drift (resolved)', async () => {
    const fetchStub = vi.fn((url: string) => {
      const path = typeof url === 'string' ? url : ''
      if (path.endsWith('/drift')) {
        return Promise.resolve({
          ok: true,
          status: 200,
          headers: new Headers(),
          json: () => Promise.resolve(MOCK_DRIFT_RESOLVED),
        })
      }
      if (path.includes('/entities/')) {
        return Promise.resolve({
          ok: true,
          status: 200,
          headers: new Headers(),
          json: () => Promise.resolve(MOCK_ENTITY_HOST),
        })
      }
      return Promise.resolve({
        ok: false,
        status: 404,
        headers: new Headers(),
        json: () => Promise.reject(new Error('404')),
      })
    })
    vi.stubGlobal('fetch', fetchStub)

    render(<RemediationCard pins={[pinEID]} />)

    await waitFor(() => {
      expect(screen.getByText(/no remediation available/i)).toBeInTheDocument()
    })
    expect(fetchStub.mock.calls.some((c) => c[0] === '/api/v1/config/push')).toBe(false)
  })

  it('renders no-remediation-available when the drift endpoint 404s (no drift record)', async () => {
    const fetchStub = vi.fn((url: string) => {
      const path = typeof url === 'string' ? url : ''
      if (path.endsWith('/drift')) {
        return Promise.resolve({
          ok: false,
          status: 404,
          headers: new Headers(),
          json: () => Promise.reject(new Error('404')),
        })
      }
      if (path.includes('/entities/')) {
        return Promise.resolve({
          ok: true,
          status: 200,
          headers: new Headers(),
          json: () => Promise.resolve(MOCK_ENTITY_HOST),
        })
      }
      return Promise.resolve({
        ok: false,
        status: 404,
        headers: new Headers(),
        json: () => Promise.reject(new Error('404')),
      })
    })
    vi.stubGlobal('fetch', fetchStub)

    render(<RemediationCard pins={[pinEID]} />)

    await waitFor(() => {
      expect(screen.getByText(/no remediation available/i)).toBeInTheDocument()
    })
  })

  it('Preview diff calls the rollback-preview endpoint with the device target mapping', async () => {
    const fetchStub = vi.fn((url: string) => {
      const path = typeof url === 'string' ? url : ''
      if (path.endsWith('/drift')) {
        return Promise.resolve({
          ok: true,
          status: 200,
          headers: new Headers(),
          json: () => Promise.resolve(MOCK_DRIFT_ACTIVE),
        })
      }
      if (path.includes('/entities/')) {
        return Promise.resolve({
          ok: true,
          status: 200,
          headers: new Headers(),
          json: () => Promise.resolve(MOCK_ENTITY_HOST),
        })
      }
      if (path === '/api/v1/rollback/preview') {
        return Promise.resolve({
          ok: true,
          status: 200,
          headers: new Headers(),
          json: () =>
            Promise.resolve({
              preview: {
                changes: [
                  { path: 'mssql/memory.conf', diff: '-max_server_memory 2048\n+max_server_memory 12288' },
                ],
              },
            }),
        })
      }
      return Promise.resolve({
        ok: false,
        status: 404,
        headers: new Headers(),
        json: () => Promise.reject(new Error('404')),
      })
    })
    vi.stubGlobal('fetch', fetchStub)

    render(<RemediationCard pins={[pinDriftRecord, pinEID]} />)

    await waitFor(() => {
      expect(screen.getByRole('button', { name: /preview diff/i })).toBeInTheDocument()
    })

    fireEvent.click(screen.getByRole('button', { name: /preview diff/i }))

    await waitFor(() => {
      const call = fetchStub.mock.calls.find((c) => c[0] === '/api/v1/rollback/preview')
      expect(call).toBeDefined()
    })

    const call = fetchStub.mock.calls.find((c) => c[0] === '/api/v1/rollback/preview')
    const body = JSON.parse(((call as unknown as [string, RequestInit])[1]).body as string)
    expect(body.target_type).toBe('device')
    expect(body.target_id).toBe('root')
    expect(body.modules).toEqual(['memory'])

    await waitFor(() => {
      expect(screen.getByText(/max_server_memory 12288/)).toBeInTheDocument()
    })
  })

  it.each([
    ['comma (selector OR separator)', pinEIDCommaAuthority],
    ['space (selector term separator)', pinEIDSpaceAuthority],
  ])(
    'renders no-remediation-available when the authority name contains a %s, without calling push or rollback-preview',
    async (_label, pin) => {
      const fetchStub = vi.fn((url: string) => {
        const path = typeof url === 'string' ? url : ''
        if (path.endsWith('/drift')) {
          return Promise.resolve({
            ok: true,
            status: 200,
            headers: new Headers(),
            json: () => Promise.resolve(MOCK_DRIFT_ACTIVE),
          })
        }
        if (path.includes('/entities/')) {
          return Promise.resolve({
            ok: true,
            status: 200,
            headers: new Headers(),
            json: () => Promise.resolve(MOCK_ENTITY_HOST),
          })
        }
        return Promise.resolve({
          ok: false,
          status: 404,
          headers: new Headers(),
          json: () => Promise.reject(new Error('404')),
        })
      })
      vi.stubGlobal('fetch', fetchStub)

      render(<RemediationCard pins={[pinDriftRecord, pin]} />)

      await waitFor(() => {
        expect(screen.getByText(/no remediation available/i)).toBeInTheDocument()
      })

      // Fails closed before any further endpoint is touched: the entity lookup
      // is the only call, and no plan (hence no action button) is ever staged.
      expect(fetchStub.mock.calls.some((c) => String(c[0]).endsWith('/drift'))).toBe(false)
      expect(fetchStub.mock.calls.some((c) => c[0] === '/api/v1/config/push')).toBe(false)
      expect(fetchStub.mock.calls.some((c) => c[0] === '/api/v1/rollback/preview')).toBe(false)
      expect(screen.queryByRole('button', { name: /approve & run/i })).toBeNull()
      expect(screen.queryByRole('button', { name: /preview diff/i })).toBeNull()
    },
  )

  it('shows a failure message when Approve & run fails', async () => {
    const fetchStub = vi.fn((url: string) => {
      const path = typeof url === 'string' ? url : ''
      if (path.endsWith('/drift')) {
        return Promise.resolve({
          ok: true,
          status: 200,
          headers: new Headers(),
          json: () => Promise.resolve(MOCK_DRIFT_ACTIVE),
        })
      }
      if (path.includes('/entities/')) {
        return Promise.resolve({
          ok: true,
          status: 200,
          headers: new Headers(),
          json: () => Promise.resolve(MOCK_ENTITY_HOST),
        })
      }
      if (path === '/api/v1/config/push') {
        return Promise.resolve({
          ok: false,
          status: 503,
          headers: new Headers(),
          json: () => Promise.resolve({ error: 'not the leader' }),
        })
      }
      return Promise.resolve({
        ok: false,
        status: 404,
        headers: new Headers(),
        json: () => Promise.reject(new Error('404')),
      })
    })
    vi.stubGlobal('fetch', fetchStub)

    render(<RemediationCard pins={[pinDriftRecord, pinEID]} />)

    await waitFor(() => {
      expect(screen.getByRole('button', { name: /approve & run/i })).toBeInTheDocument()
    })
    fireEvent.click(screen.getByRole('button', { name: /approve & run/i }))

    await waitFor(() => {
      expect(screen.getByText('not the leader')).toBeInTheDocument()
    })
    expect(screen.getByText('failed')).toBeInTheDocument()
  })
})
