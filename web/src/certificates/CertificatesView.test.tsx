// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz

/*
 * CertificatesView test suite (Issue #3135):
 * list rendering, data states, expiry visual states, provision form,
 * revoke confirm modal, and CA rotation modal (type-to-confirm).
 */
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'
import { cleanup, fireEvent, render, screen, waitFor } from '@testing-library/react'
import { MemoryRouter } from 'react-router'
import { AuthProvider } from '../auth/AuthContext.tsx'
import CertificatesView from './CertificatesView.tsx'

const fetchMock = vi.fn<typeof fetch>()

beforeEach(() => {
  vi.stubGlobal('fetch', fetchMock)
  fetchMock.mockReset()
})

afterEach(() => {
  vi.unstubAllGlobals()
  cleanup()
})

function makeCertResponse(certs: object[], status = 200) {
  return new Response(
    JSON.stringify({ data: certs }),
    { status, headers: { 'Content-Type': 'application/json' } },
  )
}

function makeCert(overrides: Partial<Record<string, unknown>> = {}) {
  return {
    serial_number: '7f:3a:9c:01',
    common_name: 'dc-01.acme-corp',
    steward_id: 'steward-abc',
    is_valid: true,
    expires_at: '2027-01-14T00:00:00Z',
    days_until_expiration: 168,
    needs_renewal: false,
    ...overrides,
  }
}

function renderCertificatesView() {
  return render(
    <MemoryRouter>
      <AuthProvider>
        <CertificatesView />
      </AuthProvider>
    </MemoryRouter>,
  )
}

// ── Page structure ────────────────────────────────────────────────────────────

describe('CertificatesView — page structure', () => {
  it('shows the Certificates heading', () => {
    fetchMock.mockReturnValue(new Promise(() => {}))
    renderCertificatesView()
    expect(screen.getByRole('heading', { name: /certificates/i, level: 1 })).toBeInTheDocument()
  })

  it('shows Provision certificate button', () => {
    fetchMock.mockReturnValue(new Promise(() => {}))
    renderCertificatesView()
    expect(screen.getByTestId('toggle-provision-btn')).toBeInTheDocument()
  })

  it('shows Rotate signing CA button', () => {
    fetchMock.mockReturnValue(new Promise(() => {}))
    renderCertificatesView()
    expect(screen.getByTestId('rotate-ca-btn')).toBeInTheDocument()
  })
})

// ── Data states ───────────────────────────────────────────────────────────────

describe('CertificatesView — data states', () => {
  it('shows loading state while fetching', () => {
    fetchMock.mockReturnValue(new Promise(() => {}))
    renderCertificatesView()
    expect(screen.getByTestId('certs-loading')).toBeInTheDocument()
  })

  it('shows empty state when no certificates returned', async () => {
    fetchMock.mockResolvedValue(makeCertResponse([]))
    renderCertificatesView()
    await waitFor(() => {
      expect(screen.getByTestId('certs-empty')).toBeInTheDocument()
    })
  })

  it('renders certificate rows in a table', async () => {
    fetchMock.mockResolvedValue(
      makeCertResponse([
        makeCert({ serial_number: 'aa:01', common_name: 'host-a.corp' }),
        makeCert({ serial_number: 'bb:02', common_name: 'host-b.corp' }),
      ]),
    )
    renderCertificatesView()
    await waitFor(() => {
      expect(screen.getByTestId('certs-table')).toBeInTheDocument()
    })
    expect(screen.getAllByTestId('cert-row')).toHaveLength(2)
    expect(screen.getByText('host-a.corp')).toBeInTheDocument()
    expect(screen.getByText('host-b.corp')).toBeInTheDocument()
  })

  it('shows certificate count', async () => {
    fetchMock.mockResolvedValue(makeCertResponse([makeCert()]))
    renderCertificatesView()
    await waitFor(() => {
      expect(screen.getByTestId('cert-count')).toHaveTextContent('1 certificate')
    })
  })

  it('shows plural count for multiple certificates', async () => {
    fetchMock.mockResolvedValue(
      makeCertResponse([makeCert(), makeCert({ serial_number: 'bb:02' })]),
    )
    renderCertificatesView()
    await waitFor(() => {
      expect(screen.getByTestId('cert-count')).toHaveTextContent('2 certificates')
    })
  })

  it('shows error state on fetch failure', async () => {
    fetchMock.mockResolvedValue(makeCertResponse([], 500))
    renderCertificatesView()
    await waitFor(() => {
      expect(screen.getByRole('alert')).toBeInTheDocument()
      expect(screen.getByText(/couldn't load certificates/i)).toBeInTheDocument()
    })
  })
})

// ── Expiry visual states ──────────────────────────────────────────────────────

describe('CertificatesView — expiry visual states', () => {
  it('shows normal days cell for cert with >30 days remaining', async () => {
    fetchMock.mockResolvedValue(
      makeCertResponse([makeCert({ days_until_expiration: 168, is_valid: true })]),
    )
    renderCertificatesView()
    await waitFor(() => expect(screen.getByTestId('cert-row')).toBeInTheDocument())
    const daysEl = screen.getByTestId('cert-days')
    expect(daysEl).toHaveTextContent('168d left')
    expect(daysEl).not.toHaveClass('warn')
    expect(daysEl).not.toHaveClass('crit')
  })

  it('shows amber/warn days cell for cert with 8–30 days remaining', async () => {
    fetchMock.mockResolvedValue(
      makeCertResponse([makeCert({ days_until_expiration: 17, is_valid: true })]),
    )
    renderCertificatesView()
    await waitFor(() => expect(screen.getByTestId('cert-row')).toBeInTheDocument())
    const daysEl = screen.getByTestId('cert-days')
    expect(daysEl).toHaveTextContent('17d left')
    expect(daysEl).toHaveClass('warn')
  })

  it('shows red/crit days cell for cert with ≤7 days remaining', async () => {
    fetchMock.mockResolvedValue(
      makeCertResponse([makeCert({ days_until_expiration: 7, is_valid: true })]),
    )
    renderCertificatesView()
    await waitFor(() => expect(screen.getByTestId('cert-row')).toBeInTheDocument())
    const daysEl = screen.getByTestId('cert-days')
    expect(daysEl).toHaveTextContent('7d left')
    expect(daysEl).toHaveClass('crit')
  })

  it('shows no days cell for expired cert', async () => {
    fetchMock.mockResolvedValue(
      makeCertResponse([makeCert({ days_until_expiration: -1, is_valid: false })]),
    )
    renderCertificatesView()
    await waitFor(() => expect(screen.getByTestId('cert-row')).toBeInTheDocument())
    expect(screen.queryByTestId('cert-days')).not.toBeInTheDocument()
  })

  it('shows no days cell for revoked cert', async () => {
    fetchMock.mockResolvedValue(
      makeCertResponse([makeCert({ days_until_expiration: 10, is_valid: false })]),
    )
    renderCertificatesView()
    await waitFor(() => expect(screen.getByTestId('cert-row')).toBeInTheDocument())
    expect(screen.queryByTestId('cert-days')).not.toBeInTheDocument()
  })
})

// ── Status pills ──────────────────────────────────────────────────────────────

describe('CertificatesView — status pills', () => {
  it('shows ok pill for valid cert >30 days', async () => {
    fetchMock.mockResolvedValue(
      makeCertResponse([makeCert({ days_until_expiration: 168, is_valid: true })]),
    )
    renderCertificatesView()
    await waitFor(() => expect(screen.getByTestId('cert-status-pill')).toBeInTheDocument())
    const pill = screen.getByTestId('cert-status-pill')
    expect(pill).toHaveClass('ok')
    expect(pill).toHaveTextContent('Valid')
  })

  it('shows warn pill for valid cert 8–30 days', async () => {
    fetchMock.mockResolvedValue(
      makeCertResponse([makeCert({ days_until_expiration: 17, is_valid: true })]),
    )
    renderCertificatesView()
    await waitFor(() => expect(screen.getByTestId('cert-status-pill')).toBeInTheDocument())
    const pill = screen.getByTestId('cert-status-pill')
    expect(pill).toHaveClass('warn')
    expect(pill).toHaveTextContent('Valid')
  })

  it('shows crit pill for valid cert ≤7 days', async () => {
    fetchMock.mockResolvedValue(
      makeCertResponse([makeCert({ days_until_expiration: 5, is_valid: true })]),
    )
    renderCertificatesView()
    await waitFor(() => expect(screen.getByTestId('cert-status-pill')).toBeInTheDocument())
    const pill = screen.getByTestId('cert-status-pill')
    expect(pill).toHaveClass('crit')
    expect(pill).toHaveTextContent('Valid')
  })

  it('shows Expired crit pill for expired cert (is_valid=false, days<0)', async () => {
    fetchMock.mockResolvedValue(
      makeCertResponse([makeCert({ days_until_expiration: -1, is_valid: false })]),
    )
    renderCertificatesView()
    await waitFor(() => expect(screen.getByTestId('cert-status-pill')).toBeInTheDocument())
    const pill = screen.getByTestId('cert-status-pill')
    expect(pill).toHaveClass('crit')
    expect(pill).toHaveTextContent('Expired')
  })

  it('shows Revoked neutral pill for revoked cert (is_valid=false, days>=0)', async () => {
    fetchMock.mockResolvedValue(
      makeCertResponse([makeCert({ days_until_expiration: 10, is_valid: false })]),
    )
    renderCertificatesView()
    await waitFor(() => expect(screen.getByTestId('cert-status-pill')).toBeInTheDocument())
    const pill = screen.getByTestId('cert-status-pill')
    expect(pill).toHaveClass('neutral')
    expect(pill).toHaveTextContent('Revoked')
  })
})

// ── Revoke button visibility ──────────────────────────────────────────────────

describe('CertificatesView — revoke button visibility', () => {
  it('shows enabled Revoke button for valid cert', async () => {
    fetchMock.mockResolvedValue(
      makeCertResponse([makeCert({ is_valid: true, days_until_expiration: 168 })]),
    )
    renderCertificatesView()
    await waitFor(() => expect(screen.getByTestId('cert-row')).toBeInTheDocument())
    expect(screen.getByTestId('cert-revoke-btn')).toBeInTheDocument()
    expect(screen.getByTestId('cert-revoke-btn')).not.toBeDisabled()
  })

  it('shows disabled Revoke button for expired cert', async () => {
    fetchMock.mockResolvedValue(
      makeCertResponse([makeCert({ is_valid: false, days_until_expiration: -1 })]),
    )
    renderCertificatesView()
    await waitFor(() => expect(screen.getByTestId('cert-row')).toBeInTheDocument())
    expect(screen.getByTestId('cert-revoke-btn-disabled')).toBeDisabled()
  })

  it('shows disabled Revoke button for revoked cert', async () => {
    fetchMock.mockResolvedValue(
      makeCertResponse([makeCert({ is_valid: false, days_until_expiration: 10 })]),
    )
    renderCertificatesView()
    await waitFor(() => expect(screen.getByTestId('cert-row')).toBeInTheDocument())
    expect(screen.getByTestId('cert-revoke-btn-disabled')).toBeDisabled()
  })
})

// ── Provision form ────────────────────────────────────────────────────────────

describe('CertificatesView — provision form', () => {
  it('opens the provision panel when Provision certificate is clicked', async () => {
    fetchMock.mockResolvedValue(makeCertResponse([]))
    renderCertificatesView()
    await waitFor(() => expect(screen.getByTestId('toggle-provision-btn')).toBeInTheDocument())
    fireEvent.click(screen.getByTestId('toggle-provision-btn'))
    expect(screen.getByTestId('provision-panel')).toBeInTheDocument()
  })

  it('closes the provision panel when Close is clicked', async () => {
    fetchMock.mockResolvedValue(makeCertResponse([]))
    renderCertificatesView()
    await waitFor(() => expect(screen.getByTestId('toggle-provision-btn')).toBeInTheDocument())
    fireEvent.click(screen.getByTestId('toggle-provision-btn'))
    expect(screen.getByTestId('provision-panel')).toBeInTheDocument()
    fireEvent.click(screen.getByTestId('toggle-provision-btn'))
    expect(screen.queryByTestId('provision-panel')).not.toBeInTheDocument()
  })

  it('shows error when Steward ID is empty on submit', async () => {
    fetchMock.mockResolvedValue(makeCertResponse([]))
    renderCertificatesView()
    await waitFor(() => expect(screen.getByTestId('toggle-provision-btn')).toBeInTheDocument())
    fireEvent.click(screen.getByTestId('toggle-provision-btn'))
    fireEvent.click(screen.getByTestId('provision-save-btn'))
    expect(screen.getByTestId('provision-error')).toHaveTextContent('Steward ID is required')
  })

  it('calls provision API and closes panel on success', async () => {
    fetchMock
      .mockResolvedValueOnce(makeCertResponse([]))
      .mockResolvedValueOnce(
        new Response(
          JSON.stringify({
            data: {
              certificate_pem: '-----BEGIN CERTIFICATE-----\n...\n-----END CERTIFICATE-----\n',
              private_key_pem: '-----BEGIN EC PRIVATE KEY-----\n...\n-----END EC PRIVATE KEY-----\n',
              ca_certificate_pem: '-----BEGIN CERTIFICATE-----\n...\n-----END CERTIFICATE-----\n',
              serial_number: 'aa:bb:cc',
              expires_at: '2027-07-30T00:00:00Z',
            },
          }),
          { status: 201, headers: { 'Content-Type': 'application/json' } },
        ),
      )
      .mockResolvedValueOnce(makeCertResponse([]))
    renderCertificatesView()
    await waitFor(() => expect(screen.getByTestId('toggle-provision-btn')).toBeInTheDocument())
    fireEvent.click(screen.getByTestId('toggle-provision-btn'))
    fireEvent.change(screen.getByTestId('provision-steward-input'), {
      target: { value: 'new-host.corp' },
    })
    fireEvent.click(screen.getByTestId('provision-save-btn'))
    await waitFor(() => {
      expect(screen.queryByTestId('provision-panel')).not.toBeInTheDocument()
    })
  })

  it('shows error when provision API fails', async () => {
    fetchMock
      .mockResolvedValueOnce(makeCertResponse([]))
      .mockResolvedValueOnce(
        new Response(
          JSON.stringify({ error: { message: 'Steward ID is required', code: 'MISSING_STEWARD_ID' } }),
          { status: 400, headers: { 'Content-Type': 'application/json' } },
        ),
      )
    renderCertificatesView()
    await waitFor(() => expect(screen.getByTestId('toggle-provision-btn')).toBeInTheDocument())
    fireEvent.click(screen.getByTestId('toggle-provision-btn'))
    fireEvent.change(screen.getByTestId('provision-steward-input'), {
      target: { value: 'bad-host' },
    })
    fireEvent.click(screen.getByTestId('provision-save-btn'))
    await waitFor(() => {
      expect(screen.getByTestId('provision-error')).toHaveTextContent('Steward ID is required')
    })
  })
})

// ── Revoke confirm modal ──────────────────────────────────────────────────────

describe('CertificatesView — revoke confirm modal', () => {
  it('opens revoke modal when Revoke is clicked on a valid cert', async () => {
    fetchMock.mockResolvedValue(
      makeCertResponse([makeCert({ is_valid: true, days_until_expiration: 168 })]),
    )
    renderCertificatesView()
    await waitFor(() => expect(screen.getByTestId('cert-row')).toBeInTheDocument())
    fireEvent.click(screen.getByTestId('cert-revoke-btn'))
    expect(screen.getByTestId('revoke-overlay')).toBeInTheDocument()
    expect(screen.getByRole('dialog')).toBeInTheDocument()
  })

  it('shows cert subject in the revoke modal', async () => {
    fetchMock.mockResolvedValue(
      makeCertResponse([makeCert({ common_name: 'dc-01.acme-corp', serial_number: '7f:3a:9c:01', is_valid: true, days_until_expiration: 168 })]),
    )
    renderCertificatesView()
    await waitFor(() => expect(screen.getByTestId('cert-row')).toBeInTheDocument())
    fireEvent.click(screen.getByTestId('cert-revoke-btn'))
    expect(screen.getByTestId('revoke-overlay')).toHaveTextContent('dc-01.acme-corp')
    expect(screen.getByTestId('revoke-overlay')).toHaveTextContent('7f:3a:9c:01')
  })

  it('closes revoke modal on Cancel', async () => {
    fetchMock.mockResolvedValue(
      makeCertResponse([makeCert({ is_valid: true, days_until_expiration: 168 })]),
    )
    renderCertificatesView()
    await waitFor(() => expect(screen.getByTestId('cert-row')).toBeInTheDocument())
    fireEvent.click(screen.getByTestId('cert-revoke-btn'))
    expect(screen.getByTestId('revoke-overlay')).toBeInTheDocument()
    fireEvent.click(screen.getByRole('button', { name: /cancel/i }))
    expect(screen.queryByTestId('revoke-overlay')).not.toBeInTheDocument()
  })

  it('calls revoke API and closes modal on confirm', async () => {
    fetchMock
      .mockResolvedValueOnce(
        makeCertResponse([makeCert({ is_valid: true, days_until_expiration: 168, serial_number: '7f:3a' })]),
      )
      .mockResolvedValue(
        new Response(
          JSON.stringify({ data: { serial_number: '7f:3a', is_valid: false, is_revoked: true } }),
          { status: 200, headers: { 'Content-Type': 'application/json' } },
        ),
      )
    renderCertificatesView()
    await waitFor(() => expect(screen.getByTestId('cert-row')).toBeInTheDocument())
    fireEvent.click(screen.getByTestId('cert-revoke-btn'))
    expect(screen.getByTestId('revoke-overlay')).toBeInTheDocument()
    fireEvent.click(screen.getByTestId('revoke-confirm-btn'))
    await waitFor(() => {
      expect(screen.queryByTestId('revoke-overlay')).not.toBeInTheDocument()
    })
    // At minimum the initial list fetch + the revoke POST were called
    expect(fetchMock.mock.calls.some(([url]) =>
      String(url).includes('/revoke'),
    )).toBe(true)
  })

  it('shows error when revoke API fails', async () => {
    fetchMock
      .mockResolvedValueOnce(
        makeCertResponse([makeCert({ is_valid: true, days_until_expiration: 168 })]),
      )
      .mockResolvedValueOnce(
        new Response(
          JSON.stringify({ error: { message: 'Certificate not found', code: 'CERTIFICATE_NOT_FOUND' } }),
          { status: 404, headers: { 'Content-Type': 'application/json' } },
        ),
      )
    renderCertificatesView()
    await waitFor(() => expect(screen.getByTestId('cert-row')).toBeInTheDocument())
    fireEvent.click(screen.getByTestId('cert-revoke-btn'))
    fireEvent.click(screen.getByTestId('revoke-confirm-btn'))
    await waitFor(() => {
      expect(screen.getByTestId('revoke-error')).toHaveTextContent('Certificate not found')
    })
  })
})

// ── CA rotation modal ─────────────────────────────────────────────────────────

describe('CertificatesView — CA rotation modal', () => {
  it('opens rotation modal when Rotate signing CA is clicked', () => {
    fetchMock.mockReturnValue(new Promise(() => {}))
    renderCertificatesView()
    fireEvent.click(screen.getByTestId('rotate-ca-btn'))
    expect(screen.getByTestId('rotate-overlay')).toBeInTheDocument()
    expect(screen.getByRole('dialog')).toBeInTheDocument()
  })

  it('rotate confirm button is disabled until ROTATE is typed', () => {
    fetchMock.mockReturnValue(new Promise(() => {}))
    renderCertificatesView()
    fireEvent.click(screen.getByTestId('rotate-ca-btn'))
    expect(screen.getByTestId('rotate-confirm-btn')).toBeDisabled()
    fireEvent.change(screen.getByTestId('rotate-confirm-input'), { target: { value: 'ROTAT' } })
    expect(screen.getByTestId('rotate-confirm-btn')).toBeDisabled()
    fireEvent.change(screen.getByTestId('rotate-confirm-input'), { target: { value: 'ROTATE' } })
    expect(screen.getByTestId('rotate-confirm-btn')).not.toBeDisabled()
  })

  it('clears the input when modal is reopened', () => {
    fetchMock.mockReturnValue(new Promise(() => {}))
    renderCertificatesView()
    fireEvent.click(screen.getByTestId('rotate-ca-btn'))
    fireEvent.change(screen.getByTestId('rotate-confirm-input'), { target: { value: 'ROTATE' } })
    fireEvent.click(screen.getByRole('button', { name: /cancel/i }))
    fireEvent.click(screen.getByTestId('rotate-ca-btn'))
    expect(screen.getByTestId('rotate-confirm-input')).toHaveValue('')
    expect(screen.getByTestId('rotate-confirm-btn')).toBeDisabled()
  })

  it('closes modal on Cancel', () => {
    fetchMock.mockReturnValue(new Promise(() => {}))
    renderCertificatesView()
    fireEvent.click(screen.getByTestId('rotate-ca-btn'))
    expect(screen.getByTestId('rotate-overlay')).toBeInTheDocument()
    fireEvent.click(screen.getByRole('button', { name: /cancel/i }))
    expect(screen.queryByTestId('rotate-overlay')).not.toBeInTheDocument()
  })

  it('calls rotate API and closes modal on confirm', async () => {
    fetchMock
      .mockReturnValueOnce(new Promise(() => {}))
      .mockResolvedValueOnce(
        new Response(
          JSON.stringify({
            data: {
              old_serial: 'aa:bb',
              new_serial: 'cc:dd',
              overlap_days: 7,
              stewards_notified: 10,
              overlap_expires_at: '2026-08-20T00:00:00Z',
            },
          }),
          { status: 200, headers: { 'Content-Type': 'application/json' } },
        ),
      )
    renderCertificatesView()
    fireEvent.click(screen.getByTestId('rotate-ca-btn'))
    fireEvent.change(screen.getByTestId('rotate-confirm-input'), { target: { value: 'ROTATE' } })
    fireEvent.click(screen.getByTestId('rotate-confirm-btn'))
    await waitFor(() => {
      expect(screen.queryByTestId('rotate-overlay')).not.toBeInTheDocument()
    })
    // The confirm path must never bypass the server's overlap-window guard.
    const rotateCall = fetchMock.mock.calls[1]
    expect(JSON.parse(rotateCall?.[1]?.body as string)).toMatchObject({ force: false })
  })

  it('shows error when rotation API fails', async () => {
    fetchMock
      .mockReturnValueOnce(new Promise(() => {}))
      .mockResolvedValueOnce(
        new Response(
          JSON.stringify({ error: { message: 'Rotation failed', code: 'ROTATION_ERROR' } }),
          { status: 500, headers: { 'Content-Type': 'application/json' } },
        ),
      )
    renderCertificatesView()
    fireEvent.click(screen.getByTestId('rotate-ca-btn'))
    fireEvent.change(screen.getByTestId('rotate-confirm-input'), { target: { value: 'ROTATE' } })
    fireEvent.click(screen.getByTestId('rotate-confirm-btn'))
    await waitFor(() => {
      expect(screen.getByTestId('rotate-error')).toHaveTextContent('Rotation failed')
    })
    // Modal stays open after error
    expect(screen.getByTestId('rotate-overlay')).toBeInTheDocument()
    expect(screen.queryByTestId('rotation-in-progress')).not.toBeInTheDocument()
  })

  it('rotation modal shows fleet-impact warning text', () => {
    fetchMock.mockReturnValue(new Promise(() => {}))
    renderCertificatesView()
    fireEvent.click(screen.getByTestId('rotate-ca-btn'))
    expect(screen.getByTestId('rotate-overlay')).toHaveTextContent('every steward in the fleet')
    expect(screen.getByTestId('rotate-overlay')).toHaveTextContent('trust bundles')
  })
})

// ── Rotation-in-progress (409) and the forced override ────────────────────────

function rotationInProgressResponse() {
  return new Response(
    JSON.stringify({
      error: { message: 'Signing rotation already in progress', code: 'ROTATION_IN_PROGRESS' },
    }),
    { status: 409, headers: { 'Content-Type': 'application/json' } },
  )
}

async function reachInProgressState() {
  renderCertificatesView()
  fireEvent.click(screen.getByTestId('rotate-ca-btn'))
  fireEvent.change(screen.getByTestId('rotate-confirm-input'), { target: { value: 'ROTATE' } })
  fireEvent.click(screen.getByTestId('rotate-confirm-btn'))
  await waitFor(() => {
    expect(screen.getByTestId('rotation-in-progress')).toBeInTheDocument()
  })
}

describe('CertificatesView — rotation in progress', () => {
  it('shows the distinct in-progress state instead of a generic error on 409', async () => {
    fetchMock
      .mockReturnValueOnce(new Promise(() => {}))
      .mockResolvedValueOnce(rotationInProgressResponse())
    await reachInProgressState()
    expect(screen.queryByTestId('rotate-error')).not.toBeInTheDocument()
    expect(screen.getByTestId('rotation-in-progress')).toHaveTextContent('overlap window is still open')
    expect(screen.getByTestId('rotation-in-progress-detail')).toHaveTextContent(
      'Signing rotation already in progress',
    )
    // The safe-path copy promising unrenewed certs keep working is gone — that
    // guarantee does not hold for the forced path being offered here.
    expect(screen.getByTestId('rotate-overlay')).not.toHaveTextContent(
      'Existing steward certs keep working',
    )
    expect(screen.getByTestId('rotate-overlay')).toHaveTextContent(
      'fails config-signature validation',
    )
  })

  it('keeps the forced override disabled until FORCE ROTATE is typed', async () => {
    fetchMock
      .mockReturnValueOnce(new Promise(() => {}))
      .mockResolvedValueOnce(rotationInProgressResponse())
    await reachInProgressState()
    expect(screen.getByTestId('force-rotate-btn')).toBeDisabled()
    fireEvent.change(screen.getByTestId('force-rotate-input'), { target: { value: 'ROTATE' } })
    expect(screen.getByTestId('force-rotate-btn')).toBeDisabled()
    fireEvent.change(screen.getByTestId('force-rotate-input'), { target: { value: 'FORCE ROTATE' } })
    expect(screen.getByTestId('force-rotate-btn')).not.toBeDisabled()
  })

  it('sends force=true only from the explicit override', async () => {
    fetchMock
      .mockReturnValueOnce(new Promise(() => {}))
      .mockResolvedValueOnce(rotationInProgressResponse())
      .mockResolvedValueOnce(
        new Response(
          JSON.stringify({
            data: {
              old_serial: 'aa:bb',
              new_serial: 'cc:dd',
              overlap_days: 7,
              stewards_notified: 10,
              overlap_expires_at: '2026-08-20T00:00:00Z',
            },
          }),
          { status: 200, headers: { 'Content-Type': 'application/json' } },
        ),
      )
    await reachInProgressState()
    fireEvent.change(screen.getByTestId('force-rotate-input'), { target: { value: 'FORCE ROTATE' } })
    fireEvent.click(screen.getByTestId('force-rotate-btn'))
    await waitFor(() => {
      expect(screen.queryByTestId('rotate-overlay')).not.toBeInTheDocument()
    })
    expect(JSON.parse(fetchMock.mock.calls[1]?.[1]?.body as string)).toMatchObject({ force: false })
    expect(JSON.parse(fetchMock.mock.calls[2]?.[1]?.body as string)).toMatchObject({ force: true })
  })

  it('reopening the modal returns to the unforced confirm state', async () => {
    fetchMock
      .mockReturnValueOnce(new Promise(() => {}))
      .mockResolvedValueOnce(rotationInProgressResponse())
    await reachInProgressState()
    fireEvent.click(screen.getByRole('button', { name: /cancel/i }))
    fireEvent.click(screen.getByTestId('rotate-ca-btn'))
    expect(screen.queryByTestId('rotation-in-progress')).not.toBeInTheDocument()
    expect(screen.getByTestId('rotate-confirm-input')).toHaveValue('')
    expect(screen.getByTestId('rotate-confirm-btn')).toBeDisabled()
  })
})
