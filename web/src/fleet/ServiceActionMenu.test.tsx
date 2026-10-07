// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz

/*
 * ServiceActionMenu suite (Story #4629): Start/Stop/Restart through the signed
 * action flow, with the request addressed by service name.
 */
import { afterEach, describe, expect, it, vi } from 'vitest'
import { cleanup, fireEvent, render, screen } from '@testing-library/react'
import ServiceActionMenu from './ServiceActionMenu.tsx'
import { useStewardControl } from './useStewardControl.ts'
import { contentFor, ENVELOPE, installHarness, PROOF } from './actionTestHarness.ts'

function Host() {
  const control = useStewardControl('st-1')
  return <ServiceActionMenu stewardId="st-1" name="nginx" control={control} />
}

afterEach(() => {
  cleanup()
  vi.unstubAllGlobals()
})

describe('ServiceActionMenu', () => {
  it('offers Start, Stop and Restart', () => {
    installHarness()
    render(<Host />)
    fireEvent.click(screen.getByRole('button', { name: 'Actions for nginx' }))
    expect(screen.getAllByRole('menuitem').map((e) => e.textContent)).toEqual(['Start', 'Stop', 'Restart'])
  })

  it.each([
    ['Restart', 'restart'],
    ['Stop', 'stop'],
    ['Start', 'start'],
  ])('%s signs the prepared content and posts the proof', async (label, action) => {
    const h = installHarness()
    render(<Host />)
    fireEvent.click(screen.getByRole('button', { name: 'Actions for nginx' }))
    fireEvent.click(screen.getByRole('menuitem', { name: label }))
    const form = screen.getByRole('form')
    expect(form.textContent).toContain(`service.${action}`)
    expect(form.textContent).toContain('Service nginx')
    fireEvent.change(screen.getByLabelText(/Justification/), { target: { value: 'maintenance' } })
    fireEvent.click(screen.getByRole('button', { name: 'Sign with passkey' }))
    await screen.findByText(`${label} service: done`)

    const begin = h.calls.find((c) => c.url.endsWith('/sign/begin'))!
    expect((begin.body as { content: string }).content).toBe(contentFor(`service.${action}`, 'service', 'nginx'))
    const post = h.calls.find((c) => c.url === '/api/v1/stewards/st-1/services/nginx/actions')!
    expect(post.body).toEqual({
      action,
      justification: 'maintenance',
      nonce: ENVELOPE.nonce,
      expires_at: ENVELOPE.expires_at,
      targets: ENVELOPE.targets,
      webauthn: PROOF,
    })
  })

  it('renders a 403 as the denied message', async () => {
    installHarness({ actionStatus: 403 })
    render(<Host />)
    fireEvent.click(screen.getByRole('button', { name: 'Actions for nginx' }))
    fireEvent.click(screen.getByRole('menuitem', { name: 'Stop' }))
    fireEvent.change(screen.getByLabelText(/Justification/), { target: { value: 'x' } })
    fireEvent.click(screen.getByRole('button', { name: 'Sign with passkey' }))
    await screen.findByText(/denied\. You do not have permission/)
  })

  it('Cancel in the confirm step sends nothing', () => {
    const h = installHarness()
    render(<Host />)
    fireEvent.click(screen.getByRole('button', { name: 'Actions for nginx' }))
    fireEvent.click(screen.getByRole('menuitem', { name: 'Restart' }))
    fireEvent.click(screen.getByRole('button', { name: 'Cancel' }))
    expect(h.calls).toHaveLength(0)
    expect(screen.queryByRole('form')).toBeNull()
  })
})
