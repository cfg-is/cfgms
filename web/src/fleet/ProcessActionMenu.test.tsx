// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz

/*
 * ProcessActionMenu suite (Story #4629): menu items, confirm text, the signed
 * request body, the self_protect blocked state, cancelled passkey prompt,
 * terminal job statuses, 403 denial, and the pending-poll-window case.
 */
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'
import { act, cleanup, fireEvent, render, screen } from '@testing-library/react'
import ProcessActionMenu from './ProcessActionMenu.tsx'
import { useStewardControl } from './useStewardControl.ts'
import { contentFor, ENVELOPE, installHarness, PROOF, type HarnessOptions } from './actionTestHarness.ts'
import { POLL_WINDOW_MS } from './useStewardControl.ts'

function Host({ status, onViewDna }: { status?: string; onViewDna?: () => void }) {
  const control = useStewardControl('st-1')
  return <ProcessActionMenu stewardId="st-1" pid={4242} name="sshd" status={status} control={control} onViewDna={onViewDna} />
}

afterEach(() => {
  cleanup()
  vi.unstubAllGlobals()
  vi.useRealTimers()
})

function open() {
  fireEvent.click(screen.getByRole('button', { name: 'Actions for PID 4242' }))
}

async function runEnd(opts: HarnessOptions = {}, justification = 'cleanup') {
  const h = installHarness(opts)
  render(<Host />)
  open()
  fireEvent.click(screen.getByRole('menuitem', { name: 'End task' }))
  fireEvent.change(screen.getByLabelText(/Justification/), { target: { value: justification } })
  fireEvent.click(screen.getByRole('button', { name: 'Sign with passkey' }))
  return h
}

describe('ProcessActionMenu', () => {
  beforeEach(() => {
    installHarness()
  })

  it('lists Copy PID, End task, Suspend and Open in DNA, with no Restart', () => {
    render(<Host onViewDna={() => {}} />)
    open()
    const labels = screen.getAllByRole('menuitem').map((e) => e.textContent)
    expect(labels).toEqual(['Copy PID', 'End task', 'Suspend', 'Open in DNA'])
  })

  it('shows Resume instead of Suspend for a suspended process', () => {
    render(<Host status="suspended" />)
    open()
    expect(screen.getByRole('menuitem', { name: 'Resume' })).toBeTruthy()
    expect(screen.queryByRole('menuitem', { name: 'Suspend' })).toBeNull()
  })

  it('Copy PID writes the PID to the clipboard', () => {
    const writeText = vi.fn().mockResolvedValue(undefined)
    Object.defineProperty(navigator, 'clipboard', { value: { writeText }, configurable: true })
    render(<Host />)
    open()
    fireEvent.click(screen.getByRole('menuitem', { name: 'Copy PID' }))
    expect(writeText).toHaveBeenCalledWith('4242')
  })

  it('Open in DNA calls the host callback', () => {
    const onViewDna = vi.fn()
    render(<Host onViewDna={onViewDna} />)
    open()
    fireEvent.click(screen.getByRole('menuitem', { name: 'Open in DNA' }))
    expect(onViewDna).toHaveBeenCalled()
  })

  it('moves focus through items with the arrow keys and closes on Escape', () => {
    render(<Host />)
    open()
    const items = screen.getAllByRole('menuitem')
    expect(document.activeElement).toBe(items[0])
    fireEvent.keyDown(items[0]!, { key: 'ArrowDown' })
    expect(document.activeElement).toBe(items[1])
    fireEvent.keyDown(document, { key: 'Escape' })
    expect(screen.queryByRole('menu')).toBeNull()
  })

  it('requires a justification before the passkey can be requested', () => {
    const h = installHarness()
    render(<Host />)
    open()
    fireEvent.click(screen.getByRole('menuitem', { name: 'End task' }))
    const sign = screen.getByRole('button', { name: 'Sign with passkey' }) as HTMLButtonElement
    expect(sign.disabled).toBe(true)
    fireEvent.change(screen.getByLabelText(/Justification/), { target: { value: '   ' } })
    expect(sign.disabled).toBe(true)
    expect(h.calls).toHaveLength(0)
  })

  it('confirm text is built from the same action that is prepared and signed', async () => {
    const h = await runEnd()
    await screen.findByText('End task: done')
    const prepare = h.calls.find((c) => c.url.endsWith('/actions/prepare'))!
    const begin = h.calls.find((c) => c.url.endsWith('/sign/begin'))!
    expect(prepare.body).toEqual({ target_kind: 'process', target_name: '4242', action: 'end', image: 'sshd' })
    // The content signed is exactly what prepare returned for this verb and target.
    const prepared = contentFor('process.end', 'process', '4242', 'sshd')
    expect((begin.body as { content: string }).content).toBe(prepared)
    expect(begin.body).toEqual({ selector: 'id:st-1', content: prepared, shell: 'steward-action' })
  })

  it('shows verb, target and steward in the confirm step', () => {
    installHarness()
    render(<Host />)
    open()
    fireEvent.click(screen.getByRole('menuitem', { name: 'End task' }))
    const form = screen.getByRole('form', { name: 'Confirm End task' })
    expect(form.textContent).toContain('process.end')
    expect(form.textContent).toContain('Process sshd (PID 4242)')
    expect(form.textContent).toContain('st-1')
  })

  it('sends the sign/finish proof and the sign/begin envelope unchanged', async () => {
    const h = await runEnd()
    await screen.findByText('End task: done')
    const post = h.calls.find((c) => c.url === '/api/v1/stewards/st-1/processes/4242/actions')!
    expect(post.method).toBe('POST')
    expect(post.body).toEqual({
      action: 'end',
      justification: 'cleanup',
      image: 'sshd',
      nonce: ENVELOPE.nonce,
      expires_at: ENVELOPE.expires_at,
      targets: ENVELOPE.targets,
      webauthn: PROOF,
    })
  })

  it('cancelling the passkey prompt sends no action request', async () => {
    const h = installHarness()
    h.credGet.mockRejectedValue(new DOMException('cancelled', 'NotAllowedError'))
    render(<Host />)
    open()
    fireEvent.click(screen.getByRole('menuitem', { name: 'End task' }))
    fireEvent.change(screen.getByLabelText(/Justification/), { target: { value: 'x' } })
    fireEvent.click(screen.getByRole('button', { name: 'Sign with passkey' }))
    await screen.findByText(/cancelled, nothing was sent/)
    expect(h.calls.some((c) => c.url.endsWith('/actions'))).toBe(false)
    expect(h.calls.some((c) => c.url.endsWith('/sign/finish'))).toBe(false)
  })

  it('refuses to sign when prepare returns content for a different action', async () => {
    const h = await runEnd({ prepareContent: contentFor('process.suspend', 'process', '4242', 'sshd') })
    await screen.findByText(/could not be sent/)
    expect(h.credGet).not.toHaveBeenCalled()
    expect(h.calls.some((c) => c.url.endsWith('/sign/begin'))).toBe(false)
  })

  it('refuses to prompt when the sign envelope names a different steward', async () => {
    const h = await runEnd({ beginTargets: ['st-other'] })
    await screen.findByText(/could not be sent/)
    expect(h.credGet).not.toHaveBeenCalled()
    expect(h.calls.some((c) => c.url.endsWith('/actions'))).toBe(false)
  })

  it('explains a missing passkey instead of failing silently', async () => {
    const h = await runEnd({ beginStatus: 409, beginCode: 'NO_CREDENTIALS' })
    await screen.findByText(/account has no passkey/)
    expect(h.calls.some((c) => c.url.endsWith('/actions'))).toBe(false)
  })

  it('End task on the steward process shows blocked from self_protect and the item stays disabled', async () => {
    await runEnd({ jobs: [{ status: 'failed', result_code: 'self_protect' }] })
    await screen.findByText(/blocked\. The steward does not act on its own process/)
    open()
    const item = screen.getByRole('menuitem', { name: 'End task (blocked)' }) as HTMLButtonElement
    expect(item.disabled).toBe(true)
  })

  it('renders process_changed and unsupported results', async () => {
    await runEnd({ jobs: [{ status: 'failed', result_code: 'process_changed' }] })
    await screen.findByText(/the process changed/)
    cleanup()
    await runEnd({ jobs: [{ status: 'failed', result_code: 'unsupported' }] })
    await screen.findByText(/not supported on this device/)
  })

  it('expired renders "expired, not run" and stays visible', async () => {
    await runEnd({ jobs: [{ status: 'expired', result_code: 'expired' }] })
    expect(await screen.findByText('End task: expired, not run')).toBeTruthy()
  })

  it('no_result renders "sent, no result reported" and stays visible', async () => {
    await runEnd({ jobs: [{ status: 'no_result' }] })
    expect(await screen.findByText('End task: sent, no result reported')).toBeTruthy()
  })

  it('shows the row pending while the job is not terminal', async () => {
    await runEnd({ jobs: [{ status: 'pending' }, { status: 'completed', result_code: 'ok' }] })
    await screen.findByText('End task: pending')
    expect(await screen.findByText('End task: done', {}, { timeout: 4000 })).toBeTruthy()
  })

  it('a 403 on the action renders the denied message', async () => {
    await runEnd({ actionStatus: 403 })
    await screen.findByText(/denied\. You do not have permission/)
  })

  it('a 403 from sign/begin renders the denied message', async () => {
    await runEnd({ beginStatus: 403, beginCode: 'FORBIDDEN' })
    await screen.findByText(/denied\. You do not have permission/)
  })

  it('polling that never reaches a terminal status renders still pending with Refresh, not a failure', async () => {
    vi.useFakeTimers({ shouldAdvanceTime: true })
    const h = installHarness({ jobs: [{ status: 'running' }] })
    render(<Host />)
    open()
    fireEvent.click(screen.getByRole('menuitem', { name: 'End task' }))
    fireEvent.change(screen.getByLabelText(/Justification/), { target: { value: 'x' } })
    fireEvent.click(screen.getByRole('button', { name: 'Sign with passkey' }))
    await screen.findByText('End task: pending')
    await act(async () => {
      await vi.advanceTimersByTimeAsync(POLL_WINDOW_MS + 2000)
    })
    await screen.findByText('End task: still pending')
    expect(screen.queryByText(/failed/)).toBeNull()
    // Refresh re-polls the same run; a terminal result then replaces the pending text.
    h.state.jobs = [{ status: 'completed', result_code: 'ok' }]
    const pollsBefore = h.calls.filter((c) => c.url.includes('/runs/')).length
    fireEvent.click(screen.getByRole('button', { name: 'Refresh' }))
    await screen.findByText('End task: done')
    expect(h.calls.filter((c) => c.url.includes('/runs/')).length).toBeGreaterThan(pollsBefore)
    expect(h.calls.filter((c) => c.url.endsWith('/actions'))).toHaveLength(1)
  })
})
