// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz

/*
 * TamperPanel suite (Story #5668): the three actions and their dialogs, the repair
 * state, the hands-on note and the non-tampered case. fetch is stubbed at the
 * network edge; apiFetch and its central step-up dispatch run for real, with a
 * test listener standing in for the passkey ceremony (tap = replay with a presence
 * token, cancel = null).
 */
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'
import { cleanup, fireEvent, render, screen, waitFor, within } from '@testing-library/react'
import { onStepUpRequired, replayRequest } from '../api/client.ts'
import TamperPanel, { type TamperSteward } from './TamperPanel.tsx'

const fetchMock = vi.fn<typeof fetch>()

interface Posts {
  path: string
  body: Record<string, unknown>
  presence: boolean
}
let posts: Posts[] = []
let repairGet: () => Response
let postReply: (path: string, body: Record<string, unknown>) => Response

function json(status: number, body: unknown, headers: Record<string, string> = {}): Response {
  return new Response(JSON.stringify(body), { status, headers: { 'Content-Type': 'application/json', ...headers } })
}

function tampered(over: Partial<TamperSteward> = {}): TamperSteward {
  return {
    id: 'stw-8f3a',
    status: 'tampered',
    hostname: 'WS-ACCT-07',
    connectionState: 'connected',
    reasons: [],
    tamperCodes: ['tamper_data_dir', 'tamper_security_profile'],
    ...over,
  }
}

beforeEach(() => {
  posts = []
  repairGet = () => json(404, { error: { code: 'REPAIR_NOT_FOUND', message: 'none' } })
  postReply = () => json(200, { data: { status: 'active' } })
  fetchMock.mockReset()
  fetchMock.mockImplementation((input, init) => {
    const path = String(input)
    if ((init?.method ?? 'GET') === 'GET') return Promise.resolve(repairGet())
    const headers = new Headers(init?.headers)
    const body = JSON.parse(String(init?.body ?? '{}')) as Record<string, unknown>
    const presence = headers.has('X-Presence-Token')
    // The controller demands a passkey proof first; without one it answers the step-up 401.
    if (!presence) return Promise.resolve(json(401, {}, { 'WWW-Authenticate': 'CFGMS-StepUp required="strong"' }))
    posts.push({ path, body, presence })
    return Promise.resolve(postReply(path, body))
  })
  vi.stubGlobal('fetch', fetchMock)
  tapPasskey()
})

afterEach(() => {
  cleanup()
  onStepUpRequired(null)
  vi.unstubAllGlobals()
})

/** The operator taps the passkey: the request is replayed with a presence token. */
function tapPasskey() {
  onStepUpRequired((req) =>
    replayRequest(req.path, { ...req.init, headers: { ...(req.init.headers as Record<string, string>), 'X-Presence-Token': 't' } }),
  )
}
function cancelPasskey() {
  onStepUpRequired(() => Promise.resolve(null))
}

function renderPanel(steward: TamperSteward, onChanged = vi.fn()) {
  render(<TamperPanel steward={steward} onChanged={onChanged} />)
  return onChanged
}

describe('non-tampered steward', () => {
  it('shows none of the three actions', async () => {
    renderPanel(tampered({ status: 'active' }))
    expect(screen.queryByRole('button', { name: 'Restore' })).not.toBeInTheDocument()
    expect(screen.queryByRole('button', { name: 'Repair and restore' })).not.toBeInTheDocument()
    expect(screen.queryByRole('button', { name: 'Ban' })).not.toBeInTheDocument()
    expect(screen.queryByTestId('tampered-banner')).not.toBeInTheDocument()
    expect(fetchMock).not.toHaveBeenCalled()
  })
})

describe('tampered banner', () => {
  it('shows the stored tamper codes, the three actions and the normal hands-on line', async () => {
    renderPanel(tampered())
    expect(await screen.findByTestId('tampered-banner')).toBeInTheDocument()
    expect(screen.getByText('tamper_data_dir')).toBeInTheDocument()
    expect(screen.getByText('tamper_security_profile')).toBeInTheDocument()
    expect(screen.getByRole('button', { name: 'Restore' })).toBeEnabled()
    expect(screen.getByRole('button', { name: 'Repair and restore' })).toBeEnabled()
    expect(screen.getByRole('button', { name: 'Ban' })).toBeEnabled()
    expect(screen.getByTestId('hands-on-line').textContent).toContain('You can still run commands, scripts and the shell by hand')
    expect(screen.queryByTestId('locked-tools')).not.toBeInTheDocument()
    expect(screen.getByRole('button', { name: 'Shell' })).toBeEnabled()
  })

  it('says so when no tamper codes are on record', async () => {
    renderPanel(tampered({ tamperCodes: [] }))
    expect(await screen.findByTestId('no-codes')).toBeInTheDocument()
  })

  it('renders steward-supplied reason text as text, not markup', async () => {
    renderPanel(tampered({ reasons: [{ component: 'binary', code: 'tamper.hash', message: '<b>bad</b>' }] }))
    const banner = await screen.findByTestId('tampered-banner')
    expect(banner.textContent).toContain('<b>bad</b>')
    expect([...banner.querySelectorAll('b')].some((b) => b.textContent === 'bad')).toBe(false)
  })

  it('shows each confirm dialog with the stored tamper codes before any action', async () => {
    renderPanel(tampered())
    for (const name of ['Restore', 'Repair and restore', 'Ban']) {
      fireEvent.click(screen.getByRole('button', { name }))
      const dialog = await screen.findByRole('dialog')
      expect(dialog.textContent).toContain('Tamper codes on record')
      expect(dialog.textContent).toContain('tamper_data_dir')
      fireEvent.click(screen.getByRole('button', { name: 'Cancel' }))
      expect(screen.queryByRole('dialog')).not.toBeInTheDocument()
    }
    expect(posts).toHaveLength(0)
  })
})

describe('locked_tools reasons', () => {
  const cases: [string, string][] = [
    ['locked_tools.no_baked_root', 'installed without this controller'],
    ['locked_tools.baked_root_malformed', 'is not valid'],
    ['locked_tools.root_mismatch', 'does not lead to a root certificate'],
    ['locked_tools.link_not_anchored', 'not secured by the root certificate'],
    ['locked_tools.revocation_stale', 'no recent enough revocation list'],
  ]
  it.each(cases)('%s shows its own plain-language reason and disables Shell and Live activity', async (code, text) => {
    renderPanel(tampered({ reasons: [{ component: 'locked_tools', code }] }))
    const note = await screen.findByTestId('locked-tools')
    expect(note.textContent).toContain(text)
    expect(note.querySelectorAll('li')).toHaveLength(1)
    expect(screen.getByTestId('hands-on-line').textContent).toContain('Hands-on tools are not available')
    expect(screen.getByRole('button', { name: 'Shell' })).toBeDisabled()
    expect(screen.getByRole('button', { name: 'Live activity' })).toBeDisabled()
    expect(screen.getByRole('button', { name: 'Logs' })).toBeEnabled()
    expect(screen.getByRole('button', { name: 'Ban' })).toBeEnabled()
  })

  it('maps repair.anchor_untrusted to ban or re-enroll in the hands-on line', async () => {
    renderPanel(tampered({ reasons: [{ component: 'repair', code: 'repair.anchor_untrusted' }] }))
    expect((await screen.findByTestId('hands-on-line')).textContent).toContain('Ban it or re-enroll it')
  })
})

describe('ban', () => {
  async function openBan() {
    fireEvent.click(screen.getByRole('button', { name: 'Ban' }))
    await screen.findByTestId('ban-dialog')
    return screen.getByLabelText(/Type .* to confirm/)
  }

  it('keeps the button disabled until the host name matches exactly, then bans after the passkey tap', async () => {
    postReply = () => json(200, { data: { id: 'stw-8f3a', status: 'revoked' } })
    const onChanged = renderPanel(tampered())
    const input = await openBan()
    const confirm = screen.getByRole('button', { name: /Ban — tap passkey/ })
    expect(confirm).toBeDisabled()
    expect(screen.getByTestId('ban-dialog').textContent).toContain('stw-8f3a')
    expect(screen.getByTestId('ban-dialog').textContent).toContain('cannot be undone')
    expect(screen.getByTestId('ban-dialog').textContent).toContain('enroll again as a new device')

    fireEvent.change(input, { target: { value: 'ws-acct-07' } })
    expect(confirm).toBeDisabled()
    fireEvent.change(input, { target: { value: 'WS-ACCT-07 ' } })
    expect(confirm).toBeDisabled()
    fireEvent.click(confirm)
    expect(posts).toHaveLength(0)

    fireEvent.change(input, { target: { value: 'WS-ACCT-07' } })
    expect(confirm).toBeEnabled()
    fireEvent.click(confirm)
    await waitFor(() => expect(posts).toHaveLength(1))
    expect(posts[0]!.path).toBe('/api/v1/stewards/stw-8f3a/tamper/ban')
    await waitFor(() => expect(onChanged).toHaveBeenCalled())
    expect(screen.getByTestId('tamper-done').textContent).toContain('Banned')
  })

  it('cancelling the passkey step-up changes nothing and offers a retry', async () => {
    cancelPasskey()
    const onChanged = renderPanel(tampered())
    const input = await openBan()
    fireEvent.change(input, { target: { value: 'WS-ACCT-07' } })
    fireEvent.click(screen.getByRole('button', { name: /Ban — tap passkey/ }))
    expect(await screen.findByText(/Passkey cancelled\. Nothing changed/)).toBeInTheDocument()
    expect(posts).toHaveLength(0)
    expect(onChanged).not.toHaveBeenCalled()
    expect(screen.getByRole('button', { name: /Ban — tap passkey/ })).toBeEnabled()
  })

  it('shows the host name with control and bidi characters escaped', async () => {
    const bidi = String.fromCharCode(0x202e)
    renderPanel(tampered({ hostname: `ws${bidi}evil${String.fromCharCode(7)}` }))
    await openBan()
    expect(screen.getByTestId('ban-expected-name').textContent).toBe('ws\\u{202E}evil\\u{7}')
    expect(screen.getByTestId('ban-dialog').textContent).not.toContain(String.fromCharCode(0x202e))
  })

  it('falls back to the steward ID when the controller has no host name', async () => {
    renderPanel(tampered({ hostname: '' }))
    const input = await openBan()
    fireEvent.change(input, { target: { value: 'stw-8f3a' } })
    expect(screen.getByRole('button', { name: /Ban — tap passkey/ })).toBeEnabled()
  })

  it('shows who/what changed it on a 409 and changes nothing', async () => {
    postReply = () => json(409, { error: { code: 'STEWARD_NOT_TAMPERED', message: 'Steward is active, not tampered' } })
    renderPanel(tampered())
    const input = await openBan()
    fireEvent.change(input, { target: { value: 'WS-ACCT-07' } })
    fireEvent.click(screen.getByRole('button', { name: /Ban — tap passkey/ }))
    expect(await screen.findByText(/Someone else already changed this steward/)).toBeInTheDocument()
    expect(screen.getByRole('button', { name: 'Reload' })).toBeInTheDocument()
  })
})

describe('restore', () => {
  it('restores after the passkey tap', async () => {
    const onChanged = renderPanel(tampered())
    fireEvent.click(screen.getByRole('button', { name: 'Restore' }))
    fireEvent.click(await screen.findByRole('button', { name: /Restore — tap passkey/ }))
    await waitFor(() => expect(posts).toHaveLength(1))
    expect(posts[0]!.path).toBe('/api/v1/stewards/stw-8f3a/tamper/restore')
    await waitFor(() => expect(onChanged).toHaveBeenCalled())
  })

  it('a restore refused with fault_still_reported offers Repair and restore and changes nothing', async () => {
    postReply = () =>
      json(409, { error: 'fault_still_reported', codes: ['tamper_data_dir'], message: 'still faulted' })
    const onChanged = renderPanel(tampered())
    fireEvent.click(screen.getByRole('button', { name: 'Restore' }))
    fireEvent.click(await screen.findByRole('button', { name: /Restore — tap passkey/ }))
    expect(await screen.findByText(/still reports a fault \(tamper_data_dir\)/)).toBeInTheDocument()
    expect(onChanged).not.toHaveBeenCalled()
    fireEvent.click(within(screen.getByTestId('restore-dialog')).getByRole('button', { name: 'Repair and restore' }))
    expect(await screen.findByTestId('repair-dialog')).toBeInTheDocument()
  })
})

describe('repair and restore', () => {
  const loss = [
    { component: 'repair', code: 'repair.loss.local_logs' },
    { component: 'repair', code: 'repair.loss.action_history' },
  ]

  it('lists the reported loss, cannot be submitted without approval, and sends exactly those codes', async () => {
    postReply = () => json(202, { data: { repair_id: 'r1', state: 'waiting', delivered: true, loss_codes: [] } })
    const onChanged = renderPanel(tampered({ reasons: loss }))
    fireEvent.click(screen.getByRole('button', { name: 'Repair and restore' }))
    const loss_ = await screen.findByTestId('repair-loss')
    expect(loss_.textContent).toContain('Local log buffer')
    expect(loss_.textContent).toContain('Local action history')
    const confirm = screen.getByRole('button', { name: /Repair — tap passkey/ })
    expect(confirm).toBeDisabled()
    fireEvent.click(confirm)
    expect(posts).toHaveLength(0)

    fireEvent.click(screen.getByRole('checkbox', { name: /I approve losing this local data/ }))
    expect(confirm).toBeEnabled()
    fireEvent.click(confirm)
    await waitFor(() => expect(posts).toHaveLength(1))
    expect(posts[0]!.path).toBe('/api/v1/stewards/stw-8f3a/tamper/repair')
    expect(posts[0]!.body).toEqual({ approved_loss_codes: ['repair.loss.action_history', 'repair.loss.local_logs'] })
    await waitFor(() => expect(onChanged).toHaveBeenCalled())
  })

  it('has no approval control when the steward reported no loss', async () => {
    postReply = () => json(202, { data: { repair_id: 'r1' } })
    renderPanel(tampered())
    fireEvent.click(screen.getByRole('button', { name: 'Repair and restore' }))
    const confirm = await screen.findByRole('button', { name: /Repair — tap passkey/ })
    expect(screen.queryByRole('checkbox')).not.toBeInTheDocument()
    expect(screen.queryByTestId('repair-loss')).not.toBeInTheDocument()
    expect(screen.getByTestId('repair-dialog').textContent).toContain('Keeps its steward ID, local logs and action history')
    fireEvent.click(confirm)
    await waitFor(() => expect(posts).toHaveLength(1))
    expect(posts[0]!.body).toEqual({ approved_loss_codes: [] })
  })

  it('reloads the current loss list on loss_approval_required and asks for approval again', async () => {
    postReply = () =>
      json(409, { error: 'loss_approval_required', loss_codes: ['repair.loss.local_logs', 'repair.loss.action_history'], message: 'approve' })
    renderPanel(tampered({ reasons: [{ component: 'repair', code: 'repair.loss.local_logs' }] }))
    fireEvent.click(screen.getByRole('button', { name: 'Repair and restore' }))
    fireEvent.click(await screen.findByRole('checkbox'))
    fireEvent.click(screen.getByRole('button', { name: /Repair — tap passkey/ }))
    await waitFor(() => expect(screen.getByTestId('repair-loss').textContent).toContain('Local action history'))
    expect(screen.getByRole('checkbox')).not.toBeChecked()
    expect(screen.getByRole('button', { name: /Repair — tap passkey/ })).toBeDisabled()
  })
})

describe('repair state', () => {
  function state(s: string, extra: Record<string, unknown> = {}) {
    repairGet = () =>
      json(200, {
        data: {
          repair_id: 'r1',
          state: s,
          requested_by: 'ana',
          requested_at: '2026-11-06T10:00:00Z',
          loss_codes: [],
          outcome_codes: [],
          ...extra,
        },
      })
  }

  it('renders waiting, with the offline variant for a disconnected steward', async () => {
    state('waiting')
    renderPanel(tampered({ connectionState: 'disconnected' }))
    expect(await screen.findByTestId('repair-waiting')).toBeInTheDocument()
    expect(screen.getByTestId('repair-offline')).toBeInTheDocument()
    expect(screen.getByRole('button', { name: 'Restore' })).toBeDisabled()
    expect(screen.getByRole('button', { name: 'Ban' })).toBeEnabled()
  })

  it('renders running', async () => {
    state('running')
    renderPanel(tampered())
    expect(await screen.findByTestId('repair-running')).toBeInTheDocument()
    expect(screen.queryByTestId('repair-offline')).not.toBeInTheDocument()
  })

  it('renders completed as waiting for the quiet period', async () => {
    state('completed')
    renderPanel(tampered())
    expect((await screen.findByTestId('repair-completed')).textContent).toContain('quiet period')
  })

  it('renders restored once the steward is no longer tampered', async () => {
    state('restored')
    renderPanel(tampered())
    expect(await screen.findByTestId('repair-restored')).toBeInTheDocument()
  })

  it('renders failed with the failure reason', async () => {
    state('failed', { outcome_codes: ['repair.failed', 'repair.fault_persists'] })
    renderPanel(tampered())
    const failed = await screen.findByTestId('repair-failed')
    expect(failed.textContent).toContain('could not complete the repair')
    expect(failed.textContent).toContain('still present after the repair')
  })

  it('renders contested and offers Ban', async () => {
    state('contested', { outcome_codes: ['repair.contested'] })
    renderPanel(tampered())
    const contested = await screen.findByTestId('repair-contested')
    fireEvent.click(contested.querySelector('button')!)
    expect(await screen.findByTestId('ban-dialog')).toBeInTheDocument()
  })

  it('shows the restored confirmation, and no actions, when a repaired steward is no longer tampered', async () => {
    state('restored')
    const view = render(<TamperPanel steward={tampered()} onChanged={vi.fn()} />)
    await screen.findByTestId('repair-restored')
    view.rerender(<TamperPanel steward={tampered({ status: 'active' })} onChanged={vi.fn()} />)
    expect(screen.getByTestId('tamper-done')).toBeInTheDocument()
    expect(screen.queryByRole('button', { name: 'Ban' })).not.toBeInTheDocument()
  })
})
