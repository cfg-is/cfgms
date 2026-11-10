// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz

/*
 * ProfilesView test suite (Issue #5461, Epic #5300). Real AuthProvider, apiFetch,
 * StepUpModal and TenantScopeProvider; only global fetch is stubbed at the network
 * edge, by a small stateful stand-in for the controller's profile routes.
 */
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'
import { cleanup, fireEvent, render, screen, waitFor, within } from '@testing-library/react'
import { MemoryRouter } from 'react-router'
import { AuthProvider } from '../auth/AuthContext.tsx'
import { TenantScopeProvider } from '../shell/TenantScopeContext.tsx'
import ProfilesView from './ProfilesView.tsx'

const fetchMock = vi.fn<typeof fetch>()
const base = '/api/v1/hyperv/profiles'

beforeEach(() => {
  fetchMock.mockReset()
  vi.stubGlobal('fetch', fetchMock)
})

afterEach(() => {
  vi.unstubAllGlobals()
  cleanup()
  localStorage.clear()
  sessionStorage.clear()
})

function jsonResponse(status: number, body: unknown = {}, headers: Record<string, string> = {}): Response {
  return new Response(status === 204 ? null : JSON.stringify(body), {
    status,
    headers: { 'Content-Type': 'application/json', ...headers },
  })
}

interface StoredProfile {
  name: string
  os_family: string
  answer_format: string
  template: string
  enroll: { registration_token_secret_key: string; bundle_url: string; correlation_label: string }
}

const noEnroll = { registration_token_secret_key: '', bundle_url: '', correlation_label: '' }

function profile(over: Partial<StoredProfile> = {}): StoredProfile {
  return {
    name: 'linux-cloud-base',
    os_family: 'linux',
    answer_format: 'cloud-init',
    template: '#cloud-config\nhostname: {{ .CorrelationID }}\npassword {{ secret "hyperv/apt-mirror-password" }}',
    enroll: {
      registration_token_secret_key: 'hyperv/enroll/regtoken',
      bundle_url: 'https://controller.acme-corp.example/bundles/steward-linux-amd64',
      correlation_label: 'vm-build',
    },
    ...over,
  }
}

const challenge = () =>
  jsonResponse(
    401,
    { error: 'step_up_required', required_assurance: 'strong', presence_required: true },
    { 'WWW-Authenticate': 'CFGMS-StepUp realm="cfgms", required="strong", presence="required"' },
  )

interface Controller {
  profiles: Map<string, StoredProfile>
  /** When set, POST and DELETE answer a presence challenge until the retry carries this token. */
  presenceToken: string | null
  /** A canned reply for the next POST, ahead of any other handling. */
  nextPost: Response | null
}

function installController(initial: StoredProfile[] = []): Controller {
  const ctl: Controller = {
    profiles: new Map(initial.map((p) => [p.name, p])),
    presenceToken: null,
    nextPost: null,
  }
  const envelope = (data: unknown) => ({ data, timestamp: new Date().toISOString() })
  fetchMock.mockImplementation((input, init) => {
    const url = String(input)
    const method = init?.method ?? 'GET'
    if (url.includes('presence/begin')) {
      return Promise.resolve(
        jsonResponse(
          200,
          envelope({
            publicKey: {
              challenge: 'Y2hhbGxlbmdl',
              timeout: 60000,
              rpId: 'localhost',
              allowCredentials: [{ type: 'public-key', id: 'Y3JlZA', transports: ['internal'] }],
              userVerification: 'required',
            },
          }),
        ),
      )
    }
    if (url.includes('presence/finish')) {
      return Promise.resolve(jsonResponse(200, envelope({ presence_token: 'tap-token-1', expires_in: 30 })))
    }
    if (!url.startsWith(base)) return Promise.resolve(jsonResponse(404, {}))
    const path = url.slice(base.length).split('?')[0] ?? ''
    if (method === 'POST' || method === 'DELETE') {
      if (ctl.presenceToken !== null && new Headers(init?.headers).get('X-Presence-Token') !== ctl.presenceToken) {
        return Promise.resolve(challenge())
      }
    }
    if (method === 'POST') {
      if (ctl.nextPost !== null) {
        const reply = ctl.nextPost
        ctl.nextPost = null
        return Promise.resolve(reply)
      }
      const body = JSON.parse(String(init?.body)) as StoredProfile
      ctl.profiles.set(body.name, body)
      return Promise.resolve(jsonResponse(201, envelope(body)))
    }
    if (method === 'DELETE') {
      const name = decodeURIComponent(path.slice(1))
      if (!ctl.profiles.delete(name)) {
        return Promise.resolve(jsonResponse(404, { error: { code: 'NOT_FOUND', message: 'Hyperv profile not found' } }))
      }
      return Promise.resolve(jsonResponse(200, envelope({ deleted: name })))
    }
    if (path === '') {
      return Promise.resolve(jsonResponse(200, envelope({ profiles: [...ctl.profiles.keys()].sort() })))
    }
    const found = ctl.profiles.get(decodeURIComponent(path.slice(1)))
    return Promise.resolve(
      found
        ? jsonResponse(200, envelope(found))
        : jsonResponse(404, { error: { code: 'NOT_FOUND', message: 'Hyperv profile not found' } }),
    )
  })
  return ctl
}

function stubPasskey() {
  const cred = {
    id: 'cred-id-b64u',
    type: 'public-key',
    rawId: new TextEncoder().encode('cred-id-b64u').buffer,
    response: {
      clientDataJSON: new TextEncoder().encode('{"type":"webauthn.get"}').buffer,
      authenticatorData: new TextEncoder().encode('ad').buffer,
      signature: new TextEncoder().encode('sig').buffer,
      userHandle: null,
    },
    getClientExtensionResults: () => ({}),
    authenticatorAttachment: null,
    toJSON: () => ({}),
  }
  vi.stubGlobal('navigator', { credentials: { get: vi.fn().mockResolvedValue(cred) } })
}

function renderView(tenant = 'acme-corp') {
  return render(
    <MemoryRouter>
      <AuthProvider>
        <TenantScopeProvider rootPath={tenant}>
          <ProfilesView />
        </TenantScopeProvider>
      </AuthProvider>
    </MemoryRouter>,
  )
}

function callsTo(method: string) {
  return fetchMock.mock.calls.filter(([u, init]) => String(u).startsWith(base) && (init?.method ?? 'GET') === method)
}

/** Opens the create flow and fills step 1 (name, template, and optionally enrollment). */
async function writeProfile(
  over: { name?: string; template?: string; enroll?: boolean } = {},
) {
  fireEvent.click(await screen.findByTestId('hvp-new-btn'))
  fireEvent.change(await screen.findByTestId('hvp-name'), { target: { value: over.name ?? 'linux-cloud-base' } })
  fireEvent.change(screen.getByTestId('hvp-template-input'), {
    target: { value: over.template ?? profile().template },
  })
  if (over.enroll !== false) {
    fireEvent.change(screen.getByTestId('hvp-enroll-key'), { target: { value: 'hyperv/enroll/regtoken' } })
    fireEvent.change(screen.getByTestId('hvp-enroll-url'), {
      target: { value: 'https://controller.acme-corp.example/bundles/steward-linux-amd64' },
    })
    fireEvent.change(screen.getByTestId('hvp-enroll-label'), { target: { value: 'vm-build' } })
  }
}

describe('ProfilesView', () => {
  it('lists names only and fetches the detail of the selected name', async () => {
    installController([profile(), profile({ name: 'lab-scratch', answer_format: 'preseed', template: 'x', enroll: noEnroll })])
    renderView()
    expect(screen.getByRole('heading', { name: 'Hyper-V profiles', level: 1 })).toBeInTheDocument()
    expect(await screen.findByTestId('hvp-pick-lab-scratch')).toBeInTheDocument()
    expect(screen.getByTestId('hvp-pick-linux-cloud-base')).toBeInTheDocument()
    // Only the list call so far: no detail until a name is selected.
    expect(callsTo('GET').map(([u]) => String(u))).toEqual([`${base}?tenant=acme-corp`])
    expect(screen.getByTestId('hvp-pick-prompt')).toBeInTheDocument()

    fireEvent.click(screen.getByTestId('hvp-pick-linux-cloud-base'))
    const detail = await screen.findByTestId('hvp-detail')
    expect(await within(detail).findByTestId('hvp-detail-name')).toHaveTextContent('linux-cloud-base')
    expect(within(detail).getByTestId('hvp-detail-os')).toHaveTextContent('linux')
    expect(within(detail).getByTestId('hvp-detail-format')).toHaveTextContent('cloud-init')
    expect(within(detail).getByTestId('hvp-detail-runs-as')).toHaveTextContent('root')
    expect(callsTo('GET').map(([u]) => String(u))).toContain(`${base}/linux-cloud-base?tenant=acme-corp`)
    expect(within(detail).getByTestId('hvp-enroll')).toHaveTextContent('hyperv/enroll/regtoken')
  })

  it('says enrollment is off when the profile has none, and that profiles cannot be edited', async () => {
    installController([profile({ name: 'lab-scratch', enroll: noEnroll })])
    renderView()
    fireEvent.click(await screen.findByTestId('hvp-pick-lab-scratch'))
    expect(await screen.findByTestId('hvp-enroll')).toHaveTextContent(/enrollment: off/i)
    expect(screen.getByTestId('hvp-no-edit')).toHaveTextContent(/cannot be edited/i)
    expect(screen.queryByRole('button', { name: /^edit/i })).toBeNull()
  })

  it('renders the template as text', async () => {
    const hostile = '<script>window.__pwned = 1</script>\n<img src=x onerror="window.__pwned = 2">\nkey: {{ .VMName }} & <b>bold</b>'
    installController([profile({ template: hostile })])
    renderView()
    fireEvent.click(await screen.findByTestId('hvp-pick-linux-cloud-base'))
    const tpl = await screen.findByTestId('hvp-template')
    await waitFor(() => expect(tpl.textContent).toContain('<script>window.__pwned = 1</script>'))
    expect(tpl.textContent).toContain('<img src=x onerror="window.__pwned = 2">')
    expect(tpl.textContent).toContain('key: {{ .VMName }} & <b>bold</b>')
    // Nothing in the template became an element.
    expect(tpl.querySelector('script, img, b')).toBeNull()
    expect((window as unknown as { __pwned?: number }).__pwned).toBeUndefined()
    // One numbered line per template line.
    expect(within(tpl).getAllByTestId('hvp-ln')).toHaveLength(3)
  })

  it('shows the loading state, then the empty state with a way to create', async () => {
    installController([])
    renderView()
    expect(screen.getByTestId('hvp-loading')).toBeInTheDocument()
    expect(await screen.findByTestId('hvp-empty')).toHaveTextContent(/no profiles in acme-corp/i)
    fireEvent.click(within(screen.getByTestId('hvp-empty')).getByRole('button', { name: /new profile/i }))
    expect(await screen.findByTestId('hvp-create')).toBeInTheDocument()
  })

  it('shows an error card on a failed list and recovers on retry', async () => {
    fetchMock.mockResolvedValueOnce(jsonResponse(500, { error: { code: 'INTERNAL_ERROR', message: 'Failed to list' } }))
    renderView()
    expect(await screen.findByTestId('hvp-error')).toHaveTextContent(/could not load profiles/i)
    installController([profile()])
    fireEvent.click(screen.getByTestId('hvp-retry'))
    expect(await screen.findByTestId('hvp-pick-linux-cloud-base')).toBeInTheDocument()
    expect(screen.queryByTestId('hvp-error')).toBeNull()
  })

  it('shows TENANT_REQUIRED as an error state and sends no tenant when none is in scope', async () => {
    fetchMock.mockResolvedValue(
      jsonResponse(400, { error: { code: 'TENANT_REQUIRED', message: 'tenant is required: pass ?tenant=<id>' } }),
    )
    renderView('')
    const err = await screen.findByTestId('hvp-error')
    expect(err).toHaveTextContent(/choose a tenant/i)
    expect(err).toHaveTextContent('tenant is required')
    expect(String(fetchMock.mock.calls[0]?.[0])).toBe(base)
    // Nothing can be created without a tenant to create it in.
    expect(screen.queryByTestId('hvp-new-btn')).toBeNull()
  })

  it('create and delete send X-Presence-Token after the tap', async () => {
    stubPasskey()
    const ctl = installController([profile({ name: 'old-one', enroll: noEnroll, template: 'old' })])
    ctl.presenceToken = 'tap-token-1'
    renderView()

    // ---- create: Write → Review → tap ----
    await writeProfile()
    fireEvent.click(screen.getByTestId('hvp-review-btn'))
    expect(await screen.findByTestId('hvp-review')).toBeInTheDocument()
    expect(callsTo('POST')).toHaveLength(0)
    const createBtn = screen.getByTestId('hvp-create-btn')
    expect(createBtn).toBeDisabled()
    fireEvent.click(screen.getByTestId('hvp-ack'))
    expect(createBtn).toBeEnabled()
    fireEvent.click(createBtn)

    await waitFor(() => expect(screen.getByTestId('step-up-overlay')).toBeInTheDocument())
    // Nothing is stored until the admin taps.
    expect(callsTo('POST')).toHaveLength(1)
    expect(new Headers(callsTo('POST')[0]?.[1]?.headers).get('X-Presence-Token')).toBeNull()
    expect(ctl.profiles.has('linux-cloud-base')).toBe(false)
    fireEvent.click(await screen.findByTestId('step-up-verify-btn'))

    expect(await screen.findByTestId('hvp-status')).toHaveTextContent(/linux-cloud-base created/i)
    const posts = callsTo('POST')
    expect(posts).toHaveLength(2)
    expect(new Headers(posts[1]?.[1]?.headers).get('X-Presence-Token')).toBe('tap-token-1')
    expect(String(posts[1]?.[0])).toBe(`${base}?tenant=acme-corp`)
    expect(JSON.parse(String(posts[1]?.[1]?.body))).toEqual(profile())
    expect(ctl.profiles.has('linux-cloud-base')).toBe(true)
    // The new profile is listed and selected.
    expect(await screen.findByTestId('hvp-detail-name')).toHaveTextContent('linux-cloud-base')

    // ---- delete: inline confirm → tap ----
    fireEvent.click(await screen.findByTestId('hvp-delete-old-one'))
    expect(callsTo('DELETE')).toHaveLength(0)
    fireEvent.click(await screen.findByTestId('hvp-confirm-delete'))
    await waitFor(() => expect(screen.getByTestId('step-up-overlay')).toBeInTheDocument())
    expect(callsTo('DELETE')).toHaveLength(1)
    expect(ctl.profiles.has('old-one')).toBe(true)
    fireEvent.click(await screen.findByTestId('step-up-verify-btn'))

    await waitFor(() => expect(screen.getByTestId('hvp-status')).toHaveTextContent(/old-one deleted/i))
    const deletes = callsTo('DELETE')
    expect(deletes).toHaveLength(2)
    expect(new Headers(deletes[1]?.[1]?.headers).get('X-Presence-Token')).toBe('tap-token-1')
    expect(String(deletes[1]?.[0])).toBe(`${base}/old-one?tenant=acme-corp`)
    expect(ctl.profiles.has('old-one')).toBe(false)
    await waitFor(() => expect(screen.queryByTestId('hvp-pick-old-one')).toBeNull())
  })

  it('keeps Create disabled until the whole template is acknowledged, and lists what runs', async () => {
    installController([])
    renderView()
    await writeProfile()
    fireEvent.click(screen.getByTestId('hvp-review-btn'))
    const review = await screen.findByTestId('hvp-review')
    expect(review).toHaveTextContent(/runs as root on first boot/i)
    // The whole template, numbered, as text.
    expect(within(screen.getByTestId('hvp-review-template')).getAllByTestId('hvp-ln')).toHaveLength(3)
    // Placeholders and secret references are listed; enrollment is in its own box.
    const vars = screen.getByTestId('hvp-vars')
    expect(vars).toHaveTextContent('.CorrelationID')
    const secret = within(vars).getByTestId('hvp-var-secret')
    expect(secret).toHaveTextContent('secret "hyperv/apt-mirror-password"')
    expect(screen.getByTestId('hvp-enroll')).toHaveTextContent('hyperv/enroll/regtoken')
    expect(screen.getByTestId('hvp-create-btn')).toBeDisabled()
    // Un-ticking disables it again.
    fireEvent.click(screen.getByTestId('hvp-ack'))
    expect(screen.getByTestId('hvp-create-btn')).toBeEnabled()
    fireEvent.click(screen.getByTestId('hvp-ack'))
    expect(screen.getByTestId('hvp-create-btn')).toBeDisabled()
    expect(callsTo('POST')).toHaveLength(0)
  })

  it('goes back to edit from review with every field kept', async () => {
    installController([])
    renderView()
    await writeProfile({ name: 'keep-me' })
    fireEvent.click(screen.getByTestId('hvp-review-btn'))
    fireEvent.click(await screen.findByTestId('hvp-back-btn'))
    expect(screen.getByTestId('hvp-name')).toHaveValue('keep-me')
    expect(screen.getByTestId('hvp-template-input')).toHaveValue(profile().template)
    expect(screen.getByTestId('hvp-enroll-label')).toHaveValue('vm-build')
  })

  it('validates the name and template before the review step', async () => {
    installController([])
    renderView()
    await writeProfile({ name: 'bad name!', template: 'x' })
    fireEvent.click(screen.getByTestId('hvp-review-btn'))
    expect(await screen.findByTestId('hvp-form-error')).toHaveTextContent(/letters, digits/i)
    expect(screen.queryByTestId('hvp-review')).toBeNull()
    fireEvent.change(screen.getByTestId('hvp-name'), { target: { value: 'ok-name' } })
    fireEvent.change(screen.getByTestId('hvp-template-input'), { target: { value: '   ' } })
    fireEvent.click(screen.getByTestId('hvp-review-btn'))
    expect(await screen.findByTestId('hvp-form-error')).toHaveTextContent(/template is required/i)
    expect(callsTo('POST')).toHaveLength(0)
  })

  it('refuses a name that already exists, since profiles cannot be edited', async () => {
    installController([profile()])
    renderView()
    await screen.findByTestId('hvp-pick-linux-cloud-base')
    await writeProfile({ name: 'linux-cloud-base' })
    fireEvent.click(screen.getByTestId('hvp-review-btn'))
    expect(await screen.findByTestId('hvp-form-error')).toHaveTextContent(/already exists.*cannot be edited/i)
    expect(screen.queryByTestId('hvp-review')).toBeNull()
  })

  it('switching the OS family changes the formats offered and who the template runs as', async () => {
    installController([])
    renderView()
    fireEvent.click(await screen.findByTestId('hvp-new-btn'))
    const format = await screen.findByTestId('hvp-format')
    expect(within(format).getAllByRole('option').map((o) => o.textContent)).toEqual(['cloud-init', 'preseed'])
    expect(screen.getByTestId('hvp-runs-as')).toHaveTextContent('root')
    fireEvent.click(screen.getByTestId('hvp-os-windows'))
    expect(within(screen.getByTestId('hvp-format')).getAllByRole('option').map((o) => o.textContent)).toEqual([
      'autounattend',
    ])
    expect(screen.getByTestId('hvp-runs-as')).toHaveTextContent('SYSTEM')
  })

  it('shows the server validation error on the write step and stores nothing', async () => {
    const ctl = installController([])
    ctl.nextPost = jsonResponse(400, {
      error: {
        code: 'INVALID_TEMPLATE',
        message: 'hyperv: invalid profile template: template: x:3: function "secrt" not defined',
      },
    })
    renderView()
    await writeProfile()
    fireEvent.click(screen.getByTestId('hvp-review-btn'))
    fireEvent.click(await screen.findByTestId('hvp-ack'))
    fireEvent.click(screen.getByTestId('hvp-create-btn'))
    const err = await screen.findByTestId('hvp-form-error')
    expect(err).toHaveTextContent(/not created\. nothing was saved/i)
    expect(err).toHaveTextContent('INVALID_TEMPLATE')
    expect(err).toHaveTextContent('function "secrt" not defined')
    // Back on the write step with the template intact for fixing.
    expect(screen.getByTestId('hvp-template-input')).toHaveValue(profile().template)
    expect(ctl.profiles.size).toBe(0)
  })

  it('a cancelled passkey tap creates nothing and stays on the review step', async () => {
    stubPasskey()
    const ctl = installController([])
    ctl.presenceToken = 'never-issued'
    renderView()
    await writeProfile()
    fireEvent.click(screen.getByTestId('hvp-review-btn'))
    fireEvent.click(await screen.findByTestId('hvp-ack'))
    fireEvent.click(screen.getByTestId('hvp-create-btn'))
    await waitFor(() => expect(screen.getByTestId('step-up-overlay')).toBeInTheDocument())
    fireEvent.click(await screen.findByTestId('step-up-cancel-btn'))
    expect(await screen.findByTestId('hvp-review-error')).toHaveTextContent(/cancelled/i)
    expect(screen.getByTestId('hvp-review')).toBeInTheDocument()
    expect(ctl.profiles.size).toBe(0)
    expect(callsTo('POST')).toHaveLength(1)
  })

  it('cancelling the create flow returns to the list without a request', async () => {
    installController([profile()])
    renderView()
    fireEvent.click(await screen.findByTestId('hvp-new-btn'))
    fireEvent.click(await screen.findByTestId('hvp-cancel-btn'))
    expect(screen.queryByTestId('hvp-create')).toBeNull()
    expect(await screen.findByTestId('hvp-pick-linux-cloud-base')).toBeInTheDocument()
    expect(callsTo('POST')).toHaveLength(0)
  })

  it('delete needs the inline confirm: Keep sends nothing', async () => {
    installController([profile()])
    renderView()
    fireEvent.click(await screen.findByTestId('hvp-delete-linux-cloud-base'))
    expect(screen.getByTestId('hvp-confirm')).toHaveTextContent(/delete linux-cloud-base\?/i)
    fireEvent.click(screen.getByTestId('hvp-keep'))
    expect(screen.queryByTestId('hvp-confirm')).toBeNull()
    expect(callsTo('DELETE')).toHaveLength(0)
  })

  it('shows a failed delete in the confirm row and keeps the profile listed', async () => {
    const ctl = installController([profile()])
    renderView()
    fireEvent.click(await screen.findByTestId('hvp-delete-linux-cloud-base'))
    ctl.profiles.delete('linux-cloud-base')
    fireEvent.click(screen.getByTestId('hvp-confirm-delete'))
    expect(await screen.findByTestId('hvp-delete-error')).toHaveTextContent(/not found/i)
    expect(screen.getByTestId('hvp-confirm')).toBeInTheDocument()
  })

  it('the detail pane Delete opens the same inline confirm', async () => {
    installController([profile()])
    renderView()
    fireEvent.click(await screen.findByTestId('hvp-pick-linux-cloud-base'))
    fireEvent.click(await screen.findByTestId('hvp-detail-delete'))
    expect(screen.getByTestId('hvp-confirm')).toHaveTextContent(/delete linux-cloud-base\?/i)
    expect(callsTo('DELETE')).toHaveLength(0)
  })
})
