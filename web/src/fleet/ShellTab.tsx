// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz

/*
 * ShellTab (Story #2762) — interactive remote terminal to a steward over
 * GET /api/v1/terminal/ws/{stewardId} (ws:// or wss://).
 *
 * Wire protocol: JSON TerminalMessage envelopes (features/terminal/types.go).
 *   data frames:   {"type":"data","data":"<base64-encoded bytes>"}
 *   resize frames: {"type":"resize","data":"<base64(JSON({cols,rows}))>"}
 *   close frames:  {"type":"close"}
 *   error frames from server: {"type":"error","error":"<text>"}
 * Go JSON encodes []byte fields as base64 strings; the browser must send
 * the same encoding when writing to the server.
 *
 * Lifecycle: WebSocket opens on mount, closes on unmount (no background
 * shells after the operator navigates away — ADR-018).
 *
 * Auth: same-origin cookie auth per ADR-018 plus a one-time ticket: before
 * the socket exists the tab runs terminal prepare, the passkey ceremony and
 * the ticket request, then offers the ticket as a subprotocol (never in the URL).
 *
 * 403 detection: when the WS upgrade returns HTTP 403 the browser fires
 * onerror then onclose before onopen ever fires.  We treat "close without
 * ever connecting" and explicit close code 4403 as "denied".
 *
 * Resize: FitAddon + ResizeObserver fit the xterm canvas to the container
 * on every layout change; each resize triggers a TerminalMessage of type
 * "resize" so the server-side PTY tracks the operator's window dimensions.
 */

import { useEffect, useRef, useState } from 'react'
import { Terminal, type ITheme } from '@xterm/xterm'
import { FitAddon } from '@xterm/addon-fit'
import '@xterm/xterm/css/xterm.css'
import './ShellTab.css'
import {
  ControlHttpError,
  NoPasskeyError,
  SignCancelledError,
  postJson,
  signPrepared,
} from './signAction.ts'

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

type ConnState = 'connecting' | 'connected' | 'disconnected' | 'denied'

const TERMINAL_SUBPROTOCOL = 'cfgms.terminal.v1'
const TICKET_SUBPROTOCOL_PREFIX = 'cfgms.ticket.'

interface PrepareResponse {
  content: string
  shell: string
  terminal_shell: string
}

/** Confirms prepare's content opens a terminal on this steward with the resolved shell. */
function contentNamesTerminal(content: string, stewardId: string, shell: string): boolean {
  try {
    const parsed = JSON.parse(atob(content)) as {
      verb?: string
      target_kind?: string
      target_name?: string
      parameters?: Record<string, string>
    }
    return (
      parsed.verb === 'terminal.open' &&
      parsed.target_kind === 'steward' &&
      parsed.target_name === stewardId &&
      shell !== '' &&
      parsed.parameters?.shell === shell
    )
  } catch {
    return false
  }
}

/** Prepare, passkey ceremony and ticket request; returns the one-time ticket. */
async function obtainTicket(stewardId: string, isCancelled: () => boolean): Promise<string> {
  const stop = () => { if (isCancelled()) throw new SignCancelledError() }
  const id = encodeURIComponent(stewardId)
  const prepared = await postJson<PrepareResponse>(`/api/v1/terminal/prepare/${id}`, {
    terminal_shell: '',
  })
  stop()
  if (!contentNamesTerminal(prepared.content, stewardId, prepared.terminal_shell)) {
    throw new Error('prepared content does not match this terminal')
  }
  const proof = await signPrepared(stewardId, prepared.content, prepared.shell)
  stop()
  const res = await postJson<{ ticket: string }>(`/api/v1/terminal/tickets/${id}`, {
    terminal_shell: prepared.terminal_shell,
    nonce: proof.nonce,
    expires_at: proof.expires_at,
    targets: proof.targets,
    webauthn: proof.webauthn,
  })
  return res.ticket
}

interface TerminalWireMsg {
  type: string
  data?: string
  error?: string
}

// ---------------------------------------------------------------------------
// Base64 helpers (Go JSON encodes []byte as base64)
// ---------------------------------------------------------------------------

function encodeBase64(str: string): string {
  const bytes = new TextEncoder().encode(str)
  let binary = ''
  bytes.forEach((b) => { binary += String.fromCharCode(b) })
  return btoa(binary)
}

function decodeBase64(b64: string): Uint8Array {
  const binary = atob(b64)
  return Uint8Array.from(binary, (c) => c.charCodeAt(0))
}

function sendResize(ws: WebSocket, cols: number, rows: number): void {
  const json = JSON.stringify({ cols, rows })
  ws.send(JSON.stringify({ type: 'resize', data: encodeBase64(json) }))
}

// ---------------------------------------------------------------------------
// Theme — xterm cannot read CSS variables itself, so resolve the design
// tokens to concrete colours (docs/design/web-ui-design-tokens.css).
// ---------------------------------------------------------------------------

export function readTerminalTheme(): ITheme {
  const style = getComputedStyle(document.documentElement)
  const token = (name: string) => style.getPropertyValue(name).trim()
  const accent = token('--accent')
  return {
    background: token('--bg-sunk'),
    foreground: token('--text-primary'),
    cursor: accent,
    cursorAccent: token('--bg-sunk'),
    // 30% alpha over the terminal ground (#rrggbb + 4d).
    selectionBackground: /^#[0-9a-f]{6}$/i.test(accent) ? `${accent}4d` : accent,
  }
}

// ---------------------------------------------------------------------------
// Sub-components
// ---------------------------------------------------------------------------

function connPillConfig(state: ConnState): { cls: string; label: string } {
  switch (state) {
    case 'connected':    return { cls: 'ok',   label: 'Connected' }
    case 'connecting':   return { cls: 'warn', label: 'Connecting…' }
    case 'disconnected': return { cls: 'crit', label: 'Disconnected' }
    case 'denied':       return { cls: 'crit', label: 'Denied' }
  }
}

function ConnPill({ state }: { state: ConnState }) {
  const { cls, label } = connPillConfig(state)
  return (
    <span className={`shell-tab-conn ${cls}`}>
      <span className="shell-tab-conn-dot" aria-hidden="true" />
      {label}
    </span>
  )
}

// ---------------------------------------------------------------------------
// Main component
// ---------------------------------------------------------------------------

interface ShellTabProps {
  stewardId: string
}

export default function ShellTab({ stewardId }: ShellTabProps) {
  const containerRef = useRef<HTMLDivElement>(null)
  const terminalRef = useRef<Terminal | null>(null)
  const wsRef = useRef<WebSocket | null>(null)
  const [connState, setConnState] = useState<ConnState>('connecting')
  const [reconnectKey, setReconnectKey] = useState(0)
  const [errorMsg, setErrorMsg] = useState('')

  useEffect(() => {
    const container = containerRef.current
    if (!container) return
    let cancelled = false
    setConnState('connecting')
    setErrorMsg('')

    const terminal = new Terminal({
      fontFamily: '"JetBrains Mono", ui-monospace, "SF Mono", Menlo, monospace',
      fontSize: 13,
      lineHeight: 1.45,
      cursorBlink: true,
      theme: readTerminalTheme(),
    })
    terminalRef.current = terminal

    const fitAddon = new FitAddon()
    terminal.loadAddon(fitAddon)
    terminal.open(container)
    try { fitAddon.fit() } catch { /* jsdom: no layout engine */ }

    // Re-theme when the app toggles data-theme or the OS scheme flips (auto mode).
    const applyTheme = () => { terminal.options.theme = readTerminalTheme() }
    const themeObserver = new MutationObserver(applyTheme)
    themeObserver.observe(document.documentElement, {
      attributes: true,
      attributeFilter: ['data-theme'],
    })
    const scheme = window.matchMedia?.('(prefers-color-scheme: dark)')
    scheme?.addEventListener?.('change', applyTheme)

    const connect = (ticket: string) => {
      const proto = location.protocol === 'https:' ? 'wss:' : 'ws:'
      // Identity is server-derived: the controller reads the operator from the
      // authenticated session context (terminal_handler.go ServeWebSocket), so
      // the client must never assert steward_id/user_id in the query string.
      const url = `${proto}//${location.host}/api/v1/terminal/ws/${encodeURIComponent(stewardId)}`
    
  const ws = new WebSocket(url, [TERMINAL_SUBPROTOCOL, TICKET_SUBPROTOCOL_PREFIX + ticket])
  wsRef.current = ws

      let wasConnected = false

      ws.onopen = () => {
        if (cancelled) return
        wasConnected = true
        setConnState('connected')
        try { fitAddon.fit() } catch { /* jsdom: no layout engine */ }
        if (ws.readyState === WebSocket.OPEN) {
          sendResize(ws, terminal.cols, terminal.rows)
        }
      }

      ws.onmessage = (ev) => {
        if (cancelled) return
        let msg: TerminalWireMsg
        try {
          msg = JSON.parse(ev.data as string) as TerminalWireMsg
        } catch {
          return  /* unparseable frame — ignore */
        }
        if (msg.type === 'data' && msg.data) {
          try { terminal.write(decodeBase64(msg.data)) } catch { /* malformed base64 */ }
        } else if (msg.type === 'error') {
          setConnState('disconnected')
        }
      }

      ws.onclose = (ev) => {
        if (cancelled) return
        // code 4403: explicit RBAC denial.
        // code 0 / no onopen: HTTP-level rejection before upgrade (likely 403).
        if (ev.code === 4403 || !wasConnected) {
          setConnState('denied')
        } else {
          setConnState('disconnected')
        }
      }


    }

    obtainTicket(stewardId, () => cancelled).then(
      (ticket) => { if (!cancelled) connect(ticket) },
      (e: unknown) => {
        if (cancelled) return
        if (e instanceof SignCancelledError) {
          setErrorMsg('The passkey prompt was cancelled, so no shell was opened.')
          setConnState('disconnected')
        } else if (e instanceof NoPasskeyError) {
          setErrorMsg('No passkey is registered for your account. Enrol a passkey to open a remote shell.')
          setConnState('disconnected')
        } else if (e instanceof ControlHttpError && e.status === 403) {
          setConnState('denied')
        } else {
          setErrorMsg('Could not obtain permission to open the shell. Try again.')
          setConnState('disconnected')
        }
      },
    )

    const dataListener = terminal.onData((data) => {
      const ws = wsRef.current
      if (ws && ws.readyState === WebSocket.OPEN) {
        try {
          ws.send(JSON.stringify({ type: 'data', data: encodeBase64(data) }))
        } catch { /* WS may have closed between the readyState check and send */ }
      }
    })

    const resizeListener = terminal.onResize(({ cols, rows }) => {
      const ws = wsRef.current
      if (ws && ws.readyState === WebSocket.OPEN) {
        sendResize(ws, cols, rows)
      }
    })

    const ro = new ResizeObserver(() => {
      try { fitAddon.fit() } catch { /* jsdom: no layout engine */ }
    })
    ro.observe(container)

    return () => {
      cancelled = true
      const ws = wsRef.current
      wsRef.current = null
      terminalRef.current = null
      ro.disconnect()
      themeObserver.disconnect()
      scheme?.removeEventListener?.('change', applyTheme)
      dataListener.dispose()
      resizeListener.dispose()
      ws?.close()
      terminal.dispose()
    }
  }, [stewardId, reconnectKey])

  function onDisconnect() {
    wsRef.current?.close(1000)
    setConnState('disconnected')
  }

  function onReconnect() {
    setReconnectKey((k) => k + 1)
  }

  function onClear() {
    terminalRef.current?.clear()
  }

  function onCopy() {
    const sel = terminalRef.current?.getSelection() ?? ''
    if (sel && navigator.clipboard) {
      navigator.clipboard.writeText(sel).catch(() => {})
    }
  }

  const isActive = connState === 'connected'

  return (
    <div className="shell-tab" data-testid="shell-tab">
      <div className="shell-tab-head">
        <ConnPill state={connState} />
        <span className="shell-tab-meta">
          {stewardId}
        </span>
        <div className="shell-tab-acts">
          <button
            type="button"
            className="shell-tab-btn"
            onClick={onClear}
            disabled={!isActive}
            aria-label="Clear terminal"
          >
            Clear
          </button>
          <button
            type="button"
            className="shell-tab-btn"
            onClick={onCopy}
            disabled={!isActive}
            aria-label="Copy selection"
          >
            Copy
          </button>
          {isActive && (
            <button
              type="button"
              className="shell-tab-btn danger"
              onClick={onDisconnect}
              aria-label="Disconnect shell"
            >
              Disconnect
            </button>
          )}
        </div>
      </div>

      <div className="shell-tab-body">
        <div ref={containerRef} className="shell-tab-xterm" aria-label="Terminal" />

        {connState === 'connecting' && (
          <div className="shell-tab-notice" role="status" aria-live="polite">
            <div className="shell-tab-spinner" aria-hidden="true" />
            <h3>Opening remote shell…</h3>
            <p>
              Establishing an encrypted PTY to <span className="mono2">{stewardId}</span> through
              the controller relay.
            </p>
          </div>
        )}

        {connState === 'disconnected' && (
          <div className="shell-tab-notice" role="alert">
            <div className="shell-tab-notice-icon crit" aria-hidden="true">
              <svg width="22" height="22" viewBox="0 0 24 24" fill="none" aria-hidden="true">
                <path d="M12 3v8" stroke="currentColor" strokeWidth="1.9" strokeLinecap="round" />
                <path d="M6.6 6.6a8 8 0 1 0 10.8 0" stroke="currentColor" strokeWidth="1.9" strokeLinecap="round" />
              </svg>
            </div>
            <h3>{errorMsg ? 'Remote shell not opened' : 'Steward unreachable'}</h3>
            <p>
              {errorMsg ||
                'The remote shell session ended. The steward may be offline or the connection was interrupted.'}
            </p>
            <button
              type="button"
              className="shell-tab-reconnect"
              onClick={onReconnect}
            >
              Reconnect
            </button>
          </div>
        )}

        {connState === 'denied' && (
          <div className="shell-tab-notice" role="alert">
            <div className="shell-tab-notice-icon crit" aria-hidden="true">
              <svg width="22" height="22" viewBox="0 0 24 24" fill="none" aria-hidden="true">
                <rect x="5" y="10.5" width="14" height="9.5" rx="2" stroke="currentColor" strokeWidth="1.8" />
                <path d="M8 10.5V8a4 4 0 0 1 8 0v2.5" stroke="currentColor" strokeWidth="1.8" />
              </svg>
            </div>
            <h3>Remote shell denied</h3>
            <p>
              You do not have permission to open a shell on this steward. Use read-only DNA or
              Live Activity, or ask an operator with remote-shell rights.
            </p>
            <span className="mono2">
              {`/api/v1/terminal/ws/${stewardId} — 403 Forbidden`}
            </span>
          </div>
        )}
      </div>
    </div>
  )
}
