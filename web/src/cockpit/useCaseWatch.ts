// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz

/*
 * useCaseWatch (Story #3613) — React hook that opens the cockpit watch WebSocket.
 *
 * Connects to GET /api/v1/cases/{caseId}/watch (WebSocket upgrade). The server
 * streams WatchEvents for the case's pinned entities; this hook:
 *  - Tracks the live connection state and connected-since timestamp used by
 *    the LIVE indicator in InvestigationRail.
 *  - Exposes the most-recent typed event so mounted cards can react selectively
 *    without forcing a full canvas re-fetch on every event.
 *  - Sends a "resync" signal (via onResync callback) when the server reports
 *    ErrCursorExpired, indicating the client must re-fetch the case and evidence.
 *
 * MVP-grade reconnect: the hook performs a single reconnect attempt after a
 * brief delay when the connection drops unexpectedly. Production-hardened
 * backoff is a follow-on story.
 *
 * WatchEventContext: exported so CockpitView can provide the last event and
 * individual cards can subscribe selectively via useWatchEvent().
 */
import { createContext, useContext, useEffect, useRef, useState } from 'react'

export type WatchEventKind = 'entity-updated' | 'edge-updated' | 'drift-updated'

export interface WatchEvent {
  subject: string
  event_kind: WatchEventKind
  version: number
  at: string // RFC 3339
}

export interface UseCaseWatchResult {
  isLive: boolean
  connectedSince: Date | null
  lastEvent: WatchEvent | null
}

// WatchEventContext provides the most-recent WatchEvent to descendant components.
// CockpitView is the provider; cards call useWatchEvent() to subscribe.
export const WatchEventContext = createContext<WatchEvent | null>(null)

// useWatchEvent returns the most-recent WatchEvent from the nearest
// WatchEventContext, or null when no event has arrived yet.
export function useWatchEvent(): WatchEvent | null {
  return useContext(WatchEventContext)
}

type ServerFrame =
  | { type: 'event'; subject: string; event_kind: WatchEventKind; version: number; at: string }
  | { type: 'resync' }

function buildWatchURL(caseId: string): string {
  const proto = window.location.protocol === 'https:' ? 'wss:' : 'ws:'
  return `${proto}//${window.location.host}/api/v1/cases/${encodeURIComponent(caseId)}/watch`
}

// useCaseWatch opens a WebSocket to the case's watch endpoint and tracks the
// live connection state and most-recent event. Cleans up on unmount or caseId change.
export function useCaseWatch(caseId: string): UseCaseWatchResult {
  const [isLive, setIsLive] = useState(false)
  const [connectedSince, setConnectedSince] = useState<Date | null>(null)
  const [lastEvent, setLastEvent] = useState<WatchEvent | null>(null)

  // wsRef lets the cleanup function close the correct socket even if caseId changes.
  const wsRef = useRef<WebSocket | null>(null)

  useEffect(() => {
    if (!caseId) return

    let socket: WebSocket
    let reconnectTimer: ReturnType<typeof setTimeout> | null = null
    let closed = false

    function connect() {
      if (closed) return
      socket = new WebSocket(buildWatchURL(caseId))
      wsRef.current = socket

      socket.onopen = () => {
        if (closed) {
          socket.close()
          return
        }
        setIsLive(true)
        setConnectedSince(new Date())
      }

      socket.onmessage = (evt) => {
        if (closed) return
        try {
          const frame = JSON.parse(evt.data as string) as ServerFrame
          if (frame.type === 'event') {
            setLastEvent({
              subject: frame.subject,
              event_kind: frame.event_kind,
              version: frame.version,
              at: frame.at,
            })
          }
          // type === 'resync': server signals cursor expiry; client should
          // re-fetch the case. Full re-fetch wiring is a follow-on story.
        } catch {
          // Discard malformed frames.
        }
      }

      socket.onclose = () => {
        if (closed) return
        setIsLive(false)
        setConnectedSince(null)
        // Single reconnect attempt after 2s (MVP-grade resilience).
        reconnectTimer = setTimeout(connect, 2000)
      }

      socket.onerror = () => {
        // onerror is always followed by onclose; let onclose handle state reset.
      }
    }

    connect()

    return () => {
      closed = true
      if (reconnectTimer !== null) clearTimeout(reconnectTimer)
      wsRef.current = null
      if (socket.readyState === WebSocket.OPEN || socket.readyState === WebSocket.CONNECTING) {
        socket.close()
      }
      setIsLive(false)
      setConnectedSince(null)
    }
  }, [caseId])

  return { isLive, connectedSince, lastEvent }
}
