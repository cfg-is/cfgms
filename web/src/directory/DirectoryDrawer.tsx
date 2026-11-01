// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz

/*
 * Directory row drawer (Issue #5565): the overlay shown when a Users or Groups
 * row is selected. A user's drawer lists the user's groups, a group's drawer
 * its direct members; both page through the #5557 endpoints with a load-more
 * control and use the fleet drawer chrome (`.det`, `.dh`, `.db`).
 *
 * Every value is a text node — no markup injection (see DirectoryPage).
 */
import { useEffect, useState } from 'react'
import { ErrorNotice, LoadingRows } from '../fleet/FleetStates.tsx'
import {
  listGroupMembers,
  listUserGroups,
  type DirectoryKind,
  type DirectoryObject,
} from './directoryApi.ts'

const DRAWER_LIMIT = 100

interface Entry {
  id: string
  name: string
  type?: string
}

interface ListState {
  entries: Entry[]
  next: string
  loading: boolean
  error: string | null
  notFound: boolean
}

const INITIAL: ListState = { entries: [], next: '', loading: true, error: null, notFound: false }

function useRelated(kind: DirectoryKind, object: DirectoryObject) {
  const [state, setState] = useState<ListState>(INITIAL)
  const [request, setRequest] = useState<{ token: string; nonce: number }>({ token: '', nonce: 0 })

  useEffect(() => {
    let cancelled = false
    const params = { limit: DRAWER_LIMIT, pageToken: request.token }
    const load =
      kind === 'users'
        ? listUserGroups(object.source, object.id, params).then((result) =>
            result.status === 'ok'
              ? {
                  entries: result.value.items.map((g): Entry => ({ id: g.id, name: g.displayName })),
                  next: result.value.nextPageToken,
                }
              : null,
          )
        : listGroupMembers(object.source, object.id, params).then((result) =>
            result.status === 'ok'
              ? {
                  entries: result.value.items.map(
                    (m): Entry => ({ id: m.id, name: m.displayName, type: m.type }),
                  ),
                  next: result.value.nextPageToken,
                }
              : null,
          )
    load
      .then((page) => {
        if (cancelled) return
        setState((was) =>
          page === null
            ? { ...INITIAL, loading: false, notFound: true }
            : {
                entries: request.token === '' ? page.entries : [...was.entries, ...page.entries],
                next: page.next,
                loading: false,
                error: null,
                notFound: false,
              },
        )
      })
      .catch((cause: unknown) => {
        if (cancelled) return
        setState((was) => ({
          ...was,
          loading: false,
          error: cause instanceof Error && cause.message ? cause.message : 'request failed',
        }))
      })
    return () => {
      cancelled = true
    }
  }, [kind, object.source, object.id, request])

  return {
    state,
    loadMore: () => {
      setState((was) => ({ ...was, loading: true, error: null }))
      setRequest((r) => ({ token: state.next, nonce: r.nonce + 1 }))
    },
    retry: () => {
      setState((was) => ({ ...was, loading: true, error: null }))
      setRequest((r) => ({ token: r.token, nonce: r.nonce + 1 }))
    },
  }
}

export default function DirectoryDrawer({
  kind,
  object,
  onClose,
}: {
  kind: DirectoryKind
  object: DirectoryObject
  onClose: () => void
}) {
  const { state, loadMore, retry } = useRelated(kind, object)
  const isUsers = kind === 'users'
  const heading = isUsers ? 'Groups' : 'Members'
  const name = object.displayName || object.samAccountName || object.id

  useEffect(() => {
    function onKey(e: KeyboardEvent) {
      if (e.key === 'Escape') onClose()
    }
    document.addEventListener('keydown', onKey)
    return () => document.removeEventListener('keydown', onKey)
  }, [onClose])

  const first = state.entries.length === 0

  return (
    <>
      <div
        className="scrim det-scrim"
        data-testid="drawer-scrim"
        onClick={onClose}
        aria-hidden="true"
      />
      <aside className="det" data-testid="directory-drawer" role="dialog" aria-label={`Details: ${name}`}>
        <div className="dh">
          <span className="nm">{name}</span>
          <button
            type="button"
            className="icobtn x"
            style={{ width: 30, height: 30, marginLeft: 'auto' }}
            aria-label="Close drawer"
            data-testid="drawer-close"
            onClick={onClose}
          >
            <svg width="15" height="15" viewBox="0 0 24 24" fill="none" aria-hidden="true">
              <path d="M6 6l12 12M18 6L6 18" stroke="currentColor" strokeWidth="1.8" strokeLinecap="round" />
            </svg>
          </button>
        </div>
        <div className="db" style={{ flex: 1, overflow: 'auto' }}>
          <h3>{heading}</h3>
          {state.loading && first ? (
            <LoadingRows label={`Loading ${heading.toLowerCase()}`} />
          ) : state.error !== null && first ? (
            <ErrorNotice
              detail={state.error}
              onRetry={retry}
              message={`The ${heading.toLowerCase()} request failed. Check your connection and try again.`}
            />
          ) : state.notFound ? (
            <div className="notice empty" data-testid="drawer-not-available">
              <p>{heading} are not available for this object.</p>
            </div>
          ) : first ? (
            <div className="notice empty" data-testid="drawer-empty">
              <p>{isUsers ? 'This user is not in any synced group.' : 'This group has no direct members.'}</p>
            </div>
          ) : (
            <ul data-testid="drawer-list">
              {state.entries.map((entry) => (
                <li key={`${entry.type ?? ''}/${entry.id}`}>
                  <span className="nm">{entry.name || entry.id}</span>
                  {entry.type !== undefined && entry.type !== '' && (
                    <>
                      {' '}
                      <span className="tag">{entry.type}</span>
                    </>
                  )}
                </li>
              ))}
            </ul>
          )}
          {state.error !== null && !first && (
            <p role="alert" className="mut">
              Couldn&apos;t load more ({state.error}).{' '}
              <button type="button" className="btn" onClick={retry}>
                Retry
              </button>
            </p>
          )}
          {state.next !== '' && state.error === null && (
            <button type="button" className="btn" disabled={state.loading} onClick={loadMore}>
              Load more
            </button>
          )}
        </div>
      </aside>
    </>
  )
}
