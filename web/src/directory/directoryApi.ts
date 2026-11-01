// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz

/*
 * Directory read client (Issue #5565) — the #5557 routes under
 * /api/v1/directory and nothing else. Every response is untrusted wire data:
 * each parser validates shape and keeps only strings/booleans, and the views
 * render every value as a text node (never markup).
 *
 * A 404 is a neutral outcome, not an error: the server answers 404 for an
 * object that does not exist and for one owned by another tenant alike, so the
 * client reports `notFound` and the view shows a neutral "not available" state.
 * Any other non-2xx response throws a DirectoryError for the Error state.
 */
import { apiFetch, unwrapEnvelope } from '../api/client.ts'

export type DirectoryKind = 'users' | 'groups'
export type DirectorySource = 'ad' | 'm365'

export interface DirectoryObject {
  source: string
  kind: string
  id: string
  authority: string
  displayName: string
  samAccountName: string
  userPrincipalName: string
  mail: string
  enabled: boolean | null
  managed: boolean
  lastObserved: string
  stale: boolean
}

export interface GroupRef {
  id: string
  displayName: string
}

export interface GroupMember {
  id: string
  type: string
  displayName: string
}

export interface Paged<T> {
  items: T[]
  nextPageToken: string
}

export type DirectoryResult<T> = { status: 'ok'; value: T } | { status: 'notFound' }

export interface ListParams {
  q?: string
  source?: DirectorySource | ''
  managed?: 'true' | 'false' | ''
  limit?: number
  pageToken?: string
}

export class DirectoryError extends Error {
  readonly httpStatus: number
  constructor(message: string, httpStatus: number) {
    super(message)
    this.name = 'DirectoryError'
    this.httpStatus = httpStatus
  }
}

const BASE = '/api/v1/directory'

/** Query string for a list/page request; empty filters are omitted. */
export function buildListQuery(params: ListParams): string {
  const query = new URLSearchParams()
  const q = params.q?.trim() ?? ''
  if (q !== '') query.set('q', q)
  if (params.source) query.set('source', params.source)
  if (params.managed) query.set('managed', params.managed)
  if (params.limit !== undefined) query.set('limit', String(params.limit))
  if (params.pageToken) query.set('page_token', params.pageToken)
  const text = query.toString()
  return text === '' ? '' : `?${text}`
}

function str(value: unknown): string {
  return typeof value === 'string' ? value : ''
}

function record(value: unknown): Record<string, unknown> | null {
  return typeof value === 'object' && value !== null ? (value as Record<string, unknown>) : null
}

export function parseObject(value: unknown): DirectoryObject | null {
  const r = record(value)
  if (r === null || typeof r.id !== 'string' || r.id === '') return null
  return {
    source: str(r.source),
    kind: str(r.kind),
    id: r.id,
    authority: str(r.authority),
    displayName: str(r.display_name),
    samAccountName: str(r.sam_account_name),
    userPrincipalName: str(r.user_principal_name),
    mail: str(r.mail),
    enabled: typeof r.enabled === 'boolean' ? r.enabled : null,
    managed: r.managed === true,
    lastObserved: str(r.last_observed),
    stale: r.stale === true,
  }
}

function parseGroupRef(value: unknown): GroupRef | null {
  const r = record(value)
  if (r === null || typeof r.id !== 'string' || r.id === '') return null
  return { id: r.id, displayName: str(r.display_name) }
}

function parseMember(value: unknown): GroupMember | null {
  const r = record(value)
  if (r === null || typeof r.id !== 'string' || r.id === '') return null
  return { id: r.id, type: str(r.type), displayName: str(r.display_name) }
}

function parsePage<T>(
  data: unknown,
  field: string,
  parseItem: (v: unknown) => T | null,
): Paged<T> {
  const r = record(data)
  if (r === null) throw new Error('unexpected response shape')
  const raw: unknown = Object.entries(r).find(([k]) => k === field)?.[1]
  // The server omits an empty list on some responses; absence is an empty page.
  if (raw !== undefined && raw !== null && !Array.isArray(raw)) {
    throw new Error('unexpected response shape')
  }
  const items = ((raw as unknown[] | null | undefined) ?? [])
    .map(parseItem)
    .filter((item): item is T => item !== null)
  return { items, nextPageToken: str(r.next_page_token) }
}

async function getPage<T>(
  path: string,
  field: string,
  parseItem: (v: unknown) => T | null,
): Promise<DirectoryResult<Paged<T>>> {
  const response = await apiFetch(path)
  if (response.status === 404) return { status: 'notFound' }
  if (!response.ok) throw new DirectoryError(`GET ${path.split('?')[0]} — ${response.status}`, response.status)
  const body: unknown = await response.json()
  return { status: 'ok', value: parsePage(unwrapEnvelope<unknown>(body), field, parseItem) }
}

function segment(value: string): string {
  return encodeURIComponent(value)
}

export function listDirectory(
  kind: DirectoryKind,
  params: ListParams,
): Promise<DirectoryResult<Paged<DirectoryObject>>> {
  return getPage(`${BASE}/${kind}${buildListQuery(params)}`, 'items', parseObject)
}

export function listUserGroups(
  source: string,
  id: string,
  params: ListParams,
): Promise<DirectoryResult<Paged<GroupRef>>> {
  const { limit, pageToken } = params
  return getPage(
    `${BASE}/users/${segment(source)}/${segment(id)}/groups${buildListQuery({ limit, pageToken })}`,
    'groups',
    parseGroupRef,
  )
}

export function listGroupMembers(
  source: string,
  id: string,
  params: ListParams,
): Promise<DirectoryResult<Paged<GroupMember>>> {
  const { limit, pageToken } = params
  return getPage(
    `${BASE}/groups/${segment(source)}/${segment(id)}/members${buildListQuery({ limit, pageToken })}`,
    'members',
    parseMember,
  )
}

/**
 * Whether the caller holds directory:read, probed with a one-row list read of
 * the #5557 users route. Only a 2xx grants; 401/403/404/network failure all
 * resolve false, so the navigation entry stays hidden unless access is proven.
 */
export async function probeDirectoryAccess(): Promise<boolean> {
  try {
    const response = await apiFetch(`${BASE}/users${buildListQuery({ limit: 1 })}`)
    return response.ok
  } catch {
    return false
  }
}
