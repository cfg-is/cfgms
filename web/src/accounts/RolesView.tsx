// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz

/*
 * Read-only roles view (Issue #2733) — surfaces GET /api/v1/rbac/roles
 * and each role's permission list. No create/update/delete exposed here
 * per the story scope; RBAC role CRUD already exists in handlers_rbac.go.
 *
 * Security A9.1: role name and description originate from user-supplied
 * content. Every value reaches the DOM as a JSX text node only.
 */
import { useState } from 'react'
import { useRoleList, type RoleInfo } from './useWebAccounts.ts'

function LoadingRows() {
  return (
    <div data-testid="roles-loading" aria-label="Loading roles">
      {Array.from({ length: 3 }, (_, i) => (
        <div className="skrow" key={i}>
          <span className="skel" style={{ width: '40%' }} />
          <span className="skel" style={{ width: '55%' }} />
          <span className="skel" style={{ width: '30%' }} />
        </div>
      ))}
    </div>
  )
}

function ErrorNotice({ detail, onRetry }: { detail: string; onRetry: () => void }) {
  return (
    <div className="notice err" role="alert">
      <div className="ic">!</div>
      <h3>Couldn&apos;t load roles</h3>
      <p>The role list request failed. Check your connection and try again.</p>
      <span className="mono2 detail">{detail}</span>
      <button type="button" className="btn" onClick={onRetry}>
        Retry
      </button>
    </div>
  )
}

function RolesEmpty() {
  return (
    <div className="notice empty" data-testid="roles-empty">
      <div className="ic">◍</div>
      <h3>No roles found</h3>
      <p>No roles have been created yet.</p>
    </div>
  )
}

function RoleRow({
  role,
  selected,
  onClick,
}: {
  role: RoleInfo
  selected: boolean
  onClick: () => void
}) {
  return (
    <>
      <tr
        className={selected ? 'selected' : ''}
        onClick={onClick}
        style={{ cursor: 'pointer' }}
        data-testid="role-row"
      >
        <td>
          <span className="nm">{role.name}</span>
        </td>
        <td>
          <span className="mono2">{role.tenant_id || '—'}</span>
        </td>
        <td>
          <span className="mut">{role.description || '—'}</span>
        </td>
        <td>
          <span className="mono2">{role.permissions.length}</span>
        </td>
      </tr>
      {selected && (
        <tr data-testid="role-permissions-row">
          <td colSpan={4} style={{ paddingTop: 0 }}>
            <div className="wf-form-panel" style={{ margin: '4px 0 8px' }}>
              <div style={{ padding: '8px 12px' }}>
                <span className="wf-form-label">Permissions</span>
                {role.permissions.length === 0 ? (
                  <span className="mut" style={{ marginLeft: 8 }}>None</span>
                ) : (
                  <ul style={{ margin: '6px 0 0', paddingLeft: 20 }}>
                    {role.permissions.map((p) => (
                      <li key={p}>
                        <span className="mono2">{p}</span>
                      </li>
                    ))}
                  </ul>
                )}
              </div>
            </div>
          </td>
        </tr>
      )}
    </>
  )
}

export default function RolesView() {
  const { roles, loading, error, retry } = useRoleList()
  const [selectedId, setSelectedId] = useState<string | null>(null)

  function handleRowClick(id: string) {
    setSelectedId((prev) => (prev === id ? null : id))
  }

  return (
    <section className="panel">
      <div className="ptool">
        {!loading && error === null && (
          <span className="cnt" data-testid="role-count">
            {roles.length} role{roles.length !== 1 ? 's' : ''}
          </span>
        )}
      </div>

      {loading ? (
        <LoadingRows />
      ) : error !== null ? (
        <ErrorNotice detail={error} onRetry={retry} />
      ) : roles.length === 0 ? (
        <RolesEmpty />
      ) : (
        <table className="tbl" data-testid="roles-table">
          <thead>
            <tr>
              <th>Name</th>
              <th>Tenant</th>
              <th>Description</th>
              <th>Permissions</th>
            </tr>
          </thead>
          <tbody>
            {roles.map((role) => (
              <RoleRow
                key={role.id}
                role={role}
                selected={selectedId === role.id}
                onClick={() => handleRowClick(role.id)}
              />
            ))}
          </tbody>
        </table>
      )}
    </section>
  )
}
