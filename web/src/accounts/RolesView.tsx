// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz

/*
 * Roles view (Issue #2733, #3133) — surfaces GET /api/v1/rbac/roles
 * with full create, edit, and delete. Exposes the inline expand-row
 * pattern for permissions, with Edit/Delete actions in the expanded panel.
 *
 * Security A9.1: role name and description originate from user-supplied
 * content. Every value reaches the DOM as a JSX text node only.
 *
 * M-AUTH-2: create, edit and delete are sensitive operations — each collects a
 * mandatory operator justification (minimum JUSTIFICATION_MIN_LENGTH
 * characters) that is sent with the request and recorded on the audit event.
 */
import { useState } from 'react'
import {
  useRoleList,
  usePermissionList,
  createRole,
  updateRole,
  deleteRole,
  validateJustification,
  JUSTIFICATION_MIN_LENGTH,
  JUSTIFICATION_MAX_LENGTH,
  type RoleInfo,
  type PermissionInfo,
} from './useWebAccounts.ts'

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

function PermissionSelector({
  available,
  selected,
  onChange,
}: {
  available: PermissionInfo[]
  selected: Set<string>
  onChange: (id: string, checked: boolean) => void
}) {
  if (available.length === 0) {
    return <span className="mut" style={{ fontSize: 13 }}>No permissions available</span>
  }
  return (
    <div data-testid="permission-selector" style={{ display: 'flex', flexDirection: 'column', gap: 4 }}>
      {available.map((perm) => (
        <label key={perm.id} style={{ display: 'flex', alignItems: 'center', gap: 6, cursor: 'pointer' }}>
          <input
            type="checkbox"
            checked={selected.has(perm.id)}
            onChange={(e) => onChange(perm.id, e.target.checked)}
          />
          <span className="mono2">{perm.name}</span>
          {perm.description && (
            <span className="mut" style={{ fontSize: 12 }}>{perm.description}</span>
          )}
        </label>
      ))}
    </div>
  )
}

/**
 * Mandatory justification input (M-AUTH-2). Rendered by every role mutation
 * surface: the create panel, the edit form and the delete confirmation.
 */
function JustificationField({
  value,
  onChange,
  testId,
}: {
  value: string
  onChange: (next: string) => void
  testId: string
}) {
  return (
    <div className="wf-form-field">
      <span className="wf-form-label">Justification *</span>
      <input
        type="text"
        aria-label="Justification"
        placeholder="Why this change is needed"
        value={value}
        onChange={(e) => onChange(e.target.value)}
        maxLength={JUSTIFICATION_MAX_LENGTH}
        data-testid={testId}
      />
      <span className="mut" style={{ fontSize: 12 }}>
        Recorded in the audit log — minimum {JUSTIFICATION_MIN_LENGTH} characters.
      </span>
    </div>
  )
}

function CreateRolePanel({
  onSaved,
  onClose,
}: {
  onSaved: () => void
  onClose: () => void
}) {
  const { permissions, loading: permLoading } = usePermissionList()
  const [name, setName] = useState('')
  const [description, setDescription] = useState('')
  const [justification, setJustification] = useState('')
  const [selectedPerms, setSelectedPerms] = useState<Set<string>>(new Set())
  const [saving, setSaving] = useState(false)
  const [saveError, setSaveError] = useState<string | null>(null)

  function togglePerm(id: string, checked: boolean) {
    setSelectedPerms((prev) => {
      const next = new Set(prev)
      if (checked) next.add(id)
      else next.delete(id)
      return next
    })
  }

  async function handleSubmit() {
    if (!name.trim()) {
      setSaveError('Role name is required')
      return
    }
    const justificationError = validateJustification(justification)
    if (justificationError !== null) {
      setSaveError(justificationError)
      return
    }
    setSaving(true)
    setSaveError(null)
    try {
      await createRole(name.trim(), description.trim(), [...selectedPerms], justification)
      onSaved()
    } catch (cause: unknown) {
      setSaveError(cause instanceof Error && cause.message ? cause.message : 'Create failed')
    } finally {
      setSaving(false)
    }
  }

  return (
    <div className="wf-form-panel" data-testid="role-form-panel">
      <div className="wf-form">
        <div className="wf-form-row">
          <div className="wf-form-field">
            <span className="wf-form-label">Role name *</span>
            <input
              type="text"
              aria-label="Role name"
              placeholder="fleet-viewer"
              value={name}
              onChange={(e) => setName(e.target.value)}
              data-testid="role-name-input"
            />
          </div>
          <div className="wf-form-field">
            <span className="wf-form-label">Description</span>
            <input
              type="text"
              aria-label="Description"
              placeholder="Read-only fleet access"
              value={description}
              onChange={(e) => setDescription(e.target.value)}
              data-testid="role-description-input"
            />
          </div>
        </div>
        <div className="wf-form-row">
          <div className="wf-form-field">
            <span className="wf-form-label">Permissions</span>
            {permLoading ? (
              <span className="mut" style={{ fontSize: 13 }}>Loading permissions…</span>
            ) : (
              <PermissionSelector
                available={permissions}
                selected={selectedPerms}
                onChange={togglePerm}
              />
            )}
          </div>
        </div>
        <div className="wf-form-row">
          <JustificationField
            value={justification}
            onChange={setJustification}
            testId="role-justification-input"
          />
        </div>
        <div className="wf-form-actions">
          <button
            type="button"
            className="wf-btn"
            disabled={saving}
            onClick={handleSubmit}
            data-testid="role-save-btn"
          >
            {saving ? 'Creating…' : 'Create role'}
          </button>
          <button type="button" className="wf-btn-secondary" onClick={onClose}>
            Cancel
          </button>
          {saveError && (
            <span className="wf-form-error" data-testid="role-save-error">
              {saveError}
            </span>
          )}
        </div>
      </div>
    </div>
  )
}

function EditRoleForm({
  role,
  onSaved,
  onCancel,
}: {
  role: RoleInfo
  onSaved: () => void
  onCancel: () => void
}) {
  const { permissions, loading: permLoading } = usePermissionList()
  const [name, setName] = useState(role.name)
  const [description, setDescription] = useState(role.description)
  const [justification, setJustification] = useState('')
  const [selectedPerms, setSelectedPerms] = useState<Set<string>>(new Set(role.permissions))
  const [saving, setSaving] = useState(false)
  const [saveError, setSaveError] = useState<string | null>(null)

  function togglePerm(id: string, checked: boolean) {
    setSelectedPerms((prev) => {
      const next = new Set(prev)
      if (checked) next.add(id)
      else next.delete(id)
      return next
    })
  }

  async function handleSave() {
    if (!name.trim()) {
      setSaveError('Role name is required')
      return
    }
    const justificationError = validateJustification(justification)
    if (justificationError !== null) {
      setSaveError(justificationError)
      return
    }
    setSaving(true)
    setSaveError(null)
    try {
      // No tenant_id is sent: the server carries the stored role's tenant
      // attribution into the update and rejects cross-tenant writes itself.
      await updateRole(role.id, name.trim(), description.trim(), [...selectedPerms], justification)
      onSaved()
    } catch (cause: unknown) {
      setSaveError(cause instanceof Error && cause.message ? cause.message : 'Update failed')
    } finally {
      setSaving(false)
    }
  }

  return (
    <div className="wf-form-panel" data-testid="role-edit-panel">
      <div className="wf-form">
        <div className="wf-form-row">
          <div className="wf-form-field">
            <span className="wf-form-label">Role name *</span>
            <input
              type="text"
              aria-label="Role name"
              value={name}
              onChange={(e) => setName(e.target.value)}
              data-testid="role-name-input"
            />
          </div>
          <div className="wf-form-field">
            <span className="wf-form-label">Description</span>
            <input
              type="text"
              aria-label="Description"
              value={description}
              onChange={(e) => setDescription(e.target.value)}
              data-testid="role-description-input"
            />
          </div>
        </div>
        <div className="wf-form-row">
          <div className="wf-form-field">
            <span className="wf-form-label">Permissions</span>
            {permLoading ? (
              <span className="mut" style={{ fontSize: 13 }}>Loading permissions…</span>
            ) : (
              <PermissionSelector
                available={permissions}
                selected={selectedPerms}
                onChange={togglePerm}
              />
            )}
          </div>
        </div>
        <div className="wf-form-row">
          <JustificationField
            value={justification}
            onChange={setJustification}
            testId="role-justification-input"
          />
        </div>
        <div className="wf-form-actions">
          <button
            type="button"
            className="wf-btn"
            disabled={saving}
            onClick={handleSave}
            data-testid="role-update-btn"
          >
            {saving ? 'Saving…' : 'Save changes'}
          </button>
          <button type="button" className="wf-btn-secondary" onClick={onCancel}>
            Cancel
          </button>
          {saveError && (
            <span className="wf-form-error" data-testid="role-edit-error">
              {saveError}
            </span>
          )}
        </div>
      </div>
    </div>
  )
}

function RoleRow({
  role,
  selected,
  editing,
  onClick,
  onEditStart,
  onEditSaved,
  onEditCancel,
  onDeleteRequest,
}: {
  role: RoleInfo
  selected: boolean
  editing: boolean
  onClick: () => void
  onEditStart: () => void
  onEditSaved: () => void
  onEditCancel: () => void
  onDeleteRequest: () => void
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
      {selected && !editing && (
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
              <div
                className="wf-form-actions"
                style={{ paddingTop: 4 }}
                onClick={(e) => e.stopPropagation()}
              >
                <button
                  type="button"
                  className="wf-btn-secondary"
                  onClick={onEditStart}
                  data-testid="role-edit-btn"
                >
                  Edit
                </button>
                <button
                  type="button"
                  className="wf-btn-sm-danger"
                  onClick={onDeleteRequest}
                  data-testid="role-delete-btn"
                >
                  Delete
                </button>
              </div>
            </div>
          </td>
        </tr>
      )}
      {selected && editing && (
        <tr data-testid="role-edit-row">
          <td colSpan={4} style={{ paddingTop: 0 }} onClick={(e) => e.stopPropagation()}>
            <EditRoleForm
              role={role}
              onSaved={onEditSaved}
              onCancel={onEditCancel}
            />
          </td>
        </tr>
      )}
    </>
  )
}

export default function RolesView() {
  const { roles, loading, error, retry } = useRoleList()
  const [selectedId, setSelectedId] = useState<string | null>(null)
  const [editingId, setEditingId] = useState<string | null>(null)
  const [showCreate, setShowCreate] = useState(false)
  const [deletingRole, setDeletingRole] = useState<RoleInfo | null>(null)
  const [deleting, setDeleting] = useState(false)
  const [deleteError, setDeleteError] = useState<string | null>(null)
  const [deleteJustification, setDeleteJustification] = useState('')
  const [deleteJustificationError, setDeleteJustificationError] = useState<string | null>(null)

  function closeDeleteModal() {
    setDeletingRole(null)
    setDeleteJustification('')
    setDeleteJustificationError(null)
  }

  function handleRowClick(id: string) {
    if (editingId === id) return
    setSelectedId((prev) => (prev === id ? null : id))
    setEditingId(null)
  }

  function handleEditStart(id: string) {
    setSelectedId(id)
    setEditingId(id)
  }

  function handleEditSaved() {
    setEditingId(null)
    retry()
  }

  function handleEditCancel() {
    setEditingId(null)
  }

  function handleCreateSaved() {
    setShowCreate(false)
    retry()
  }

  async function handleConfirmDelete() {
    if (!deletingRole) return
    const justificationError = validateJustification(deleteJustification)
    if (justificationError !== null) {
      setDeleteJustificationError(justificationError)
      return
    }
    setDeleting(true)
    setDeleteError(null)
    const roleToDelete = deletingRole
    const justification = deleteJustification
    closeDeleteModal()
    try {
      await deleteRole(roleToDelete.id, justification)
      retry()
    } catch (cause: unknown) {
      setDeleteError(cause instanceof Error && cause.message ? cause.message : 'Delete failed')
    } finally {
      setDeleting(false)
    }
  }

  return (
    <>
      <section className="panel">
        <div className="ptool">
          <button
            type="button"
            className={showCreate ? 'wf-btn' : 'wf-btn-secondary'}
            onClick={() => setShowCreate((v) => !v)}
            data-testid="toggle-create-role-btn"
          >
            {showCreate ? 'Close' : '+ New role'}
          </button>
          {!loading && error === null && (
            <span className="cnt" data-testid="role-count">
              {roles.length} role{roles.length !== 1 ? 's' : ''}
            </span>
          )}
        </div>

        {showCreate && (
          <CreateRolePanel
            onSaved={handleCreateSaved}
            onClose={() => setShowCreate(false)}
          />
        )}

        {deleteError && (
          <div className="wf-form-error" style={{ padding: '8px 14px' }} data-testid="role-delete-error">
            {deleteError}
          </div>
        )}

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
                  editing={editingId === role.id}
                  onClick={() => handleRowClick(role.id)}
                  onEditStart={() => handleEditStart(role.id)}
                  onEditSaved={handleEditSaved}
                  onEditCancel={handleEditCancel}
                  onDeleteRequest={() => {
                    setDeleteError(null)
                    setDeleteJustification('')
                    setDeleteJustificationError(null)
                    setDeletingRole(role)
                  }}
                />
              ))}
            </tbody>
          </table>
        )}
      </section>

      {deletingRole !== null && (
        <div
          className="wf-overlay"
          role="dialog"
          aria-modal="true"
          aria-labelledby="delete-role-title"
        >
          <div className="wf-modal">
            <h3 id="delete-role-title">Delete role?</h3>
            <p>
              This will permanently delete the role <b>{deletingRole.name}</b>.
            </p>
            <p>This action cannot be undone.</p>
            <div className="wf-form">
              <div className="wf-form-row">
                <JustificationField
                  value={deleteJustification}
                  onChange={(next) => {
                    setDeleteJustification(next)
                    setDeleteJustificationError(null)
                  }}
                  testId="delete-role-justification-input"
                />
              </div>
              {deleteJustificationError && (
                <span
                  className="wf-form-error"
                  data-testid="delete-role-justification-error"
                >
                  {deleteJustificationError}
                </span>
              )}
            </div>
            <div className="wf-modal-actions">
              <button
                type="button"
                className="wf-btn-secondary"
                disabled={deleting}
                onClick={closeDeleteModal}
              >
                Cancel
              </button>
              <button
                type="button"
                className="wf-btn-danger"
                disabled={deleting}
                onClick={handleConfirmDelete}
                data-testid="delete-role-confirm-btn"
              >
                {deleting ? 'Deleting…' : 'Delete role'}
              </button>
            </div>
          </div>
        </div>
      )}
    </>
  )
}
