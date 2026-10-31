// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz

/* Users page (Issue #5565): directory users, read only. See DirectoryPage. */
import DirectoryPage from './DirectoryPage.tsx'

export default function UsersPage() {
  return <DirectoryPage kind="users" />
}
