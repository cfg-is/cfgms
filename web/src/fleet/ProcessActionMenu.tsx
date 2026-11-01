// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz

/*
 * Process row action menu (Story #4629): Copy PID, End task, Suspend or Resume,
 * Open in DNA. End/Suspend/Resume are operator-signed (signAction.ts). The
 * "End task (blocked)" state comes only from the server's self_protect job
 * result, never from a client-side guess about which process is the steward's.
 */
import { useState } from 'react'
import ActionMenuBase, { type ActionItem } from './ActionMenuBase.tsx'
import type { StewardControl } from './useStewardControl.ts'

interface ProcessActionMenuProps {
  stewardId: string
  pid: number
  name: string
  /** Process run status from the telemetry stream: "running" or "suspended". */
  status?: string
  control: StewardControl
  onViewDna?: () => void
}

export default function ProcessActionMenu({
  stewardId,
  pid,
  name,
  status,
  control,
  onViewDna,
}: ProcessActionMenuProps) {
  const [endBlocked, setEndBlocked] = useState(false)
  const target = String(pid)
  const suspended = status === 'suspended'

  const items: ActionItem[] = [
    {
      id: 'copy-pid',
      label: 'Copy PID',
      onSelect: () => {
        void navigator.clipboard?.writeText(target)
      },
    },
    {
      id: 'end',
      label: endBlocked ? 'End task (blocked)' : 'End task',
      title: 'End task',
      disabled: endBlocked,
      spec: { targetKind: 'process', targetName: target, action: 'end', image: name },
    },
    suspended
      ? {
          id: 'resume',
          label: 'Resume',
          title: 'Resume',
          spec: { targetKind: 'process', targetName: target, action: 'resume', image: name },
        }
      : {
          id: 'suspend',
          label: 'Suspend',
          title: 'Suspend',
          spec: { targetKind: 'process', targetName: target, action: 'suspend', image: name },
        },
  ]
  if (onViewDna) items.push({ id: 'dna', label: 'Open in DNA', onSelect: onViewDna })

  return (
    <ActionMenuBase
      stewardId={stewardId}
      rowLabel={`PID ${pid}`}
      targetText={`Process ${name} (PID ${pid})`}
      items={items}
      control={control}
      onOutcome={(item, o) => {
        if (item.id === 'end' && o.kind === 'result' && o.code === 'self_protect') setEndBlocked(true)
      }}
    />
  )
}
