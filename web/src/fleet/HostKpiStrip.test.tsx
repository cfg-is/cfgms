// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz

import { afterEach, describe, expect, it } from 'vitest'
import { cleanup, render, screen } from '@testing-library/react'
import HostKpiStrip, { HOST_HISTORY_LIMIT, pushHostHistory, type HostTotals } from './HostKpiStrip.tsx'

afterEach(cleanup)

const host = (cpu: number): HostTotals => ({
  cpu_percent: cpu,
  memory_used_bytes: 2 * 1024 ** 3,
  memory_total_bytes: 8 * 1024 ** 3,
  disk_read_bytes_per_sec: 1024,
  disk_write_bytes_per_sec: 2048,
  disk_used_bytes: 50,
  disk_total_bytes: 100,
  net_rx_bytes_per_sec: 2048,
  net_tx_bytes_per_sec: 1024,
})

describe('HostKpiStrip', () => {
  it('renders four tiles from the latest totals', () => {
    render(<HostKpiStrip history={[host(10), host(42.5)]} />)
    expect(screen.getByTestId('kpi-cpu')).toHaveTextContent('42.5%')
    expect(screen.getByTestId('kpi-memory')).toHaveTextContent('25.0%')
    expect(screen.getByTestId('kpi-disk')).toHaveTextContent('50.0%')
    expect(screen.getByTestId('kpi-network')).toHaveTextContent('3.0 KB/s')
  })

  it('draws a sparkline once two snapshots exist', () => {
    const { container, rerender } = render(<HostKpiStrip history={[host(1)]} />)
    expect(container.querySelectorAll('svg')).toHaveLength(0)
    rerender(<HostKpiStrip history={[host(1), host(2)]} />)
    expect(container.querySelectorAll('svg')).toHaveLength(4)
  })

  it('renders the empty state, not NaN, when host totals are absent', () => {
    const { container } = render(<HostKpiStrip history={[]} />)
    expect(screen.getByTestId('kpi-empty')).toBeInTheDocument()
    expect(container.textContent).not.toContain('NaN')
  })

  it('keeps zero totals finite', () => {
    const zero = { ...host(0), memory_total_bytes: 0, disk_total_bytes: 0 }
    const { container } = render(<HostKpiStrip history={[zero]} />)
    expect(container.textContent).not.toContain('NaN')
  })
})

describe('pushHostHistory', () => {
  it('holds a bounded window, dropping the oldest', () => {
    let h: HostTotals[] = []
    for (let i = 0; i < HOST_HISTORY_LIMIT + 10; i++) h = pushHostHistory(h, host(i))
    expect(h).toHaveLength(HOST_HISTORY_LIMIT)
    expect(h[0]!.cpu_percent).toBe(10)
    expect(h.at(-1)!.cpu_percent).toBe(HOST_HISTORY_LIMIT + 9)
  })
})
