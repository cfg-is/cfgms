// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz

/*
 * Blast-radius evidence card (Story #3610, Epic #2854).
 *
 * Renders a depth-2 dependency neighborhood (depends-on/serves/runs-on) for a
 * pinned entity as an SVG node-and-edge graph. Fetches from:
 *   GET /api/v1/entities/{eid}/neighborhood?depth=2&edge_type=depends-on&edge_type=serves&edge_type=runs-on
 *
 * Edge types confirmed against egtypes.DefaultTaxonomy() in
 * pkg/entitygraph/types/taxonomy.go (lines 171–174).
 *
 * The component looks for an eid-bearing pin: kind='eid' first, then
 * kind='subject-time-range' with a subject field. Auto-discovered by
 * EvidenceCanvas.tsx's glob; no edit to that file is needed.
 *
 * Nodes render in neutral (non-health-colored) state only. Health coloring is
 * deferred to DEX epics.
 *
 * Visual design: docs/design/mockups/troubleshooting-cockpit.html §.card.graph
 *   and the SVG dependency-graph illustration earlier in that file.
 * Colour tokens: docs/design/web-ui-design-tokens.css.
 */
import { useEffect, useState } from 'react'
import type { EvidenceCardProps, Pin } from '../evidenceTypes.ts'
import { apiFetch } from '../../api/client.ts'
import './BlastRadiusCard.css'

// ── API response shapes ───────────────────────────────────────────────────────
// Mirrors the Go Neighborhood struct (pkg/entitygraph/types/edge.go) serialised
// by writeEntityJSON. EID fields are the canonical string form (EID.MarshalJSON).

interface NeighborNode {
  EID: string
  Kind: string
}

interface NeighborEdge {
  Type: string
  From: string
  To: string
}

interface NeighborhoodResponse {
  Root: string
  Nodes: NeighborNode[]
  Edges: NeighborEdge[]
}

// ── Internal state machine ────────────────────────────────────────────────────

type CardPhase =
  | { kind: 'loading' }
  | { kind: 'error'; message: string }
  | { kind: 'ready'; neighborhood: NeighborhoodResponse }

// ── Helpers ───────────────────────────────────────────────────────────────────

function extractEID(pins: Pin[]): string | null {
  const eidPin = pins.find((p) => p.ref.kind === 'eid')
  if (eidPin?.ref.eid) return eidPin.ref.eid
  const subjectPin = pins.find((p) => p.ref.kind === 'subject-time-range')
  if (subjectPin?.ref.subject) return subjectPin.ref.subject
  return null
}

// Last path segment of the EID string (the entity's local name).
function entityLabel(eid: string): string {
  const slash = eid.lastIndexOf('/')
  return slash >= 0 ? eid.slice(slash + 1) : eid
}

function truncateLabel(s: string, max = 11): string {
  return s.length > max ? s.slice(0, max - 1) + '…' : s
}

/*
 * Normalise the /neighborhood response at the boundary.
 * Go nil slices serialise as JSON null; Array.isArray(null) is false so
 * we default to []. Coercion keeps the render path safe against wire variance.
 */
function normalizeNeighborhood(raw: unknown): NeighborhoodResponse {
  const n = (typeof raw === 'object' && raw !== null ? raw : {}) as Partial<NeighborhoodResponse>
  return {
    Root: typeof n.Root === 'string' ? n.Root : '',
    Nodes: Array.isArray(n.Nodes)
      ? n.Nodes.filter(
          (x): x is NeighborNode =>
            typeof x === 'object' && x !== null && typeof (x as NeighborNode).EID === 'string',
        )
      : [],
    Edges: Array.isArray(n.Edges)
      ? n.Edges.filter(
          (x): x is NeighborEdge =>
            typeof x === 'object' &&
            x !== null &&
            typeof (x as NeighborEdge).From === 'string' &&
            typeof (x as NeighborEdge).To === 'string',
        )
      : [],
  }
}

// ── SVG graph layout ──────────────────────────────────────────────────────────

const SVG_W = 320
const SVG_H = 190

interface LayoutNode {
  eid: string
  label: string
  x: number
  y: number
  isRoot: boolean
}

/*
 * Radial layout: root at centre, neighbours distributed evenly on a circle.
 * The 65px radius fits within the 320×190 viewBox at all neighbour counts
 * while keeping nodes clear of the edges.
 */
function buildLayout(neighborhood: NeighborhoodResponse): LayoutNode[] {
  const cx = SVG_W / 2
  const cy = SVG_H / 2
  const rootEID = neighborhood.Root

  const neighbors = neighborhood.Nodes.filter((n) => n.EID !== rootEID)
  const radius = 65

  const nodes: LayoutNode[] = []

  nodes.push({
    eid: rootEID,
    label: truncateLabel(entityLabel(rootEID)),
    x: cx,
    y: cy,
    isRoot: true,
  })

  const count = neighbors.length
  neighbors.forEach((node, i) => {
    const angle = count === 1 ? -Math.PI / 2 : (2 * Math.PI * i) / count - Math.PI / 2
    nodes.push({
      eid: node.EID,
      label: truncateLabel(entityLabel(node.EID)),
      x: cx + radius * Math.cos(angle),
      y: cy + radius * Math.sin(angle),
      isRoot: false,
    })
  })

  return nodes
}

// ── SVG graph sub-component ───────────────────────────────────────────────────

function NeighborhoodGraph({ neighborhood }: { neighborhood: NeighborhoodResponse }) {
  const layoutNodes = buildLayout(neighborhood)
  const posMap = new Map(layoutNodes.map((n) => [n.eid, n]))

  const noEdges = neighborhood.Edges.length === 0

  return (
    <div className="blast-radius-card__gwrap">
      <svg
        viewBox={`0 0 ${SVG_W} ${SVG_H}`}
        role="img"
        aria-label="Dependency graph"
        className="blast-radius-card__svg"
      >
        {neighborhood.Edges.map((edge, i) => {
          const from = posMap.get(edge.From)
          const to = posMap.get(edge.To)
          if (!from || !to) return null
          return (
            <line
              key={`${edge.From}-${edge.To}-${i}`}
              x1={from.x}
              y1={from.y}
              x2={to.x}
              y2={to.y}
              className="blast-radius-card__edge"
            />
          )
        })}

        <g fontFamily="var(--font-mono)" fontSize="9">
          {layoutNodes.map((node) => (
            <g key={node.eid}>
              <circle
                cx={node.x}
                cy={node.y}
                r={node.isRoot ? 26 : 20}
                className={
                  node.isRoot ? 'blast-radius-card__node-root' : 'blast-radius-card__node'
                }
              />
              <text
                x={node.x}
                y={node.y + 3}
                textAnchor="middle"
                className={
                  node.isRoot ? 'blast-radius-card__label-root' : 'blast-radius-card__label'
                }
                fontWeight={node.isRoot ? '700' : '400'}
              >
                {node.label}
              </text>
            </g>
          ))}
        </g>
      </svg>

      {noEdges && <p className="blast-radius-card__no-deps">No dependents found</p>}
    </div>
  )
}

// ── Component ─────────────────────────────────────────────────────────────────

export default function BlastRadiusCard({ pins }: EvidenceCardProps) {
  const eid = extractEID(pins)
  const [phase, setPhase] = useState<CardPhase>({ kind: 'loading' })

  useEffect(() => {
    if (!eid) return

    let cancelled = false

    /*
     * Percent-encode the EID before interpolating it into the request path.
     * Entity local IDs are steward-supplied and may contain '/', '..', '?' or
     * '#'. Unencoded, such a value would redirect this credentialed same-origin
     * GET to an attacker-chosen controller API path. gorilla/mux URL-decodes
     * the {eid:.+} path variable before matching, so encoding embedded slashes
     * is transparent to routing.
     */
    const encodedEID = encodeURIComponent(eid)
    const neighborhoodPath =
      `/api/v1/entities/${encodedEID}/neighborhood` +
      '?depth=2&edge_type=depends-on&edge_type=serves&edge_type=runs-on'

    async function fetchData(): Promise<void> {
      try {
        const res = await apiFetch(neighborhoodPath)

        if (cancelled) return

        if (!res.ok) {
          throw new Error(`GET ${neighborhoodPath} — ${res.status}`)
        }

        const neighborhood = normalizeNeighborhood(await res.json())

        if (!cancelled) {
          setPhase({ kind: 'ready', neighborhood })
        }
      } catch (err) {
        if (!cancelled) {
          setPhase({
            kind: 'error',
            message: err instanceof Error ? err.message : 'Failed to load neighborhood',
          })
        }
      }
    }

    void fetchData()

    return () => {
      cancelled = true
    }
  }, [eid])

  if (!eid) return null

  if (phase.kind === 'error') {
    return (
      <section className="blast-radius-card blast-radius-card--error" aria-label="Blast radius">
        <h3 className="blast-radius-card__header">
          <span>Blast radius</span>
        </h3>
        <p className="blast-radius-card__error">{phase.message}</p>
      </section>
    )
  }

  if (phase.kind === 'loading') {
    return (
      <section className="blast-radius-card" aria-label="Blast radius">
        <h3 className="blast-radius-card__header">
          <span>Blast radius</span>
        </h3>
        <p className="blast-radius-card__loading" aria-label="Loading neighborhood">
          Loading…
        </p>
      </section>
    )
  }

  const { neighborhood } = phase
  const dependentCount = neighborhood.Nodes.length - 1
  const hasDependents = dependentCount > 0

  return (
    <section className="blast-radius-card" aria-label="Blast radius">
      <h3 className="blast-radius-card__header">
        <span>Blast radius</span>
        {hasDependents && (
          <span className="blast-radius-card__sub">
            {dependentCount} {dependentCount === 1 ? 'dependent' : 'dependents'}
          </span>
        )}
      </h3>
      <NeighborhoodGraph neighborhood={neighborhood} />
    </section>
  )
}
