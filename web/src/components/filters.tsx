import { useState } from 'react'

// Shared dashboard/query filter UI: time ranges, the node-focus dropdown, and the
// node color palette — used by both the Dashboard and the Queries pages.

export const RANGES = [
  { label: '1h', hours: 1 },
  { label: '24h', hours: 24 },
  { label: '7d', hours: 24 * 7 },
  { label: '30d', hours: 24 * 30 },
  { label: '90d', hours: 24 * 90 },
]

export const NODE_PALETTE = ['#4ea1ff', '#3ecf8e', '#c48aff', '#ffb454', '#ff5d6c', '#56d4dd', '#e070c0']
// "overall" is not a node — it gets a reserved neutral color, never a palette slot.
export const OVERALL_COLOR = '#e6e9ee'
// colorAt maps any integer (including -1) to a stable palette color.
export const colorAt = (i: number) => NODE_PALETTE[((i % NODE_PALETTE.length) + NODE_PALETTE.length) % NODE_PALETTE.length]

// makeNodeColor returns a color function keyed by a node's position in one
// canonical, sorted name list, so a node keeps the same color everywhere.
export const makeNodeColor = (names: string[]) => {
  const sorted = [...new Set(names)].sort()
  return (name: string) => colorAt(sorted.indexOf(name))
}

// NodeFilter is a multi-select dropdown to focus on one or more nodes.
// Empty selection = all nodes.
export function NodeFilter({
  options,
  selected,
  onChange,
  color,
}: {
  options: string[]
  selected: string[]
  onChange: (s: string[]) => void
  color: (name: string) => string
}) {
  const [open, setOpen] = useState(false)
  const allActive = selected.length === 0
  const label = allActive ? 'All nodes' : selected.length === 1 ? selected[0] : `${selected.length} nodes`
  const toggle = (n: string) =>
    onChange(selected.includes(n) ? selected.filter((x) => x !== n) : [...selected, n])
  return (
    <div className="nodefilter">
      <button className={`nf-trigger ${open ? 'open' : ''} ${allActive ? '' : 'active'}`} onClick={() => setOpen((o) => !o)}>
        <span className="nf-label">{label}</span>
        <span className="nf-caret">▾</span>
      </button>
      {open && (
        <>
          <div className="nodefilter-backdrop" onClick={() => setOpen(false)} />
          <div className="nodefilter-menu">
            <div className="nf-head">Focus on nodes</div>
            <button type="button" className={`nf-opt ${allActive ? 'sel' : ''}`} onClick={() => onChange([])}>
              <span className="nf-check">{allActive ? '✓' : ''}</span>
              <span className="nf-name">All nodes</span>
            </button>
            <div className="nf-divider" />
            {options.map((o) => {
              const sel = selected.includes(o)
              return (
                <button key={o} type="button" className={`nf-opt ${sel ? 'sel' : ''}`} onClick={() => toggle(o)}>
                  <span className="nf-check">{sel ? '✓' : ''}</span>
                  <span className="nf-swatch" style={{ background: color(o) }} />
                  <span className="nf-name">{o}</span>
                </button>
              )
            })}
          </div>
        </>
      )}
    </div>
  )
}

// RangeNodeBar renders the shared "Window" range tabs plus the node-focus filter.
export function RangeNodeBar({
  hours,
  setHours,
  focus,
  setFocus,
  nodeNames,
  color,
}: {
  hours: number
  setHours: (h: number) => void
  focus: string[]
  setFocus: (f: string[]) => void
  nodeNames: string[]
  color: (name: string) => string
}) {
  return (
    <div className="range-tabs">
      <span className="muted">Window</span>
      {RANGES.map((r) => (
        <button key={r.hours} className={hours === r.hours ? 'active' : ''} onClick={() => setHours(r.hours)}>
          {r.label}
        </button>
      ))}
      {nodeNames.length > 0 && (
        <>
          <div className="spacer" />
          <span className="muted">Focus</span>
          <NodeFilter options={nodeNames} selected={focus} onChange={setFocus} color={color} />
        </>
      )}
    </div>
  )
}
