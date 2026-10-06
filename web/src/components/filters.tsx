import { useState } from 'react'
import '../styles/overview.css'

// Shared dashboard/query filter UI: time ranges, the agent-focus dropdown, and the
// node color palette — used by the Overview, Queries and Clients pages. Its CSS
// lives in styles/overview.css (imported here so it loads wherever these render).

export const RANGES = [
  { label: '30m', hours: 0.5 },
  { label: '1h', hours: 1 },
  { label: '2h', hours: 2 },
  { label: '4h', hours: 4 },
  { label: '8h', hours: 8 },
  { label: '24h', hours: 24 },
  { label: '2d', hours: 48 },
  { label: '15d', hours: 360 },
]
// VALID_HOURS is the set of allowed window values, for persisting a saved range.
export const VALID_HOURS = RANGES.map((r) => r.hours)

// Node (agent) identity colours. They deliberately avoid the four semantic hues
// (teal = cache, blue = forwarded, coral = blocked, amber = rewritten) so an
// agent's line is never read as an answer type, and are mid-tones that stay
// legible on both the dark and the light theme (checked for lightness, chroma,
// colour-blind separation and 3:1 contrast against both panel colours). With
// more agents than slots the colours repeat; the name is always shown with them.
export const NODE_PALETTE = ['#8b6fe8', '#b0703f', '#c053b5', '#6f9a2a', '#3a95c0']
// "overall" is not a node — it gets a reserved neutral color, never a palette
// slot. It follows the theme's text colour so it reads on light and dark.
export const OVERALL_COLOR = 'var(--text)'
// colorAt maps any integer (including -1) to a stable palette color.
export const colorAt = (i: number) => NODE_PALETTE[((i % NODE_PALETTE.length) + NODE_PALETTE.length) % NODE_PALETTE.length]

// hashColor gives a name that isn't in the canonical list a colour derived from
// the name itself, so it is still the same on every page.
const hashColor = (name: string) => {
  let h = 0
  for (let i = 0; i < name.length; i++) h = (h * 31 + name.charCodeAt(i)) | 0
  return colorAt(Math.abs(h))
}

// makeNodeColor returns a color function keyed by a node's position in one
// canonical, sorted name list, so a node keeps the same color everywhere. Pass
// the cluster's agent names (api.clusterNodes) — every page does, so the same
// agent gets the same colour on Overview, Queries and Clients. Names outside
// that list (e.g. "master" rows from before the control plane stopped serving
// DNS) get a colour from their own name instead of shifting everyone else's.
export const makeNodeColor = (names: string[]) => {
  const sorted = [...new Set(names)].sort()
  return (name: string) => {
    const i = sorted.indexOf(name)
    return i >= 0 ? colorAt(i) : hashColor(name)
  }
}

// SiteGroup is a site and the node names it contains, for the site-focus filter.
export type SiteGroup = { name: string; members: string[] }

// siteGroups builds the site -> member-node-names list from the cluster nodes
// (each node now carries its site), so a "focus on this site" = focus on its nodes.
export const siteGroups = (nodes: { name: string; site: string }[]): SiteGroup[] => {
  const m = new Map<string, string[]>()
  for (const n of nodes) if (n.site) m.set(n.site, [...(m.get(n.site) || []), n.name])
  return [...m.entries()].map(([name, members]) => ({ name, members })).sort((a, b) => a.name.localeCompare(b.name))
}

// sameSet reports whether two name lists contain exactly the same members.
const sameSet = (a: string[], b: string[]) => a.length === b.length && a.every((x) => b.includes(x))

// NodeFilter is a multi-select dropdown to focus on one or more nodes.
// Empty selection = all nodes.
export function NodeFilter({
  options,
  selected,
  onChange,
  color,
  sites,
}: {
  options: string[]
  selected: string[]
  onChange: (s: string[]) => void
  color: (name: string) => string
  sites?: SiteGroup[]
}) {
  const [open, setOpen] = useState(false)
  const allActive = selected.length === 0
  // When the focus set exactly matches a site's members, label it as that site.
  const activeSite = sites?.find((s) => s.members.length > 0 && sameSet(selected, s.members))?.name
  const label = allActive
    ? 'All agents'
    : activeSite
    ? `Site: ${activeSite}`
    : selected.length === 1
    ? selected[0]
    : `${selected.length} agents`
  const toggle = (n: string) =>
    onChange(selected.includes(n) ? selected.filter((x) => x !== n) : [...selected, n])
  return (
    <div className="nodefilter">
      <button
        type="button"
        className={`btn nf-trigger ${open ? 'open' : ''} ${allActive ? '' : 'active'}`}
        aria-haspopup="true"
        aria-expanded={open}
        onClick={() => setOpen((o) => !o)}
      >
        <span className="nf-label">{label}</span>
        <span className="nf-caret">▾</span>
      </button>
      {open && (
        <>
          <div className="nodefilter-backdrop" onClick={() => setOpen(false)} />
          <div className="nodefilter-menu">
            <button type="button" className={`nf-opt ${allActive ? 'sel' : ''}`} onClick={() => onChange([])}>
              <span className="nf-check">{allActive ? '✓' : ''}</span>
              <span className="nf-name">All agents</span>
            </button>
            {sites && sites.length > 0 && (
              <>
                <div className="nf-divider" />
                <div className="nf-head">Sites</div>
                {sites.map((s) => {
                  const sel = activeSite === s.name
                  return (
                    <button key={s.name} type="button" className={`nf-opt ${sel ? 'sel' : ''}`} onClick={() => onChange(s.members)}>
                      <span className="nf-check">{sel ? '✓' : ''}</span>
                      <span className="nf-name">
                        {s.name} <span className="muted">({s.members.length})</span>
                      </span>
                    </button>
                  )
                })}
              </>
            )}
            <div className="nf-divider" />
            <div className="nf-head">Focus on agents</div>
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

// RangeNodeBar renders the shared time-window segmented control plus the
// agent-focus filter. It has no outer margins so a page can put it in its
// .page-head (right side) or in a toolbar.
export function RangeNodeBar({
  hours,
  setHours,
  focus,
  setFocus,
  nodeNames,
  color,
  sites,
}: {
  hours: number
  setHours: (h: number) => void
  focus: string[]
  setFocus: (f: string[]) => void
  nodeNames: string[]
  color: (name: string) => string
  sites?: SiteGroup[]
}) {
  return (
    <div className="range-bar">
      <div className="seg" role="group" aria-label="Time window">
        {RANGES.map((r) => (
          <button
            key={r.hours}
            type="button"
            className={hours === r.hours ? 'on' : ''}
            aria-pressed={hours === r.hours}
            onClick={() => setHours(r.hours)}
          >
            {r.label}
          </button>
        ))}
      </div>
      {nodeNames.length > 0 && (
        <NodeFilter options={nodeNames} selected={focus} onChange={setFocus} color={color} sites={sites} />
      )}
    </div>
  )
}
