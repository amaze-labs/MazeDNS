import { type ReactNode } from 'react'

export interface Scope {
  scope_type: string
  scope_values: string[]
}

export const ALL_SCOPE: Scope = { scope_type: 'all', scope_values: [] }

// Human-readable badge for a stored scope ("all nodes", "2 nodes: a, b", …).
export function scopeBadge(scopeType?: string, scopeValues?: string[], known?: string[]): ReactNode {
  const st = scopeType || 'all'
  if (st === 'all') return <span className="muted">all nodes</span>
  const vals = scopeValues || []
  const label = st === 'nodes' ? 'node' : 'site'
  const missing = known ? vals.filter((v) => !known.includes(v)) : []
  return (
    <span title={vals.join(', ')}>
      {vals.length === 1 ? `${label}: ${vals[0]}` : `${vals.length} ${label}s: ${vals.join(', ')}`}
      {missing.length > 0 && (
        <span className="muted" title={`unknown ${label}(s): ${missing.join(', ')} — this entry currently matches nothing`}>
          {' '}
          ⚠
        </span>
      )}
    </span>
  )
}

// Scope selector: "all nodes" or a checkbox list of nodes / sites. Options come
// from the cluster endpoints; when the cluster is empty the picker collapses to
// "all nodes" only. Pass null for a list that hasn't loaded (or failed to load):
// values already in the scope are still shown, just not flagged as unknown.
// Selected values missing from a loaded list (a renamed or removed node, say)
// stay visible, marked with ⚠, so an edit can drop them instead of silently
// keeping them.
export default function ScopePicker({
  value,
  onChange,
  nodes,
  sites,
}: {
  value: Scope
  onChange: (s: Scope) => void
  nodes: string[] | null
  sites: string[] | null
}) {
  const known = value.scope_type === 'nodes' ? nodes : value.scope_type === 'sites' ? sites : []
  const options = [...(known ?? []), ...value.scope_values.filter((v) => !(known ?? []).includes(v))]
  const label = value.scope_type === 'nodes' ? 'node' : 'site'
  const toggle = (name: string) => {
    const has = value.scope_values.includes(name)
    onChange({
      ...value,
      scope_values: has ? value.scope_values.filter((v) => v !== name) : [...value.scope_values, name],
    })
  }
  return (
    <span className="scope-picker">
      <select
        value={value.scope_type}
        onChange={(e) => onChange({ scope_type: e.target.value, scope_values: [] })}
      >
        <option value="all">All nodes</option>
        {((nodes?.length ?? 0) > 0 || value.scope_type === 'nodes') && <option value="nodes">Specific nodes</option>}
        {((sites?.length ?? 0) > 0 || value.scope_type === 'sites') && <option value="sites">Sites</option>}
      </select>
      {value.scope_type !== 'all' &&
        options.map((name) => {
          const unknown = known !== null && !known.includes(name)
          return (
            <label
              key={name}
              className="scope-chip"
              title={unknown ? `unknown ${label}: no longer in the cluster, so it matches nothing` : undefined}
            >
              <input type="checkbox" checked={value.scope_values.includes(name)} onChange={() => toggle(name)} />
              {name}
              {unknown && <span className="muted">⚠</span>}
            </label>
          )
        })}
    </span>
  )
}
