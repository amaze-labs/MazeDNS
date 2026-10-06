import { useEffect, useState, type ReactNode } from 'react'
import { api } from '../api'

export interface Scope {
  scope_type: string
  scope_values: string[]
}

export const ALL_SCOPE: Scope = { scope_type: 'all', scope_values: [] }

// The signed-in user's role, fetched once and shared by every page that asks.
// Pages render inside App without a role prop, so they look it up themselves to
// hide controls a readonly user can't use (the API refuses them anyway).
let rolePromise: Promise<string> | null = null
const loadRole = () => {
  if (!rolePromise) {
    rolePromise = api
      .me()
      .then((u) => u?.role || '')
      .catch(() => {
        rolePromise = null // retry on the next mount
        return ''
      })
  }
  return rolePromise
}

// useIsAdmin is null until the role is known, then true for admins. Treat null
// as "not admin" so readonly users never see a flash of edit controls.
export function useIsAdmin(): boolean | null {
  const [admin, setAdmin] = useState<boolean | null>(null)
  useEffect(() => {
    let alive = true
    loadRole().then((r) => alive && setAdmin(r === 'admin'))
    return () => {
      alive = false
    }
  }, [])
  return admin
}

// Scope chips for a stored entry: "Everyone", "Site: home", or agent names.
// Values no longer in the cluster stay visible, flagged, because the entry then
// matches nothing for them.
export function scopeBadge(scopeType?: string, scopeValues?: string[], known?: string[]): ReactNode {
  const st = scopeType || 'all'
  if (st === 'all') return <span className="chip">Everyone</span>
  const vals = scopeValues || []
  const isSite = st === 'sites'
  const label = isSite ? 'site' : 'agent'
  return (
    <span className="scope-chips">
      {vals.map((v) => {
        const unknown = !!known && !known.includes(v)
        return (
          <span
            key={v}
            className={`chip${unknown ? ' unknown' : ''}`}
            title={unknown ? `Unknown ${label}: no longer in the cluster, so this entry matches nothing there` : undefined}
          >
            {isSite ? `Site: ${v}` : v}
            {unknown && <span className="warn-text">⚠</span>}
          </span>
        )
      })}
      {vals.length === 0 && <span className="chip unknown">No {label}s picked</span>}
    </span>
  )
}

// Scope selector: everyone, or a set of agents / sites picked as toggle chips.
// Options come from the cluster endpoints; when the cluster is empty the picker
// collapses to "Everyone" only. Pass null for a list that hasn't loaded (or
// failed to load): values already in the scope are still shown, just not
// flagged as unknown. Selected values missing from a loaded list (a renamed or
// removed agent, say) stay visible, marked with ⚠, so an edit can drop them
// instead of silently keeping them.
export default function ScopePicker({
  value,
  onChange,
  nodes,
  sites,
  id,
}: {
  value: Scope
  onChange: (s: Scope) => void
  nodes: string[] | null
  sites: string[] | null
  id?: string
}) {
  const known = value.scope_type === 'nodes' ? nodes : value.scope_type === 'sites' ? sites : []
  const options = [...(known ?? []), ...value.scope_values.filter((v) => !(known ?? []).includes(v))]
  const label = value.scope_type === 'nodes' ? 'agent' : 'site'
  const toggle = (name: string) => {
    const has = value.scope_values.includes(name)
    onChange({
      ...value,
      scope_values: has ? value.scope_values.filter((v) => v !== name) : [...value.scope_values, name],
    })
  }
  return (
    <div className="scope-picker">
      <select id={id} value={value.scope_type} onChange={(e) => onChange({ scope_type: e.target.value, scope_values: [] })}>
        <option value="all">Everyone</option>
        {((nodes?.length ?? 0) > 0 || value.scope_type === 'nodes') && <option value="nodes">Specific agents</option>}
        {((sites?.length ?? 0) > 0 || value.scope_type === 'sites') && <option value="sites">Sites</option>}
      </select>
      {value.scope_type !== 'all' && (
        <div className="scope-options" role="group" aria-label={`Pick ${label}s`}>
          {options.map((name) => {
            const unknown = known !== null && !known.includes(name)
            const on = value.scope_values.includes(name)
            return (
              <button
                type="button"
                key={name}
                className={`chip${on ? ' on' : ''}`}
                aria-pressed={on}
                onClick={() => toggle(name)}
                title={unknown ? `Unknown ${label}: no longer in the cluster, so it matches nothing` : undefined}
              >
                {name}
                {unknown && <span className="warn-text">⚠</span>}
              </button>
            )
          })}
          {options.length === 0 && <span className="faint small">No {label}s yet</span>}
        </div>
      )}
    </div>
  )
}
