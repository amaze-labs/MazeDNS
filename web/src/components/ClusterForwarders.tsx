import { useCallback, useEffect, useState, type FormEvent } from 'react'
import { api, type Forwarder } from '../api'
import EditScopedModal from './EditScopedModal'
import ScopePicker, { ALL_SCOPE, scopeBadge, useIsAdmin, type Scope } from './ScopePicker'
import { useTable, Th, Pager, TableStatusRow, type SortAccessors } from './tableKit'
import '../styles/local-dns.css'

// Upstreams are edited as one comma-separated field in both the add form and
// the edit dialog.
const splitUpstreams = (raw: string) =>
  raw
    .split(',')
    .map((u) => u.trim())
    .filter(Boolean)

const FWD_COLS: SortAccessors<Forwarder> = {
  suffix: (f) => f.suffix,
  upstreams: (f) => f.upstreams.join(','),
  scope: (f) => `${f.scope_type || 'all'} ${(f.scope_values ?? []).join(',')}`,
}

const errMsg = (e: unknown) => (e instanceof Error ? e.message : String(e)) || 'Request failed'

// ClusterForwarders manages the conditional forwarders pushed to the agents:
// each sends a domain to specific resolvers, scoped to everyone, a site or an
// agent. Every change is saved at once, not with the page's Save button.
// `reload` is bumped by the parent after it adds entries itself.
export default function ClusterForwarders({ reload = 0 }: { reload?: number }) {
  const admin = useIsAdmin() === true
  const [fwds, setFwds] = useState<Forwarder[]>([])
  const [loaded, setLoaded] = useState(false)
  const [suffix, setSuffix] = useState('')
  const [upstreams, setUpstreams] = useState('')
  const [scope, setScope] = useState<Scope>(ALL_SCOPE)
  const [adding, setAdding] = useState(false)
  const [err, setErr] = useState('')
  const [editing, setEditing] = useState<Forwarder | null>(null)
  const closeEdit = useCallback(() => setEditing(null), [])

  const [nodes, setNodes] = useState<string[] | null>(null)
  const [sites, setSites] = useState<string[] | null>(null)

  const load = () => {
    api
      .forwarders()
      .then((f) => {
        setFwds(f)
        setLoaded(true)
      })
      .catch((e) => setErr(errMsg(e)))
  }
  useEffect(load, [reload])
  useEffect(() => {
    // Cluster lists feed the scope pickers; on a standalone control plane the
    // calls fail and scoping simply collapses to "Everyone".
    api.clusterNodes().then((ns) => setNodes(ns.map((n) => n.name))).catch(() => {})
    api.clusterSites().then((ss) => setSites(ss.map((s) => s.name))).catch(() => {})
  }, [])

  const add = async (e: FormEvent) => {
    e.preventDefault()
    const ups = splitUpstreams(upstreams)
    if (!suffix.trim() || ups.length === 0 || adding) return
    setAdding(true)
    try {
      await api.addForwarder(suffix.trim(), ups, scope.scope_type, scope.scope_values)
      setSuffix('')
      setUpstreams('')
      setScope(ALL_SCOPE)
      setErr('')
      load()
    } catch (e) {
      setErr(errMsg(e))
    } finally {
      setAdding(false)
    }
  }

  const toggle = async (f: Forwarder) => {
    try {
      await api.updateForwarder(f.id, f.upstreams, !f.enabled, f.scope_type, f.scope_values)
      setErr('')
      load()
    } catch (e) {
      setErr(errMsg(e))
    }
  }

  const saveEdit = async (f: Forwarder, raw: string, s: Scope) => {
    const ups = splitUpstreams(raw)
    if (ups.length === 0) throw new Error('Enter at least one resolver')
    await api.updateForwarder(f.id, ups, f.enabled, s.scope_type, s.scope_values)
    setEditing(null)
    load()
  }

  const del = async (f: Forwarder) => {
    if (!window.confirm(`Stop forwarding ${f.suffix} to ${f.upstreams.join(', ')}?`)) return
    try {
      await api.deleteForwarder(f.id)
      setErr('')
      load()
    } catch (e) {
      setErr(errMsg(e))
    }
  }

  const table = useTable(fwds, FWD_COLS, 'suffix')
  const known = (t?: string) => (t === 'nodes' ? nodes ?? undefined : t === 'sites' ? sites ?? undefined : undefined)

  return (
    <div className="scoped-ui card flush">
      {admin && (
        <form className="rw-addrow fw" onSubmit={add}>
          <label className="field">
            <span>Domain</span>
            <input className="mono" placeholder="corp.internal" value={suffix} onChange={(e) => setSuffix(e.target.value)} />
          </label>
          <label className="field">
            <span>Resolvers</span>
            <input
              className="mono"
              placeholder="10.0.0.2:53, 10.0.0.3:53"
              value={upstreams}
              onChange={(e) => setUpstreams(e.target.value)}
            />
          </label>
          <div className="field">
            <label htmlFor="fw-scope">Scope</label>
            <ScopePicker id="fw-scope" value={scope} onChange={setScope} nodes={nodes} sites={sites} />
          </div>
          <button type="submit" className="btn primary" disabled={adding || !suffix.trim() || !upstreams.trim()}>
            {adding ? 'Adding…' : 'Add'}
          </button>
        </form>
      )}
      {err && (
        <div className="error rw-err" role="alert">
          {err}
        </div>
      )}
      <div className="table-scroll">
        <table className="stackable rw-table">
          <thead>
            <tr>
              <Th table={table} col="suffix">Domain</Th>
              <Th table={table} col="upstreams">Resolvers</Th>
              <Th table={table} col="scope">Scope</Th>
              <th>{admin ? <span className="sr-only">Enabled</span> : 'Status'}</th>
              {admin && <th></th>}
            </tr>
          </thead>
          <tbody>
            {table.rows.map((f) => (
              <tr key={f.id} className={f.enabled ? '' : 'off'}>
                <td className="lead">
                  <span className="domain">{f.suffix}</span>
                </td>
                <td>
                  <span className="domain">{f.upstreams.join(', ')}</span>
                </td>
                <td>{scopeBadge(f.scope_type, f.scope_values, known(f.scope_type))}</td>
                <td className="lead-r rw-switch">
                  {admin ? (
                    <button
                      type="button"
                      role="switch"
                      aria-checked={f.enabled}
                      aria-label={`${f.enabled ? 'Disable' : 'Enable'} forwarding for ${f.suffix}`}
                      className="switch-btn"
                      onClick={() => toggle(f)}
                      title={f.enabled ? 'On — click to turn off' : 'Off — click to turn on'}
                    >
                      <span className={`switch${f.enabled ? ' on' : ''}`} />
                    </button>
                  ) : f.enabled ? (
                    <span className="tag ok">On</span>
                  ) : (
                    <span className="tag">Off</span>
                  )}
                </td>
                {admin && (
                  <td className="actions">
                    <button className="btn sm quiet" onClick={() => setEditing(f)}>
                      Edit
                    </button>
                    <button className="btn sm quiet rw-del" onClick={() => del(f)}>
                      Delete
                    </button>
                  </td>
                )}
              </tr>
            ))}
            <TableStatusRow loading={!loaded} error={err} empty={fwds.length === 0} colSpan={admin ? 5 : 4}>
              No forwarding rules. Every name goes to the normal upstream resolvers.
            </TableStatusRow>
          </tbody>
        </table>
      </div>
      <Pager table={table} unit="rules" />

      {editing && (
        <EditScopedModal
          title={`Edit forwarding for ${editing.suffix}`}
          intro={
            <>
              The domain <code>{editing.suffix}</code> identifies the rule and can't be changed. To change it, delete the
              rule and add a new one.
            </>
          }
          fieldLabel="Resolvers (comma-separated)"
          fieldPlaceholder="10.0.0.2:53, 10.0.0.3:53"
          initialText={editing.upstreams.join(', ')}
          initialScope={{ scope_type: editing.scope_type || 'all', scope_values: editing.scope_values ?? [] }}
          nodes={nodes}
          sites={sites}
          onClose={closeEdit}
          onSave={(text, s) => saveEdit(editing, text, s)}
        />
      )}
    </div>
  )
}
