import { useCallback, useEffect, useRef, useState, type FormEvent, type ReactNode } from 'react'
import { api, type Forwarder, type Rewrite } from '../api'
import Modal from './Modal'
import ScopePicker, { ALL_SCOPE, scopeBadge, useIsAdmin, type Scope } from './ScopePicker'
import { useTable, Th, Pager, TableStatusRow, type SortAccessors } from './tableKit'
import { invalidateAllClientNames } from '../useClientNames'
import '../styles/rewrites.css'

// Upstreams are edited as one comma-separated field in both the add form and
// the edit dialog.
const splitUpstreams = (raw: string) =>
  raw
    .split(',')
    .map((u) => u.trim())
    .filter(Boolean)

const COLS: SortAccessors<Rewrite> = {
  domain: (r) => r.domain,
  value: (r) => `${r.rrtype} ${r.value}`,
  scope: (r) => `${r.scope_type || 'all'} ${(r.scope_values ?? []).join(',')}`,
}

const FWD_COLS: SortAccessors<Forwarder> = {
  suffix: (f) => f.suffix,
  upstreams: (f) => f.upstreams.join(','),
  scope: (f) => `${f.scope_type || 'all'} ${(f.scope_values ?? []).join(',')}`,
}

const errMsg = (e: unknown) => (e instanceof Error ? e.message : String(e)) || 'Request failed'

export default function Rewrites() {
  const admin = useIsAdmin() === true
  const [rows, setRows] = useState<Rewrite[]>([])
  const [loaded, setLoaded] = useState(false)
  const [domain, setDomain] = useState('')
  const [rrtype, setRrtype] = useState('A')
  const [value, setValue] = useState('')
  const [scope, setScope] = useState<Scope>(ALL_SCOPE)
  const [adding, setAdding] = useState(false)
  const [err, setErr] = useState('')

  const [fwds, setFwds] = useState<Forwarder[]>([])
  const [fwdsLoaded, setFwdsLoaded] = useState(false)
  const [suffix, setSuffix] = useState('')
  const [upstreams, setUpstreams] = useState('')
  const [fwdScope, setFwdScope] = useState<Scope>(ALL_SCOPE)
  const [addingFwd, setAddingFwd] = useState(false)
  const [fwdErr, setFwdErr] = useState('')

  const [nodes, setNodes] = useState<string[] | null>(null)
  const [sites, setSites] = useState<string[] | null>(null)

  const [editing, setEditing] = useState<Rewrite | null>(null)
  const [editingFwd, setEditingFwd] = useState<Forwarder | null>(null)
  const closeEdit = useCallback(() => setEditing(null), [])
  const closeEditFwd = useCallback(() => setEditingFwd(null), [])

  const load = () => {
    api
      .rewrites()
      .then((rs) => {
        setRows(rs)
        setLoaded(true)
      })
      .catch((e) => setErr(errMsg(e)))
    api
      .forwarders()
      .then((f) => {
        setFwds(f)
        setFwdsLoaded(true)
      })
      .catch((e) => setFwdErr(errMsg(e)))
  }
  useEffect(() => {
    load()
    // Cluster lists feed the scope pickers; on a standalone control plane the
    // calls fail and scoping simply collapses to "Everyone".
    api.clusterNodes().then((ns) => setNodes(ns.map((n) => n.name))).catch(() => {})
    api.clusterSites().then((ss) => setSites(ss.map((s) => s.name))).catch(() => {})
  }, [])

  const add = async (e: FormEvent) => {
    e.preventDefault()
    if (!domain.trim() || !value.trim() || adding) return
    setAdding(true)
    try {
      await api.addRewrite(domain.trim(), rrtype, value.trim(), scope.scope_type, scope.scope_values)
      setDomain('')
      setValue('')
      setScope(ALL_SCOPE)
      setErr('')
      invalidateAllClientNames()
      load()
    } catch (e) {
      setErr(errMsg(e))
    } finally {
      setAdding(false)
    }
  }

  const del = async (r: Rewrite) => {
    if (!window.confirm(`Delete the ${r.rrtype} record for ${r.domain}?`)) return
    try {
      await api.deleteRewrite(r.id)
      setErr('')
      invalidateAllClientNames()
      load()
    } catch (e) {
      setErr(errMsg(e))
    }
  }

  const toggle = async (r: Rewrite) => {
    try {
      await api.updateRewrite(r.id, r.value, !r.enabled, r.scope_type || 'all', r.scope_values ?? [])
      setErr('')
      // A disabled A/AAAA record no longer names its client.
      invalidateAllClientNames()
      load()
    } catch (e) {
      setErr(errMsg(e))
    }
  }

  const saveEdit = async (r: Rewrite, value: string, s: Scope) => {
    if (!value) throw new Error('Enter an answer')
    await api.updateRewrite(r.id, value, r.enabled, s.scope_type, s.scope_values)
    setEditing(null)
    invalidateAllClientNames()
    load()
  }

  const addFwd = async (e: FormEvent) => {
    e.preventDefault()
    const ups = splitUpstreams(upstreams)
    if (!suffix.trim() || ups.length === 0 || addingFwd) return
    setAddingFwd(true)
    try {
      await api.addForwarder(suffix.trim(), ups, fwdScope.scope_type, fwdScope.scope_values)
      setSuffix('')
      setUpstreams('')
      setFwdScope(ALL_SCOPE)
      setFwdErr('')
      load()
    } catch (e) {
      setFwdErr(errMsg(e))
    } finally {
      setAddingFwd(false)
    }
  }

  const toggleFwd = async (f: Forwarder) => {
    try {
      await api.updateForwarder(f.id, f.upstreams, !f.enabled, f.scope_type, f.scope_values)
      setFwdErr('')
      load()
    } catch (e) {
      setFwdErr(errMsg(e))
    }
  }

  const saveFwdEdit = async (f: Forwarder, raw: string, s: Scope) => {
    const ups = splitUpstreams(raw)
    if (ups.length === 0) throw new Error('Enter at least one resolver')
    await api.updateForwarder(f.id, ups, f.enabled, s.scope_type, s.scope_values)
    setEditingFwd(null)
    load()
  }

  const delFwd = async (f: Forwarder) => {
    if (!window.confirm(`Stop forwarding ${f.suffix} to ${f.upstreams.join(', ')}?`)) return
    try {
      await api.deleteForwarder(f.id)
      setFwdErr('')
      load()
    } catch (e) {
      setFwdErr(errMsg(e))
    }
  }

  const table = useTable(rows, COLS, 'domain')
  const fwdTable = useTable(fwds, FWD_COLS, 'suffix')
  const known = (t?: string) => (t === 'nodes' ? nodes ?? undefined : t === 'sites' ? sites ?? undefined : undefined)
  const recCols = admin ? 5 : 4

  return (
    <div className="pg-rewrites">
      <header className="page-head">
        <h1>Rewrites</h1>
      </header>
      <p className="intro">
        Answer names on your own network. Records are pushed to every agent; scope one to a site or a single agent for
        split-horizon answers.
      </p>
      <div className="rw-explain">
        <span>
          <b className="mono">*.lab.lan</b> matches every subdomain, not the bare name
        </span>
        <span>
          <b>Most specific scope wins:</b> agent › site › everyone
        </span>
        <span>
          <b>A/AAAA records</b> also name the client on every page and answer reverse lookups
        </span>
      </div>

      <section className="card flush">
        <div className="card-head">
          <div>
            <h2>Local records</h2>
            <p className="sub">
              {loaded ? `${rows.length} ${rows.length === 1 ? 'record' : 'records'}` : 'Loading…'}
            </p>
          </div>
        </div>
        {admin && (
          <form className="rw-addrow" onSubmit={add}>
            <label className="field">
              <span>Name</span>
              <input
                className="mono"
                placeholder="nas.home.lan or *.lab.lan"
                value={domain}
                onChange={(e) => setDomain(e.target.value)}
              />
            </label>
            <label className="field">
              <span>Type</span>
              <select value={rrtype} onChange={(e) => setRrtype(e.target.value)}>
                <option>A</option>
                <option>AAAA</option>
                <option>CNAME</option>
              </select>
            </label>
            <label className="field">
              <span>Answer</span>
              <input
                className="mono"
                placeholder={rrtype === 'CNAME' ? 'nas.home.lan' : rrtype === 'AAAA' ? 'fd00::5' : '192.168.1.5'}
                value={value}
                onChange={(e) => setValue(e.target.value)}
              />
            </label>
            <div className="field">
              <label htmlFor="rw-scope">Scope</label>
              <ScopePicker id="rw-scope" value={scope} onChange={setScope} nodes={nodes} sites={sites} />
            </div>
            <button type="submit" className="btn primary" disabled={adding || !domain.trim() || !value.trim()}>
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
                <Th table={table} col="domain">Name</Th>
                <Th table={table} col="value">Answer</Th>
                <Th table={table} col="scope">Scope</Th>
                <th>{admin ? <span className="sr-only">Enabled</span> : 'Status'}</th>
                {admin && <th></th>}
              </tr>
            </thead>
            <tbody>
              {table.rows.map((r) => (
                <tr key={r.id} className={r.enabled ? '' : 'off'}>
                  <td className="lead">
                    <span className="domain">{r.domain}</span>
                  </td>
                  <td>
                    <span className="tag rewrite">{r.rrtype}</span> <span className="domain">{r.value}</span>
                  </td>
                  <td>{scopeBadge(r.scope_type, r.scope_values, known(r.scope_type))}</td>
                  <td className="lead-r rw-switch">
                    {admin ? (
                      <button
                        type="button"
                        role="switch"
                        aria-checked={r.enabled}
                        aria-label={`${r.enabled ? 'Disable' : 'Enable'} ${r.domain}`}
                        className={`switch-btn`}
                        onClick={() => toggle(r)}
                        title={r.enabled ? 'On — click to turn off' : 'Off — click to turn on'}
                      >
                        <span className={`switch${r.enabled ? ' on' : ''}`} />
                      </button>
                    ) : r.enabled ? (
                      <span className="tag ok">On</span>
                    ) : (
                      <span className="tag">Off</span>
                    )}
                  </td>
                  {admin && (
                    <td className="actions">
                      <button className="btn sm quiet" onClick={() => setEditing(r)}>
                        Edit
                      </button>
                      <button className="btn sm quiet rw-del" onClick={() => del(r)}>
                        Delete
                      </button>
                    </td>
                  )}
                </tr>
              ))}
              <TableStatusRow loading={!loaded} error={err} empty={table.rows.length === 0} colSpan={recCols}>
                No records yet.{admin ? ' Add one above to answer a name on your network.' : ''}
              </TableStatusRow>
            </tbody>
          </table>
        </div>
        <Pager table={table} unit="records" />
      </section>

      <h2 className="section">Conditional forwarding</h2>
      <p className="section">
        Send a domain to a specific resolver — your router for <code>home.lan</code>, the office DNS for{' '}
        <code>corp.internal</code>. Entries are pushed to the scoped agents and override an agent's own forwarder for the
        same domain.
      </p>
      <section className="card flush">
        {admin && (
          <form className="rw-addrow fw" onSubmit={addFwd}>
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
              <ScopePicker id="fw-scope" value={fwdScope} onChange={setFwdScope} nodes={nodes} sites={sites} />
            </div>
            <button type="submit" className="btn primary" disabled={addingFwd || !suffix.trim() || !upstreams.trim()}>
              {addingFwd ? 'Adding…' : 'Add'}
            </button>
          </form>
        )}
        {fwdErr && (
          <div className="error rw-err" role="alert">
            {fwdErr}
          </div>
        )}
        <div className="table-scroll">
          <table className="stackable rw-table">
            <thead>
              <tr>
                <Th table={fwdTable} col="suffix">Domain</Th>
                <Th table={fwdTable} col="upstreams">Resolvers</Th>
                <Th table={fwdTable} col="scope">Scope</Th>
                <th>{admin ? <span className="sr-only">Enabled</span> : 'Status'}</th>
                {admin && <th></th>}
              </tr>
            </thead>
            <tbody>
              {fwdTable.rows.map((f) => (
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
                        onClick={() => toggleFwd(f)}
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
                      <button className="btn sm quiet" onClick={() => setEditingFwd(f)}>
                        Edit
                      </button>
                      <button className="btn sm quiet rw-del" onClick={() => delFwd(f)}>
                        Delete
                      </button>
                    </td>
                  )}
                </tr>
              ))}
              <TableStatusRow loading={!fwdsLoaded} error={fwdErr} empty={fwds.length === 0} colSpan={recCols}>
                No forwarding rules. Every name goes to the normal upstream resolvers.
              </TableStatusRow>
            </tbody>
          </table>
        </div>
        <Pager table={fwdTable} unit="rules" />
      </section>

      {editing && (
        <EditScopedModal
          title={`Edit ${editing.domain}`}
          intro={
            <>
              The name <code>{editing.domain}</code> and type <code>{editing.rrtype}</code> identify the record and can't
              be changed. To change them, delete the record and add a new one.
            </>
          }
          fieldLabel={editing.rrtype === 'CNAME' ? 'Answer (target name)' : `Answer (${editing.rrtype === 'AAAA' ? 'IPv6' : 'IPv4'} address)`}
          fieldPlaceholder={editing.rrtype === 'CNAME' ? 'nas.home.lan' : editing.rrtype === 'AAAA' ? 'fd00::5' : '192.168.1.5'}
          initialText={editing.value}
          initialScope={{ scope_type: editing.scope_type || 'all', scope_values: editing.scope_values ?? [] }}
          nodes={nodes}
          sites={sites}
          onClose={closeEdit}
          onSave={(text, s) => saveEdit(editing, text, s)}
        />
      )}
      {editingFwd && (
        <EditScopedModal
          title={`Edit forwarding for ${editingFwd.suffix}`}
          intro={
            <>
              The domain <code>{editingFwd.suffix}</code> identifies the rule and can't be changed. To change it, delete
              the rule and add a new one.
            </>
          }
          fieldLabel="Resolvers (comma-separated)"
          fieldPlaceholder="10.0.0.2:53, 10.0.0.3:53"
          initialText={editingFwd.upstreams.join(', ')}
          initialScope={{ scope_type: editingFwd.scope_type || 'all', scope_values: editingFwd.scope_values ?? [] }}
          nodes={nodes}
          sites={sites}
          onClose={closeEditFwd}
          onSave={(text, s) => saveFwdEdit(editingFwd, text, s)}
        />
      )}
    </div>
  )
}

// EditScopedModal edits the mutable part of a scoped entry (record answer or
// forwarding resolvers, plus the scope). Save errors, including the backend's
// 409 when the new scope overlaps another entry for the same name, are shown
// inside the dialog so the operator can adjust the scope and retry.
function EditScopedModal({
  title,
  intro,
  fieldLabel,
  fieldPlaceholder,
  initialText,
  initialScope,
  nodes,
  sites,
  onClose,
  onSave,
}: {
  title: string
  intro: ReactNode
  fieldLabel: string
  fieldPlaceholder: string
  initialText: string
  initialScope: Scope
  nodes: string[] | null
  sites: string[] | null
  onClose: () => void
  onSave: (text: string, scope: Scope) => Promise<void>
}) {
  const [text, setText] = useState(initialText)
  const [scope, setScope] = useState<Scope>(initialScope)
  const [saving, setSaving] = useState(false)
  const [err, setErr] = useState('')
  // Modal focuses its panel on open (its effect runs after ours), so move focus
  // into the field on the next tick instead of relying on autoFocus.
  const field = useRef<HTMLInputElement>(null)
  useEffect(() => {
    const t = setTimeout(() => field.current?.focus(), 0)
    return () => clearTimeout(t)
  }, [])

  const save = async (e?: FormEvent) => {
    e?.preventDefault()
    if (saving) return
    setSaving(true)
    setErr('')
    try {
      await onSave(text.trim(), scope)
    } catch (e) {
      setErr(errMsg(e))
      setSaving(false)
    }
  }

  return (
    <Modal
      kind="dialog"
      title={title}
      onClose={onClose}
      footer={
        <>
          <span className="spacer" />
          <button className="btn ghost" onClick={onClose} disabled={saving}>
            Cancel
          </button>
          <button className="btn primary" onClick={() => save()} disabled={saving}>
            {saving ? 'Saving…' : 'Save'}
          </button>
        </>
      }
    >
      <form className="rw-edit" onSubmit={save}>
        <p className="muted">{intro}</p>
        <label className="field">
          <span>{fieldLabel}</span>
          <input
            ref={field}
            className="mono"
            placeholder={fieldPlaceholder}
            value={text}
            onChange={(e) => setText(e.target.value)}
          />
        </label>
        <div className="field">
          <label htmlFor="edit-scope">Scope</label>
          <ScopePicker id="edit-scope" value={scope} onChange={setScope} nodes={nodes} sites={sites} />
        </div>
        {err && (
          <div className="error" role="alert">
            {err}
          </div>
        )}
        {/* Enter in the field submits the form. */}
        <button type="submit" hidden />
      </form>
    </Modal>
  )
}
