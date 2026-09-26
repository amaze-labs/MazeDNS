import { useEffect, useState, type FormEvent, type ReactNode } from 'react'
import { api, type Forwarder, type Rewrite } from '../api'
import Modal from './Modal'
import ScopePicker, { ALL_SCOPE, scopeBadge, type Scope } from './ScopePicker'
import { useTable, Th, Pager, type SortAccessors } from './tableKit'
import { invalidateAllClientNames } from '../useClientNames'

// Upstreams are edited as one comma-separated field in both the add form and
// the edit dialog.
const splitUpstreams = (raw: string) =>
  raw
    .split(',')
    .map((u) => u.trim())
    .filter(Boolean)

const COLS: SortAccessors<Rewrite> = {
  domain: (r) => r.domain,
  rrtype: (r) => r.rrtype,
  value: (r) => r.value,
}

export default function Rewrites() {
  const [rows, setRows] = useState<Rewrite[]>([])
  const [domain, setDomain] = useState('')
  const [rrtype, setRrtype] = useState('A')
  const [value, setValue] = useState('')
  const [scope, setScope] = useState<Scope>(ALL_SCOPE)
  const [err, setErr] = useState('')

  const [fwds, setFwds] = useState<Forwarder[]>([])
  const [suffix, setSuffix] = useState('')
  const [upstreams, setUpstreams] = useState('')
  const [fwdScope, setFwdScope] = useState<Scope>(ALL_SCOPE)
  const [fwdErr, setFwdErr] = useState('')

  const [nodes, setNodes] = useState<string[] | null>(null)
  const [sites, setSites] = useState<string[] | null>(null)

  const [editing, setEditing] = useState<Rewrite | null>(null)
  const [editingFwd, setEditingFwd] = useState<Forwarder | null>(null)

  const load = () => {
    api.rewrites().then(setRows).catch((e) => setErr(e.message))
    api.forwarders().then((f) => {
      setFwds(f)
      setFwdErr('')
    }).catch((e) => setFwdErr(e.message))
  }
  useEffect(() => {
    load()
    // Cluster lists feed the scope pickers; on a standalone control plane the
    // calls fail and scoping simply collapses to "all nodes".
    api.clusterNodes().then((ns) => setNodes(ns.map((n) => n.name))).catch(() => {})
    api.clusterSites().then((ss) => setSites(ss.map((s) => s.name))).catch(() => {})
  }, [])

  const add = async (e: FormEvent) => {
    e.preventDefault()
    if (!domain.trim() || !value.trim()) return
    try {
      await api.addRewrite(domain.trim(), rrtype, value.trim(), scope.scope_type, scope.scope_values)
      setDomain('')
      setValue('')
      setScope(ALL_SCOPE)
      setErr('')
      invalidateAllClientNames()
      load()
    } catch (e: any) {
      setErr(e.message)
    }
  }

  const del = async (id: number) => {
    await api.deleteRewrite(id)
    invalidateAllClientNames()
    load()
  }

  const toggle = async (r: Rewrite) => {
    try {
      await api.updateRewrite(r.id, r.value, !r.enabled, r.scope_type || 'all', r.scope_values ?? [])
      setErr('')
      load()
    } catch (e: any) {
      setErr(e.message)
    }
  }

  const saveEdit = async (r: Rewrite, value: string, s: Scope) => {
    if (!value) throw new Error('value required')
    await api.updateRewrite(r.id, value, r.enabled, s.scope_type, s.scope_values)
    setEditing(null)
    load()
  }

  const addFwd = async (e: FormEvent) => {
    e.preventDefault()
    const ups = splitUpstreams(upstreams)
    if (!suffix.trim() || ups.length === 0) return
    try {
      await api.addForwarder(suffix.trim(), ups, fwdScope.scope_type, fwdScope.scope_values)
      setSuffix('')
      setUpstreams('')
      setFwdScope(ALL_SCOPE)
      setFwdErr('')
      load()
    } catch (e: any) {
      setFwdErr(e.message)
    }
  }

  const toggleFwd = async (f: Forwarder) => {
    try {
      await api.updateForwarder(f.id, f.upstreams, !f.enabled, f.scope_type, f.scope_values)
      load()
    } catch (e: any) {
      setFwdErr(e.message)
    }
  }

  const saveFwdEdit = async (f: Forwarder, raw: string, s: Scope) => {
    const ups = splitUpstreams(raw)
    if (ups.length === 0) throw new Error('at least one upstream is required')
    await api.updateForwarder(f.id, ups, f.enabled, s.scope_type, s.scope_values)
    setEditingFwd(null)
    load()
  }

  const delFwd = async (id: number) => {
    await api.deleteForwarder(id)
    load()
  }

  const table = useTable(rows, COLS, 'domain')

  return (
    <div>
      <h2>Local DNS rewrites</h2>
      <p className="muted">
        Use <code>*.example.com</code> to match every subdomain. The wildcard does not cover the bare
        <code> example.com</code> — add a separate entry for the apex if you need it. Scope an entry to
        nodes or sites for split-horizon answers; the most specific scope wins (node &gt; site &gt; all).
        Exact <code>A</code>/<code>AAAA</code> entries also name clients on the Clients page and answer reverse
        (PTR) lookups for their address.
      </p>
      {err && <div className="error">{err}</div>}
      <form className="row" onSubmit={add}>
        <input placeholder="domain (e.g. nas.lan or *.lab.lan)" value={domain} onChange={(e) => setDomain(e.target.value)} />
        <select value={rrtype} onChange={(e) => setRrtype(e.target.value)}>
          <option>A</option>
          <option>AAAA</option>
          <option>CNAME</option>
        </select>
        <input placeholder="value (IP or target)" value={value} onChange={(e) => setValue(e.target.value)} />
        <ScopePicker value={scope} onChange={setScope} nodes={nodes} sites={sites} />
        <button type="submit">Add</button>
      </form>
      <table>
        <thead>
          <tr>
            <Th table={table} col="domain">Domain</Th>
            <Th table={table} col="rrtype">Type</Th>
            <Th table={table} col="value">Value</Th>
            <th>Scope</th>
            <th>Enabled</th>
            <th></th>
          </tr>
        </thead>
        <tbody>
          {table.rows.map((r) => (
            <tr key={r.id} className={r.enabled ? '' : 'muted'}>
              <td>{r.domain}</td>
              <td>{r.rrtype}</td>
              <td>{r.value}</td>
              <td>
                {scopeBadge(
                  r.scope_type,
                  r.scope_values,
                  r.scope_type === 'nodes' ? nodes ?? undefined : r.scope_type === 'sites' ? sites ?? undefined : undefined,
                )}
              </td>
              <td>
                <button onClick={() => toggle(r)}>{r.enabled ? 'On' : 'Off'}</button>
              </td>
              <td>
                <div className="actions">
                  <button className="btn ghost" onClick={() => setEditing(r)}>
                    Edit
                  </button>
                  <button className="del" onClick={() => del(r.id)} title="Delete">
                    ✕
                  </button>
                </div>
              </td>
            </tr>
          ))}
          {table.rows.length === 0 && (
            <tr>
              <td colSpan={6} className="muted">
                No rewrites
              </td>
            </tr>
          )}
        </tbody>
      </table>
      <Pager table={table} unit="rewrites" />

      <h2>Conditional forwarders (cluster)</h2>
      <p className="muted">
        Send a domain suffix to specific upstreams. Entries here are pushed to the scoped agents
        automatically and override a node's own forwarder for the same suffix.
      </p>
      {fwdErr && <div className="error">{fwdErr}</div>}
      <form className="row" onSubmit={addFwd}>
        <input placeholder="suffix (e.g. corp.internal)" value={suffix} onChange={(e) => setSuffix(e.target.value)} />
        <input
          placeholder="upstreams, comma-separated (e.g. 10.0.0.2:53)"
          value={upstreams}
          onChange={(e) => setUpstreams(e.target.value)}
        />
        <ScopePicker value={fwdScope} onChange={setFwdScope} nodes={nodes} sites={sites} />
        <button type="submit">Add</button>
      </form>
      <table>
        <thead>
          <tr>
            <th>Suffix</th>
            <th>Upstreams</th>
            <th>Scope</th>
            <th>Enabled</th>
            <th></th>
          </tr>
        </thead>
        <tbody>
          {fwds.map((f) => (
            <tr key={f.id} className={f.enabled ? '' : 'muted'}>
              <td>{f.suffix}</td>
              <td>{f.upstreams.join(', ')}</td>
              <td>
                {scopeBadge(
                  f.scope_type,
                  f.scope_values,
                  f.scope_type === 'nodes' ? nodes ?? undefined : f.scope_type === 'sites' ? sites ?? undefined : undefined,
                )}
              </td>
              <td>
                <button onClick={() => toggleFwd(f)}>{f.enabled ? 'On' : 'Off'}</button>
              </td>
              <td>
                <div className="actions">
                  <button className="btn ghost" onClick={() => setEditingFwd(f)}>
                    Edit
                  </button>
                  <button className="del" onClick={() => delFwd(f.id)} title="Delete">
                    ✕
                  </button>
                </div>
              </td>
            </tr>
          ))}
          {fwds.length === 0 && (
            <tr>
              <td colSpan={5} className="muted">
                No cluster forwarders
              </td>
            </tr>
          )}
        </tbody>
      </table>

      {editing && (
        <EditScopedModal
          title={`Edit rewrite ${editing.domain}`}
          intro={
            <>
              Domain <code>{editing.domain}</code> and type <code>{editing.rrtype}</code> identify the record and can't
              be changed; delete it and add a new one instead.
            </>
          }
          fieldLabel={editing.rrtype === 'CNAME' ? 'Value (target name)' : `Value (${editing.rrtype === 'AAAA' ? 'IPv6' : 'IPv4'} address)`}
          fieldPlaceholder="value (IP or target)"
          initialText={editing.value}
          initialScope={{ scope_type: editing.scope_type || 'all', scope_values: editing.scope_values ?? [] }}
          nodes={nodes}
          sites={sites}
          onClose={() => setEditing(null)}
          onSave={(text, s) => saveEdit(editing, text, s)}
        />
      )}
      {editingFwd && (
        <EditScopedModal
          title={`Edit forwarder ${editingFwd.suffix}`}
          intro={
            <>
              The suffix <code>{editingFwd.suffix}</code> identifies the forwarder and can't be changed; delete it and add
              a new one instead.
            </>
          }
          fieldLabel="Upstreams (comma-separated)"
          fieldPlaceholder="e.g. 10.0.0.2:53"
          initialText={editingFwd.upstreams.join(', ')}
          initialScope={{ scope_type: editingFwd.scope_type || 'all', scope_values: editingFwd.scope_values ?? [] }}
          nodes={nodes}
          sites={sites}
          onClose={() => setEditingFwd(null)}
          onSave={(text, s) => saveFwdEdit(editingFwd, text, s)}
        />
      )}
    </div>
  )
}

// EditScopedModal edits the mutable part of a scoped entry (rewrite value or
// forwarder upstreams, plus the scope). Save errors, including the backend's
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

  const save = async () => {
    if (saving) return
    setSaving(true)
    setErr('')
    try {
      await onSave(text.trim(), scope)
    } catch (e: any) {
      setErr(e.message)
      setSaving(false)
    }
  }

  return (
    <Modal title={title} onClose={onClose}>
      <p className="muted" style={{ textAlign: 'left', marginTop: 0 }}>
        {intro}
      </p>
      <div className="field">
        <label>{fieldLabel}</label>
        <input
          autoFocus
          placeholder={fieldPlaceholder}
          value={text}
          onChange={(e) => setText(e.target.value)}
          onKeyDown={(e) => e.key === 'Enter' && save()}
        />
      </div>
      <div className="field">
        <label>Scope</label>
        <ScopePicker value={scope} onChange={setScope} nodes={nodes} sites={sites} />
      </div>
      {err && <div className="error">{err}</div>}
      <div className="settings-actions" style={{ marginTop: 8 }}>
        <button className="btn ghost" onClick={onClose} disabled={saving}>
          Cancel
        </button>
        <button className="btn primary" onClick={save} disabled={saving}>
          {saving ? 'Saving…' : 'Save'}
        </button>
      </div>
    </Modal>
  )
}
