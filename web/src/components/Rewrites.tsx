import { useEffect, useState, type FormEvent } from 'react'
<<<<<<< feature/scoped-rewrites-forwarders
import { api, type Forwarder, type Rewrite } from '../api'
import ScopePicker, { ALL_SCOPE, scopeBadge, type Scope } from './ScopePicker'
=======
import { api, type Rewrite } from '../api'
import { useTable, Th, Pager, type SortAccessors } from './tableKit'

const COLS: SortAccessors<Rewrite> = {
  domain: (r) => r.domain,
  rrtype: (r) => r.rrtype,
  value: (r) => r.value,
}
>>>>>>> main

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
      load()
    } catch (e: any) {
      setErr(e.message)
    }
  }

  const del = async (id: number) => {
    await api.deleteRewrite(id)
    load()
  }

<<<<<<< feature/scoped-rewrites-forwarders
  const addFwd = async (e: FormEvent) => {
    e.preventDefault()
    const ups = upstreams
      .split(',')
      .map((u) => u.trim())
      .filter(Boolean)
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

  const delFwd = async (id: number) => {
    await api.deleteForwarder(id)
    load()
  }
=======
  const table = useTable(rows, COLS, 'domain')
>>>>>>> main

  return (
    <div>
      <h2>Local DNS rewrites</h2>
      <p className="muted">
        Use <code>*.example.com</code> to match every subdomain. The wildcard does not cover the bare
        <code> example.com</code> — add a separate entry for the apex if you need it. Scope an entry to
        nodes or sites for split-horizon answers; the most specific scope wins (node &gt; site &gt; all).
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
        <ScopePicker value={scope} onChange={setScope} nodes={nodes ?? []} sites={sites ?? []} />
        <button type="submit">Add</button>
      </form>
      <table>
        <thead>
          <tr>
<<<<<<< feature/scoped-rewrites-forwarders
            <th>Domain</th>
            <th>Type</th>
            <th>Value</th>
            <th>Scope</th>
=======
            <Th table={table} col="domain">Domain</Th>
            <Th table={table} col="rrtype">Type</Th>
            <Th table={table} col="value">Value</Th>
>>>>>>> main
            <th></th>
          </tr>
        </thead>
        <tbody>
          {table.rows.map((r) => (
            <tr key={r.id}>
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
                <button className="del" onClick={() => del(r.id)}>
                  ✕
                </button>
              </td>
            </tr>
          ))}
          {table.rows.length === 0 && (
            <tr>
              <td colSpan={5} className="muted">
                No rewrites
              </td>
            </tr>
          )}
        </tbody>
      </table>
<<<<<<< feature/scoped-rewrites-forwarders

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
        <ScopePicker value={fwdScope} onChange={setFwdScope} nodes={nodes ?? []} sites={sites ?? []} />
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
                <button className="del" onClick={() => delFwd(f.id)}>
                  ✕
                </button>
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
=======
      <Pager table={table} unit="rewrites" />
>>>>>>> main
    </div>
  )
}
