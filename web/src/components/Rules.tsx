import { useEffect, useState, type FormEvent } from 'react'
import { api, type Rule } from '../api'
import { useTable, Th, Pager, type SortAccessors } from './tableKit'

const categories = ['custom', 'ads', 'trackers', 'malware', 'phishing', 'not-found']

const COLS: SortAccessors<Rule> = {
  action: (r) => r.action,
  domain: (r) => r.domain,
  category: (r) => r.category,
}

export default function Rules() {
  const [rules, setRules] = useState<Rule[]>([])
  const [action, setAction] = useState('deny')
  const [domain, setDomain] = useState('')
  const [category, setCategory] = useState('custom')
  const [err, setErr] = useState('')

  const load = () => api.rules().then(setRules).catch((e) => setErr(e.message))
  useEffect(() => {
    load()
  }, [])

  const add = async (e: FormEvent) => {
    e.preventDefault()
    if (!domain.trim()) return
    try {
      await api.addRule(action, domain.trim(), category)
      setDomain('')
      setErr('')
      load()
    } catch (e: any) {
      setErr(e.message)
    }
  }

  const del = async (id: number) => {
    await api.deleteRule(id)
    load()
  }

  const table = useTable(rules, COLS, 'domain')

  return (
    <div>
      <h2>Manual rules</h2>
      <p className="muted">
        Individual allow/deny entries. Imported blocklists live under the <strong>Blocklists</strong> tab.
      </p>
      {err && <div className="error">{err}</div>}

      <form className="row" onSubmit={add}>
        <select value={action} onChange={(e) => setAction(e.target.value)}>
          <option value="deny">deny</option>
          <option value="allow">allow</option>
        </select>
        <input placeholder="domain (e.g. ads.example.com)" value={domain} onChange={(e) => setDomain(e.target.value)} />
        <select value={category} onChange={(e) => setCategory(e.target.value)}>
          {categories.map((c) => (
            <option key={c} value={c}>
              {c}
            </option>
          ))}
        </select>
        <button type="submit" className="btn primary">
          Add
        </button>
      </form>

      <table>
        <thead>
          <tr>
            <Th table={table} col="action">Action</Th>
            <Th table={table} col="domain">Domain</Th>
            <Th table={table} col="category">Category</Th>
            <th></th>
          </tr>
        </thead>
        <tbody>
          {table.rows.map((r) => (
            <tr key={r.id}>
              <td>
                <span className={`badge ${r.action === 'deny' ? 'blocked' : 'allow'}`}>{r.action}</span>
              </td>
              <td>{r.domain}</td>
              <td>{r.category}</td>
              <td>
                <button className="del" onClick={() => del(r.id)}>
                  ✕
                </button>
              </td>
            </tr>
          ))}
          {table.rows.length === 0 && (
            <tr>
              <td colSpan={4} className="muted">
                No manual rules
              </td>
            </tr>
          )}
        </tbody>
      </table>
      <Pager table={table} unit="rules" />
    </div>
  )
}
