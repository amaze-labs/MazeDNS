import { useEffect, useState, type FormEvent } from 'react'
import { api, type Rule } from '../api'

const categories = ['custom', 'ads', 'trackers', 'malware']

export default function Rules() {
  const [rules, setRules] = useState<Rule[]>([])
  const [action, setAction] = useState('deny')
  const [domain, setDomain] = useState('')
  const [category, setCategory] = useState('custom')
  const [importText, setImportText] = useState('')
  const [importCategory, setImportCategory] = useState('ads')
  const [msg, setMsg] = useState('')
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
      setMsg('')
      load()
    } catch (e: any) {
      setErr(e.message)
    }
  }

  const doImport = async (e: FormEvent) => {
    e.preventDefault()
    if (!importText.trim()) return
    try {
      const r = await api.importRules(importText, importCategory)
      setImportText('')
      setErr('')
      setMsg(`Imported ${r.imported} rules`)
      load()
    } catch (e: any) {
      setErr(e.message)
      setMsg('')
    }
  }

  const del = async (id: number) => {
    await api.deleteRule(id)
    load()
  }

  return (
    <div>
      <h2>Block / allow rules</h2>
      {err && <div className="error">{err}</div>}
      {msg && <div className="ok-msg">{msg}</div>}

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
        <button type="submit">Add</button>
      </form>

      <h2>Import list (AdGuard / Pi-hole / hosts)</h2>
      <form onSubmit={doImport}>
        <textarea
          className="import"
          rows={6}
          placeholder={'Paste a blocklist…\n||ads.example.com^\n0.0.0.0 tracker.example.com\nplain-domain.example'}
          value={importText}
          onChange={(e) => setImportText(e.target.value)}
        />
        <div className="row">
          <select value={importCategory} onChange={(e) => setImportCategory(e.target.value)}>
            {categories.map((c) => (
              <option key={c} value={c}>
                {c}
              </option>
            ))}
          </select>
          <button type="submit">Import</button>
        </div>
      </form>

      <table>
        <thead>
          <tr>
            <th>Action</th>
            <th>Domain</th>
            <th>Category</th>
            <th></th>
          </tr>
        </thead>
        <tbody>
          {rules.map((r) => (
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
          {rules.length === 0 && (
            <tr>
              <td colSpan={4} className="muted">
                No rules
              </td>
            </tr>
          )}
        </tbody>
      </table>
    </div>
  )
}
