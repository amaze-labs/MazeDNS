import { useEffect, useState, type FormEvent } from 'react'
import { api, type Rule } from '../api'

export default function Rules() {
  const [rules, setRules] = useState<Rule[]>([])
  const [action, setAction] = useState('deny')
  const [domain, setDomain] = useState('')
  const [err, setErr] = useState('')

  const load = () => api.rules().then(setRules).catch((e) => setErr(e.message))
  useEffect(() => {
    load()
  }, [])

  const add = async (e: FormEvent) => {
    e.preventDefault()
    if (!domain.trim()) return
    try {
      await api.addRule(action, domain.trim())
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

  return (
    <div>
      <h2>Block / allow rules</h2>
      {err && <div className="error">{err}</div>}
      <form className="row" onSubmit={add}>
        <select value={action} onChange={(e) => setAction(e.target.value)}>
          <option value="deny">deny</option>
          <option value="allow">allow</option>
        </select>
        <input
          placeholder="domain (e.g. ads.example.com)"
          value={domain}
          onChange={(e) => setDomain(e.target.value)}
        />
        <button type="submit">Add</button>
      </form>
      <table>
        <thead>
          <tr>
            <th>Action</th>
            <th>Domain</th>
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
              <td>
                <button className="del" onClick={() => del(r.id)}>
                  ✕
                </button>
              </td>
            </tr>
          ))}
          {rules.length === 0 && (
            <tr>
              <td colSpan={3} className="muted">
                No rules
              </td>
            </tr>
          )}
        </tbody>
      </table>
    </div>
  )
}
