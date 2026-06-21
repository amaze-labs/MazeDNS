import { useEffect, useState, type FormEvent } from 'react'
import { api, type Rewrite } from '../api'

export default function Rewrites() {
  const [rows, setRows] = useState<Rewrite[]>([])
  const [domain, setDomain] = useState('')
  const [rrtype, setRrtype] = useState('A')
  const [value, setValue] = useState('')
  const [err, setErr] = useState('')

  const load = () => api.rewrites().then(setRows).catch((e) => setErr(e.message))
  useEffect(() => {
    load()
  }, [])

  const add = async (e: FormEvent) => {
    e.preventDefault()
    if (!domain.trim() || !value.trim()) return
    try {
      await api.addRewrite(domain.trim(), rrtype, value.trim())
      setDomain('')
      setValue('')
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

  return (
    <div>
      <h2>Local DNS rewrites</h2>
      {err && <div className="error">{err}</div>}
      <form className="row" onSubmit={add}>
        <input placeholder="domain (e.g. nas.lan)" value={domain} onChange={(e) => setDomain(e.target.value)} />
        <select value={rrtype} onChange={(e) => setRrtype(e.target.value)}>
          <option>A</option>
          <option>AAAA</option>
          <option>CNAME</option>
        </select>
        <input placeholder="value (IP or target)" value={value} onChange={(e) => setValue(e.target.value)} />
        <button type="submit">Add</button>
      </form>
      <table>
        <thead>
          <tr>
            <th>Domain</th>
            <th>Type</th>
            <th>Value</th>
            <th></th>
          </tr>
        </thead>
        <tbody>
          {rows.map((r) => (
            <tr key={r.id}>
              <td>{r.domain}</td>
              <td>{r.rrtype}</td>
              <td>{r.value}</td>
              <td>
                <button className="del" onClick={() => del(r.id)}>
                  ✕
                </button>
              </td>
            </tr>
          ))}
          {rows.length === 0 && (
            <tr>
              <td colSpan={4} className="muted">
                No rewrites
              </td>
            </tr>
          )}
        </tbody>
      </table>
    </div>
  )
}
