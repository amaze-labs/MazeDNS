import { useEffect, useRef, useState, type FormEvent } from 'react'
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
  const [importing, setImporting] = useState(false)
  const fileRef = useRef<HTMLInputElement>(null)

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

  const importFiles = async (files: FileList) => {
    setErr('')
    setMsg('')
    setImporting(true)
    try {
      let total = 0
      for (const f of Array.from(files)) {
        const r = await api.importRules(await f.text(), importCategory)
        total += r.imported
      }
      setMsg(`Imported ${total} rules from ${files.length} file${files.length > 1 ? 's' : ''} as “${importCategory}”`)
      load()
    } catch (e: any) {
      setErr(e.message)
      setMsg('')
    } finally {
      setImporting(false)
      if (fileRef.current) fileRef.current.value = ''
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
      <p className="muted">Paste a list or upload one or more files. Everything is imported under the chosen category.</p>
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
          <button type="submit" className="btn primary" disabled={importing}>
            Import pasted
          </button>
          <span className="import-group">
            <button type="button" className="btn" disabled={importing} onClick={() => fileRef.current?.click()}>
              {importing ? 'Importing…' : '⬆ Import file(s)…'}
            </button>
          </span>
          <input
            ref={fileRef}
            type="file"
            accept=".txt,.hosts,.list,.conf,text/plain"
            multiple
            hidden
            onChange={(e) => e.target.files?.length && importFiles(e.target.files)}
          />
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
