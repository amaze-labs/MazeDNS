import { useEffect, useRef, useState, type FormEvent } from 'react'
import { api, type List, type Protection, type Rule } from '../api'

const categories = ['custom', 'ads', 'trackers', 'malware']
const PAUSE_PRESETS = [
  { label: '30 seconds', seconds: 30 },
  { label: '5 minutes', seconds: 300 },
  { label: '30 minutes', seconds: 1800 },
  { label: 'Until I re-enable', seconds: 0 },
]

function ago(unixSec: number): string {
  if (!unixSec) return 'never'
  const s = Math.max(0, Math.floor(Date.now() / 1000 - unixSec))
  if (s < 60) return `${s}s ago`
  if (s < 3600) return `${Math.floor(s / 60)}m ago`
  if (s < 86400) return `${Math.floor(s / 3600)}h ago`
  return `${Math.floor(s / 86400)}d ago`
}

function fmtLeft(s: number): string {
  if (s <= 0) return ''
  if (s < 60) return `${s}s`
  if (s < 3600) return `${Math.floor(s / 60)}m ${s % 60}s`
  if (s > 86400 * 365) return 'until re-enabled'
  return `${Math.floor(s / 3600)}h ${Math.floor((s % 3600) / 60)}m`
}

export default function Lists() {
  const [lists, setLists] = useState<List[]>([])
  const [prot, setProt] = useState<Protection | null>(null)
  const [err, setErr] = useState('')
  const [msg, setMsg] = useState('')

  // expand-to-view rules
  const [openId, setOpenId] = useState<number | null>(null)
  const [openRules, setOpenRules] = useState<Rule[]>([])

  // import (file / paste)
  const [name, setName] = useState('')
  const [category, setCategory] = useState('ads')
  const [paste, setPaste] = useState('')
  const fileRef = useRef<HTMLInputElement>(null)

  // url subscription
  const [urlName, setUrlName] = useState('')
  const [url, setUrl] = useState('')
  const [urlCategory, setUrlCategory] = useState('ads')
  const [interval, setIntervalMin] = useState(60)

  const load = async () => {
    try {
      const [ls, p] = await Promise.all([api.lists(), api.protection()])
      setLists(ls)
      setProt(p)
      setErr('')
    } catch (e: any) {
      setErr(e.message)
    }
  }
  useEffect(() => {
    load()
    const id = setInterval(load, 5000)
    return () => clearInterval(id)
  }, [])

  const flash = (m: string) => {
    setMsg(m)
    setErr('')
  }

  const toggle = async (l: List) => {
    try {
      await api.updateList(l.id, { enabled: !l.enabled })
      load()
    } catch (e: any) {
      setErr(e.message)
    }
  }
  const refresh = async (l: List) => {
    flash(`Refreshing ${l.name}…`)
    try {
      const updated = await api.refreshList(l.id)
      flash(updated.last_error ? `${l.name}: ${updated.last_error}` : `${l.name} refreshed.`)
      load()
    } catch (e: any) {
      setErr(e.message)
    }
  }
  const del = async (l: List) => {
    if (!window.confirm(`Remove the list “${l.name}” and all of its rules?`)) return
    try {
      await api.deleteList(l.id)
      if (openId === l.id) setOpenId(null)
      load()
    } catch (e: any) {
      setErr(e.message)
    }
  }
  const expand = async (l: List) => {
    if (openId === l.id) {
      setOpenId(null)
      return
    }
    try {
      const rules = await api.listRules(l.id)
      setOpenRules(rules)
      setOpenId(l.id)
    } catch (e: any) {
      setErr(e.message)
    }
  }
  const setListInterval = async (l: List, minutes: number) => {
    try {
      await api.updateList(l.id, { interval_minutes: minutes })
      load()
    } catch (e: any) {
      setErr(e.message)
    }
  }

  const importPaste = async (e: FormEvent) => {
    e.preventDefault()
    if (!name.trim() || !paste.trim()) return
    try {
      const r = await api.importList(name.trim(), category, paste, 'paste')
      setName('')
      setPaste('')
      flash(`Imported ${r.imported} rules into “${r.name}”.`)
      load()
    } catch (e: any) {
      setErr(e.message)
    }
  }
  const importFiles = async (files: FileList) => {
    try {
      let total = 0
      for (const f of Array.from(files)) {
        const r = await api.importList(f.name, category, await f.text(), 'file')
        total += r.imported
      }
      flash(`Imported ${total} rules from ${files.length} file${files.length > 1 ? 's' : ''}.`)
      load()
    } catch (e: any) {
      setErr(e.message)
    } finally {
      if (fileRef.current) fileRef.current.value = ''
    }
  }
  const addUrl = async (e: FormEvent) => {
    e.preventDefault()
    if (!urlName.trim() || !url.trim()) return
    try {
      const l = await api.addUrlList(urlName.trim(), url.trim(), urlCategory, interval)
      setUrlName('')
      setUrl('')
      flash(l.last_error ? `Added, but fetch failed: ${l.last_error}` : `Added “${l.name}” (${l.rule_count} rules).`)
      load()
    } catch (e: any) {
      setErr(e.message)
    }
  }

  const disable = async (seconds: number) => {
    try {
      setProt(await api.disableProtection(seconds))
    } catch (e: any) {
      setErr(e.message)
    }
  }
  const enable = async () => {
    try {
      setProt(await api.enableProtection())
    } catch (e: any) {
      setErr(e.message)
    }
  }

  return (
    <div>
      <h2>Protection</h2>
      <div className={`settings-card protection ${prot?.paused ? 'paused' : ''}`}>
        {prot?.paused ? (
          <div className="protection-row">
            <span className="badge blocked">Blocking paused</span>
            <span className="muted">{fmtLeft(prot.seconds_left)} remaining</span>
            <button className="btn primary" onClick={enable}>
              Resume blocking
            </button>
          </div>
        ) : (
          <div className="protection-row">
            <span className="badge allow">Protection active</span>
            <span className="muted">Disable blocking for:</span>
            {PAUSE_PRESETS.map((p) => (
              <button key={p.seconds} className="btn" onClick={() => disable(p.seconds)}>
                {p.label}
              </button>
            ))}
          </div>
        )}
      </div>

      <h2>Block lists</h2>
      {err && <div className="error">{err}</div>}
      {msg && <div className="ok-msg">{msg}</div>}

      <table>
        <thead>
          <tr>
            <th>List</th>
            <th>Source</th>
            <th>Category</th>
            <th>Rules</th>
            <th>Updated</th>
            <th>Enabled</th>
            <th></th>
          </tr>
        </thead>
        <tbody>
          {lists.map((l) => (
            <RowGroup
              key={l.id}
              l={l}
              open={openId === l.id}
              rules={openId === l.id ? openRules : []}
              onExpand={() => expand(l)}
              onToggle={() => toggle(l)}
              onRefresh={() => refresh(l)}
              onDelete={() => del(l)}
              onInterval={(m) => setListInterval(l, m)}
            />
          ))}
          {lists.length === 0 && (
            <tr>
              <td colSpan={7} className="muted">
                No lists yet — import a file or add a URL below
              </td>
            </tr>
          )}
        </tbody>
      </table>

      <div className="charts">
        <div className="panel">
          <h2>Import a list (file or paste)</h2>
          <p className="muted">AdGuard / Pi-hole / hosts syntax. Each file becomes a list named after the file.</p>
          <form onSubmit={importPaste}>
            <div className="row">
              <input placeholder="list name" value={name} onChange={(e) => setName(e.target.value)} />
              <select value={category} onChange={(e) => setCategory(e.target.value)}>
                {categories.map((c) => (
                  <option key={c}>{c}</option>
                ))}
              </select>
            </div>
            <textarea
              className="import"
              rows={5}
              placeholder={'Paste a list…\n||ads.example.com^\n0.0.0.0 tracker.example.com'}
              value={paste}
              onChange={(e) => setPaste(e.target.value)}
            />
            <div className="row">
              <button type="submit" className="btn primary">
                Import pasted
              </button>
              <button type="button" className="btn" onClick={() => fileRef.current?.click()}>
                ⬆ Import file(s)…
              </button>
              <input
                ref={fileRef}
                type="file"
                accept=".list,.txt,text/plain"
                multiple
                hidden
                onChange={(e) => e.target.files?.length && importFiles(e.target.files)}
              />
            </div>
          </form>
        </div>

        <div className="panel">
          <h2>Subscribe to a URL</h2>
          <p className="muted">Fetches a remote list (e.g. a raw GitHub .list file) and re-fetches on a schedule.</p>
          <form onSubmit={addUrl}>
            <div className="row">
              <input placeholder="list name" value={urlName} onChange={(e) => setUrlName(e.target.value)} />
              <select value={urlCategory} onChange={(e) => setUrlCategory(e.target.value)}>
                {categories.map((c) => (
                  <option key={c}>{c}</option>
                ))}
              </select>
            </div>
            <div className="row">
              <input
                placeholder="https://raw.githubusercontent.com/owner/repo/main/blocklist.list"
                value={url}
                onChange={(e) => setUrl(e.target.value)}
              />
            </div>
            <div className="row">
              <label className="muted">Refresh every</label>
              <select value={interval} onChange={(e) => setIntervalMin(Number(e.target.value))}>
                <option value={0}>manual only</option>
                <option value={15}>15 minutes</option>
                <option value={60}>1 hour</option>
                <option value={360}>6 hours</option>
                <option value={1440}>1 day</option>
              </select>
              <button type="submit" className="btn primary">
                Add URL list
              </button>
            </div>
          </form>
        </div>
      </div>
    </div>
  )
}

function RowGroup({
  l,
  open,
  rules,
  onExpand,
  onToggle,
  onRefresh,
  onDelete,
  onInterval,
}: {
  l: List
  open: boolean
  rules: Rule[]
  onExpand: () => void
  onToggle: () => void
  onRefresh: () => void
  onDelete: () => void
  onInterval: (minutes: number) => void
}) {
  return (
    <>
      <tr>
        <td>
          <button className="linklike" onClick={onExpand}>
            {open ? '▾' : '▸'} {l.name}
          </button>
          {l.last_error && <div className="list-err">⚠ {l.last_error}</div>}
        </td>
        <td>
          <span className="badge src">{l.source}</span>
        </td>
        <td>{l.category}</td>
        <td>{l.rule_count.toLocaleString()}</td>
        <td className="muted" style={{ textAlign: 'left' }}>
          {l.source === 'url' ? ago(l.last_fetch) : ago(l.updated_at)}
        </td>
        <td>
          <label className="toggle">
            <input type="checkbox" checked={l.enabled} onChange={onToggle} />
            <span className="track">
              <span className="thumb" />
            </span>
          </label>
        </td>
        <td>
          <div className="actions">
            {l.source === 'url' && (
              <button className="btn ghost" onClick={onRefresh}>
                ↻ Refresh
              </button>
            )}
            <button className="del" onClick={onDelete}>
              ✕
            </button>
          </div>
        </td>
      </tr>
      {open && (
        <tr className="expand">
          <td colSpan={7}>
            {l.source === 'url' && (
              <div className="row" style={{ marginBottom: 10 }}>
                <span className="muted" style={{ wordBreak: 'break-all' }}>
                  {l.url}
                </span>
                <span className="muted">· refresh:</span>
                <select value={Math.round(l.interval_sec / 60)} onChange={(e) => onInterval(Number(e.target.value))}>
                  <option value={0}>manual</option>
                  <option value={15}>15m</option>
                  <option value={60}>1h</option>
                  <option value={360}>6h</option>
                  <option value={1440}>1d</option>
                </select>
              </div>
            )}
            <div className="rule-grid">
              {rules.map((r) => (
                <span key={r.id} className={`rule-chip ${r.action}`}>
                  {r.action === 'allow' ? '✓ ' : ''}
                  {r.domain}
                </span>
              ))}
              {rules.length === 0 && <span className="muted">No rules in this list</span>}
            </div>
          </td>
        </tr>
      )}
    </>
  )
}
