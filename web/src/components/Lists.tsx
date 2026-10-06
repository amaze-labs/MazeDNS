import { useEffect, useMemo, useRef, useState, type FormEvent } from 'react'
import { api, type List, type Rule } from '../api'
import Spinner from './Spinner'

const CATEGORIES: { value: string; label: string }[] = [
  { value: 'ads', label: 'Ads' },
  { value: 'trackers', label: 'Trackers' },
  { value: 'malware', label: 'Malware' },
  { value: 'phishing', label: 'Phishing' },
  { value: 'custom', label: 'Custom' },
  { value: 'not-found', label: 'Not found (NXDOMAIN)' },
]
const catLabel = (c: string) => CATEGORIES.find((x) => x.value === c)?.label ?? c

const INTERVALS = [
  { minutes: 0, label: 'Manually only' },
  { minutes: 15, label: 'Every 15 minutes' },
  { minutes: 60, label: 'Every hour' },
  { minutes: 360, label: 'Every 6 hours' },
  { minutes: 1440, label: 'Every day' },
]

type SortKey = 'name' | 'rules' | 'updated'
type AddMode = 'url' | 'file' | 'paste'

// Rules shown per step when a list is expanded. Lists can hold 100k+ entries;
// the API returns them all, so render a window and grow it on demand.
const RULE_STEP = 500

function ago(unixSec: number): string {
  if (!unixSec) return 'never'
  const s = Math.max(0, Math.floor(Date.now() / 1000 - unixSec))
  if (s < 60) return 'just now'
  if (s < 3600) return `${Math.floor(s / 60)} min ago`
  if (s < 86400) return `${Math.floor(s / 3600)} h ago`
  return `${Math.floor(s / 86400)} d ago`
}
const lastUpdate = (l: List) => (l.source === 'url' ? l.last_fetch : l.updated_at)

// Lists manages the blocklists: one row per list (on/off, source, size, health)
// next to the form that adds a list from a URL, a file or pasted text. The page
// (Filtering) owns the list data and polls it.
export default function Lists({
  lists,
  loaded,
  loadErr,
  reload,
  canEdit,
}: {
  lists: List[]
  loaded: boolean
  loadErr: string
  reload: () => Promise<void> | void
  canEdit: boolean
}) {
  // Action feedback stays until the next action or until dismissed — polling
  // never clears it.
  const [err, setErr] = useState('')
  const [msg, setMsg] = useState('')
  const [busy, setBusy] = useState<number | null>(null)
  const [menu, setMenu] = useState<number | null>(null)
  const [sort, setSort] = useState<SortKey>('name')

  // Expanded list (rule viewer).
  const [openId, setOpenId] = useState<number | null>(null)
  const [openRules, setOpenRules] = useState<Rule[] | null>(null)
  const [ruleErr, setRuleErr] = useState('')
  const openSeq = useRef(0)

  const report = (ok: string, bad = '') => {
    setMsg(ok)
    setErr(bad)
  }
  const run = async (id: number | null, fn: () => Promise<void>) => {
    setBusy(id)
    setMenu(null)
    try {
      await fn()
    } catch (e: any) {
      report('', e.message)
    } finally {
      setBusy(null)
      reload()
    }
  }

  const toggle = (l: List) =>
    run(l.id, async () => {
      await api.updateList(l.id, { enabled: !l.enabled })
      report(`${l.enabled ? 'Turned off' : 'Turned on'} “${l.name}”.`)
    })
  const refresh = (l: List) =>
    run(l.id, async () => {
      report(`Refreshing “${l.name}”…`)
      const u = await api.refreshList(l.id)
      if (u.last_error) report('', `“${l.name}” could not be refreshed: ${u.last_error}`)
      else report(`“${l.name}” refreshed: ${u.rule_count.toLocaleString()} rules.`)
      if (openId === l.id) loadRules(l.id)
    })
  const del = (l: List) => {
    setMenu(null)
    if (!window.confirm(`Remove the list “${l.name}” and all of its rules?`)) return
    run(l.id, async () => {
      await api.deleteList(l.id)
      if (openId === l.id) setOpenId(null)
      report(`Removed “${l.name}”.`)
    })
  }
  const setListInterval = (l: List, minutes: number) =>
    run(l.id, async () => {
      await api.updateList(l.id, { interval_minutes: minutes })
      report(`“${l.name}” now refreshes ${INTERVALS.find((i) => i.minutes === minutes)?.label.toLowerCase() ?? `every ${minutes} min`}.`)
    })

  const loadRules = (id: number) => {
    const seq = ++openSeq.current
    setOpenRules(null)
    setRuleErr('')
    api
      .listRules(id)
      .then((rs) => seq === openSeq.current && setOpenRules(rs))
      .catch((e) => seq === openSeq.current && setRuleErr(e.message))
  }
  const expand = (l: List) => {
    setMenu(null)
    if (openId === l.id) {
      openSeq.current++
      setOpenId(null)
      return
    }
    setOpenId(l.id)
    loadRules(l.id)
  }

  const rows = useMemo(() => {
    const out = [...lists]
    out.sort((a, b) =>
      sort === 'rules'
        ? b.rule_count - a.rule_count
        : sort === 'updated'
          ? lastUpdate(b) - lastUpdate(a)
          : a.name.localeCompare(b.name, undefined, { sensitivity: 'base' }),
    )
    return out
  }, [lists, sort])

  return (
    <>
      {err && (
        <div className="error" role="alert">
          <span className="grow">{err}</span>
          <button className="btn sm quiet" onClick={() => setErr('')}>
            Dismiss
          </button>
        </div>
      )}
      {msg && (
        <div className="ok-msg" role="status">
          <span className="grow">{msg}</span>
          <button className="btn sm quiet" onClick={() => setMsg('')}>
            Dismiss
          </button>
        </div>
      )}
      {loadErr && loaded && <div className="error">Could not refresh the lists: {loadErr}</div>}

      <div className={canEdit ? 'cols lists-cols' : ''}>
        <section className="card flush">
          <div className="card-head">
            <div className="grow">
              <h2>Lists</h2>
              <p className="sub">Domains on enabled lists are blocked for every client. Lists from a URL refresh on their own schedule.</p>
            </div>
            {lists.length > 1 && (
              <label className="sort-by">
                <span className="muted small">Sort</span>
                <select value={sort} onChange={(e) => setSort(e.target.value as SortKey)} aria-label="Sort lists">
                  <option value="name">Name</option>
                  <option value="rules">Size</option>
                  <option value="updated">Last update</option>
                </select>
              </label>
            )}
          </div>

          <div className="rowlist lists">
            {!loaded ? (
              loadErr ? (
                <div className="error list-load-err">Could not load the lists: {loadErr}</div>
              ) : (
                <div className="rowitem">
                  <Spinner label="Loading lists…" />
                </div>
              )
            ) : rows.length === 0 ? (
              <div className="empty">
                No lists yet.{canEdit ? ' Add one from a URL, a file or pasted text.' : ''}
              </div>
            ) : (
              rows.map((l) => (
                <ListRow
                  key={l.id}
                  l={l}
                  canEdit={canEdit}
                  busy={busy === l.id}
                  open={openId === l.id}
                  menuOpen={menu === l.id}
                  onMenu={() => setMenu((m) => (m === l.id ? null : l.id))}
                  onCloseMenu={() => setMenu(null)}
                  onExpand={() => expand(l)}
                  onToggle={() => toggle(l)}
                  onRefresh={() => refresh(l)}
                  onDelete={() => del(l)}
                >
                  {openId === l.id && (
                    <RuleViewer
                      l={l}
                      rules={openRules}
                      error={ruleErr}
                      canEdit={canEdit}
                      onInterval={(m) => setListInterval(l, m)}
                    />
                  )}
                </ListRow>
              ))
            )}
          </div>
          <p className="config-note faint small">
            Blocklist files set in the server config (<code>filter.blocklist_files</code> or <code>MAZEDNS_BLOCKLIST_FILES</code>) are
            applied too, but aren’t shown here.
          </p>
        </section>

        {canEdit && <AddList onDone={report} reload={reload} />}
      </div>
    </>
  )
}

function ListRow({
  l,
  canEdit,
  busy,
  open,
  menuOpen,
  onMenu,
  onCloseMenu,
  onExpand,
  onToggle,
  onRefresh,
  onDelete,
  children,
}: {
  l: List
  canEdit: boolean
  busy: boolean
  open: boolean
  menuOpen: boolean
  onMenu: () => void
  onCloseMenu: () => void
  onExpand: () => void
  onToggle: () => void
  onRefresh: () => void
  onDelete: () => void
  children?: React.ReactNode
}) {
  const stale = !!l.last_error
  const source =
    l.source === 'url' ? l.url : l.source === 'file' ? `Imported from ${l.name}` : l.source === 'paste' ? 'Pasted list' : l.source
  return (
    <div className={`rowitem list${l.enabled ? '' : ' off'}${open ? ' open' : ''}`}>
      {canEdit ? (
        <button
          className={`switch${l.enabled ? ' on' : ''}`}
          role="switch"
          aria-checked={l.enabled}
          aria-label={`${l.enabled ? 'Turn off' : 'Turn on'} ${l.name}`}
          onClick={onToggle}
          disabled={busy}
        />
      ) : (
        <span className={`switch${l.enabled ? ' on' : ''} ro`} role="img" aria-label={l.enabled ? 'On' : 'Off'} />
      )}
      <div className="body">
        <div className="title">
          <button className="name" onClick={onExpand} aria-expanded={open}>
            {l.name}
          </button>
          <span className="tag">{catLabel(l.category)}</span>
          {!l.enabled && <span className="tag">Off</span>}
        </div>
        {stale ? (
          <span className="err">
            Last refresh failed: {l.last_error}
            {l.rule_count > 0 ? ' Still using the previous copy.' : ''}
          </span>
        ) : (
          <span className={`src${l.source === 'url' ? ' mono' : ''}`} title={source}>
            {source}
          </span>
        )}
      </div>
      <div className="count">
        {l.rule_count.toLocaleString()}
        {stale ? (
          <small className="bad-text">stale</small>
        ) : (
          <small>
            {l.source === 'url' ? 'updated' : 'imported'} {ago(lastUpdate(l))}
          </small>
        )}
      </div>
      <div className="row-actions">
        {busy ? (
          <Spinner />
        ) : (
          <>
            <button className="btn sm quiet more" aria-haspopup="menu" aria-expanded={menuOpen} aria-label={`Actions for ${l.name}`} onClick={onMenu}>
              ⋯
            </button>
            {menuOpen && (
              <>
                <div className="menu-backdrop" onClick={onCloseMenu} />
                <div className="menu" role="menu">
                  <button role="menuitem" onClick={onExpand}>
                    {open ? 'Hide rules' : 'Show rules'}
                  </button>
                  {canEdit && l.source === 'url' && (
                    <button role="menuitem" onClick={onRefresh}>
                      Refresh now
                    </button>
                  )}
                  {canEdit && (
                    <button role="menuitem" onClick={onToggle}>
                      {l.enabled ? 'Turn off' : 'Turn on'}
                    </button>
                  )}
                  {canEdit && (
                    <button role="menuitem" className="danger" onClick={onDelete}>
                      Remove list
                    </button>
                  )}
                </div>
              </>
            )}
          </>
        )}
      </div>
      {children && <div className="expand">{children}</div>}
    </div>
  )
}

// RuleViewer shows the rules of one list. The API returns the whole list (no
// paging yet), so only a window is rendered: RULE_STEP rules at first, more on
// request, and a filter that searches the full set.
function RuleViewer({
  l,
  rules,
  error,
  canEdit,
  onInterval,
}: {
  l: List
  rules: Rule[] | null
  error: string
  canEdit: boolean
  onInterval: (minutes: number) => void
}) {
  const [q, setQ] = useState('')
  const [shown, setShown] = useState(RULE_STEP)
  useEffect(() => setShown(RULE_STEP), [q, l.id])
  const filtered = useMemo(() => {
    if (!rules) return []
    const s = q.trim().toLowerCase()
    return s ? rules.filter((r) => r.domain.toLowerCase().includes(s)) : rules
  }, [rules, q])
  const intervalMin = Math.round(l.interval_sec / 60)

  return (
    <div className="viewer">
      {l.source === 'url' && (
        <div className="viewer-meta">
          <span className="mono wrap muted">{l.url}</span>
          {canEdit ? (
            <label className="interval">
              <span className="muted small">Refresh</span>
              <select value={intervalMin} onChange={(e) => onInterval(Number(e.target.value))}>
                {!INTERVALS.some((i) => i.minutes === intervalMin) && <option value={intervalMin}>Every {intervalMin} minutes</option>}
                {INTERVALS.map((i) => (
                  <option key={i.minutes} value={i.minutes}>
                    {i.label}
                  </option>
                ))}
              </select>
            </label>
          ) : (
            <span className="muted small">
              Refresh: {INTERVALS.find((i) => i.minutes === intervalMin)?.label.toLowerCase() ?? `every ${intervalMin} minutes`}
            </span>
          )}
        </div>
      )}
      {error ? (
        <div className="error">Could not load the rules: {error}</div>
      ) : rules === null ? (
        <Spinner label="Loading rules…" />
      ) : rules.length === 0 ? (
        <span className="muted">This list has no rules.</span>
      ) : (
        <>
          <div className="viewer-bar">
            <input
              type="search"
              className="search"
              placeholder={`Search ${rules.length.toLocaleString()} rules`}
              value={q}
              onChange={(e) => setQ(e.target.value)}
              aria-label="Search rules in this list"
            />
            <span className="muted small">
              {q.trim()
                ? `${filtered.length.toLocaleString()} match${filtered.length === 1 ? '' : 'es'}`
                : `Showing ${Math.min(shown, filtered.length).toLocaleString()} of ${filtered.length.toLocaleString()}`}
            </span>
          </div>
          <div className="rule-grid">
            {filtered.slice(0, shown).map((r) => (
              <span key={r.id} className={`domain rule${r.action === 'allow' ? ' allow' : ''}`} title={r.action === 'allow' ? 'Allow rule' : undefined}>
                {r.action === 'allow' ? '✓ ' : ''}
                {r.domain}
              </span>
            ))}
            {filtered.length === 0 && <span className="muted">No rules match.</span>}
          </div>
          {filtered.length > shown && (
            <div className="row">
              <button className="btn sm" onClick={() => setShown((n) => n + RULE_STEP)}>
                Show {Math.min(RULE_STEP, filtered.length - shown).toLocaleString()} more
              </button>
              <span className="muted small">{(filtered.length - shown).toLocaleString()} not shown — search to find a domain.</span>
            </div>
          )}
        </>
      )}
    </div>
  )
}

// AddList adds a blocklist from a URL (re-fetched on a schedule), from uploaded
// files (one list per file) or from pasted text.
function AddList({ onDone, reload }: { onDone: (ok: string, bad?: string) => void; reload: () => Promise<void> | void }) {
  const [mode, setMode] = useState<AddMode>('url')
  const [name, setName] = useState('')
  const [category, setCategory] = useState('ads')
  const [url, setUrl] = useState('')
  const [interval, setIntervalMin] = useState(1440)
  const [paste, setPaste] = useState('')
  const [saving, setSaving] = useState(false)
  const [drag, setDrag] = useState(false)
  const fileRef = useRef<HTMLInputElement>(null)

  const guard = async (fn: () => Promise<void>) => {
    setSaving(true)
    try {
      await fn()
    } catch (e: any) {
      onDone('', e.message)
    } finally {
      setSaving(false)
      reload()
    }
  }
  const nameFromUrl = (u: string) => {
    try {
      const p = new URL(u)
      return p.pathname.split('/').filter(Boolean).pop() || p.hostname
    } catch {
      return u
    }
  }

  const addUrl = (e: FormEvent) => {
    e.preventDefault()
    if (!url.trim()) return
    guard(async () => {
      const l = await api.addUrlList(name.trim() || nameFromUrl(url.trim()), url.trim(), category, interval)
      setName('')
      setUrl('')
      if (l.last_error) onDone('', `Added “${l.name}”, but the first fetch failed: ${l.last_error}`)
      else onDone(`Added “${l.name}” with ${l.rule_count.toLocaleString()} rules.`)
    })
  }
  const importPaste = (e: FormEvent) => {
    e.preventDefault()
    if (!name.trim() || !paste.trim()) return
    guard(async () => {
      const r = await api.importList(name.trim(), category, paste, 'paste')
      setName('')
      setPaste('')
      onDone(`Imported ${r.imported.toLocaleString()} rules into “${r.name}”.`)
    })
  }
  const importFiles = (files: FileList | File[]) => {
    const fs = Array.from(files)
    if (!fs.length) return
    guard(async () => {
      try {
        let total = 0
        for (const f of fs) {
          const r = await api.importList(f.name, category, await f.text(), 'file')
          total += r.imported
        }
        onDone(`Imported ${total.toLocaleString()} rules from ${fs.length} file${fs.length > 1 ? 's' : ''}.`)
      } finally {
        if (fileRef.current) fileRef.current.value = ''
      }
    })
  }

  const categoryField = (
    <label className="field">
      <span>Category</span>
      <select value={category} onChange={(e) => setCategory(e.target.value)}>
        {CATEGORIES.map((c) => (
          <option key={c.value} value={c.value}>
            {c.label}
          </option>
        ))}
      </select>
      <small>Shown next to blocked queries so you know why.</small>
    </label>
  )

  return (
    <section className="card add-list">
      <h2>Add a list</h2>
      <p className="sub">AdGuard, Pi-hole and hosts formats all work.</p>
      <div className="seg" role="tablist" aria-label="How to add the list">
        <button role="tab" aria-selected={mode === 'url'} className={mode === 'url' ? 'on' : ''} onClick={() => setMode('url')}>
          From a URL
        </button>
        <button role="tab" aria-selected={mode === 'file'} className={mode === 'file' ? 'on' : ''} onClick={() => setMode('file')}>
          Upload a file
        </button>
        <button role="tab" aria-selected={mode === 'paste'} className={mode === 'paste' ? 'on' : ''} onClick={() => setMode('paste')}>
          Paste
        </button>
      </div>

      {mode === 'url' && (
        <form className="addform" onSubmit={addUrl}>
          <label className="field">
            <span>List URL</span>
            <input
              type="url"
              className="mono"
              placeholder="https://example.com/blocklist.txt"
              value={url}
              onChange={(e) => setUrl(e.target.value)}
              required
            />
          </label>
          <div className="pair">
            <label className="field">
              <span>Name</span>
              <input placeholder="Optional" value={name} onChange={(e) => setName(e.target.value)} />
            </label>
            <label className="field">
              <span>Refresh</span>
              <select value={interval} onChange={(e) => setIntervalMin(Number(e.target.value))}>
                {INTERVALS.map((i) => (
                  <option key={i.minutes} value={i.minutes}>
                    {i.label}
                  </option>
                ))}
              </select>
            </label>
          </div>
          {categoryField}
          <div>
            <button type="submit" className="btn primary" disabled={saving || !url.trim()}>
              {saving ? 'Adding…' : 'Add list'}
            </button>
          </div>
        </form>
      )}

      {mode === 'file' && (
        <div className="addform">
          {categoryField}
          <div
            className={`drop${drag ? ' over' : ''}`}
            onDragOver={(e) => {
              e.preventDefault()
              setDrag(true)
            }}
            onDragLeave={() => setDrag(false)}
            onDrop={(e) => {
              e.preventDefault()
              setDrag(false)
              importFiles(e.dataTransfer.files)
            }}
          >
            <b>Drop list files here</b>
            <span className="muted small">Each file becomes its own list, named after the file.</span>
            <button type="button" className="btn" onClick={() => fileRef.current?.click()} disabled={saving}>
              {saving ? 'Importing…' : 'Choose files'}
            </button>
            <input
              ref={fileRef}
              type="file"
              accept=".list,.txt,.hosts,text/plain"
              multiple
              hidden
              onChange={(e) => e.target.files?.length && importFiles(e.target.files)}
            />
          </div>
        </div>
      )}

      {mode === 'paste' && (
        <form className="addform" onSubmit={importPaste}>
          <label className="field">
            <span>Name</span>
            <input placeholder="e.g. Smart TV telemetry" value={name} onChange={(e) => setName(e.target.value)} required />
          </label>
          {categoryField}
          <label className="field">
            <span>Rules</span>
            <textarea
              rows={6}
              placeholder={'One per line, e.g.\n||ads.example.com^\n0.0.0.0 tracker.example.com'}
              value={paste}
              onChange={(e) => setPaste(e.target.value)}
            />
          </label>
          <div>
            <button type="submit" className="btn primary" disabled={saving || !name.trim() || !paste.trim()}>
              {saving ? 'Importing…' : 'Import list'}
            </button>
          </div>
        </form>
      )}
    </section>
  )
}
