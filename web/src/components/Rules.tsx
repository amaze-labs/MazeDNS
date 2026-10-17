import { useMemo, useState, type FormEvent } from 'react'
import { api, type Rule } from '../api'
import { useTable, Th, Pager, TableStatusRow, type SortAccessors } from './tableKit'

const CATEGORIES: { value: string; label: string }[] = [
  { value: 'custom', label: 'Custom' },
  { value: 'ads', label: 'Ads' },
  { value: 'trackers', label: 'Trackers' },
  { value: 'malware', label: 'Malware' },
  { value: 'phishing', label: 'Phishing' },
  { value: 'not-found', label: 'Not found (NXDOMAIN)' },
]
const catLabel = (c: string) => CATEGORIES.find((x) => x.value === c)?.label ?? c

const COLS: SortAccessors<Rule> = {
  action: (r) => r.action,
  domain: (r) => r.domain,
  category: (r) => r.category,
  added: (r) => r.updated_at,
}

type Filter = 'all' | 'deny' | 'allow'

const fmtDate = (unixSec: number) =>
  unixSec ? new Date(unixSec * 1000).toLocaleDateString(undefined, { day: 'numeric', month: 'short', year: 'numeric' }) : '—'

// Rules is the operator's own allow/block list: a quick-add row on top, then the
// searchable table. The page (Filtering) owns the rule data.
export default function Rules({
  rules,
  loaded,
  loadErr,
  reload,
  canEdit,
}: {
  rules: Rule[]
  loaded: boolean
  loadErr: string
  reload: () => Promise<void> | void
  canEdit: boolean
}) {
  const [action, setAction] = useState<'deny' | 'allow'>('deny')
  const [domain, setDomain] = useState('')
  const [category, setCategory] = useState('custom')
  const [saving, setSaving] = useState(false)
  const [err, setErr] = useState('')
  const [busy, setBusy] = useState<number | null>(null)
  const [q, setQ] = useState('')
  const [filter, setFilter] = useState<Filter>('all')

  const add = async (e: FormEvent) => {
    e.preventDefault()
    if (!domain.trim()) return
    setSaving(true)
    try {
      await api.addRule(action, domain.trim(), action === 'allow' ? 'custom' : category)
      setDomain('')
      setErr('')
      await reload()
    } catch (e: any) {
      setErr(e.message)
    } finally {
      setSaving(false)
    }
  }

  const del = async (r: Rule) => {
    setBusy(r.id)
    try {
      await api.deleteRule(r.id)
      setErr('')
      await reload()
    } catch (e: any) {
      setErr(`Could not remove ${r.domain}: ${e.message}`)
    } finally {
      setBusy(null)
    }
  }

  const nBlock = rules.filter((r) => r.action === 'deny').length
  const nAllow = rules.length - nBlock
  const shown = useMemo(() => {
    const s = q.trim().toLowerCase()
    return rules.filter((r) => (filter === 'all' || r.action === filter) && (!s || r.domain.toLowerCase().includes(s)))
  }, [rules, q, filter])
  const table = useTable(shown, COLS, 'domain')
  const cols = canEdit ? 5 : 4

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
      {loadErr && loaded && <div className="error">Could not refresh the rules: {loadErr}</div>}

      <section className="card flush rules-card">
        {canEdit && (
          <>
            <form className="quickadd" onSubmit={add}>
              <div className="seg" role="group" aria-label="Rule effect">
                <button type="button" className={action === 'deny' ? 'on' : ''} aria-pressed={action === 'deny'} onClick={() => setAction('deny')}>
                  Block
                </button>
                <button type="button" className={action === 'allow' ? 'on' : ''} aria-pressed={action === 'allow'} onClick={() => setAction('allow')}>
                  Allow
                </button>
              </div>
              <input
                className="mono qa-domain"
                placeholder="example.com, *.example.com or ||example.com^"
                value={domain}
                onChange={(e) => setDomain(e.target.value)}
                aria-label="Domain"
              />
              {action === 'deny' ? (
                <select className="qa-cat" value={category} onChange={(e) => setCategory(e.target.value)} aria-label="Category">
                  {CATEGORIES.map((c) => (
                    <option key={c.value} value={c.value}>
                      {c.label}
                    </option>
                  ))}
                </select>
              ) : (
                <span className="qa-cat" />
              )}
              <button type="submit" className="btn primary" disabled={saving || !domain.trim()}>
                {saving ? 'Adding…' : 'Add rule'}
              </button>
            </form>
            <p className="qa-hint">
              Allow rules win over every blocklist. A rule on <code>example.com</code> also covers its subdomains. Rules apply to every
              client.
            </p>
          </>
        )}

        <div className="toolbar rules-toolbar">
          <input
            type="search"
            className="search grow"
            placeholder="Search rules"
            value={q}
            onChange={(e) => setQ(e.target.value)}
            aria-label="Search rules"
          />
          <div className="row chips">
            <button className={`chip${filter === 'all' ? ' on' : ''}`} onClick={() => setFilter('all')}>
              <b>All</b> {rules.length.toLocaleString()}
            </button>
            <button className={`chip${filter === 'deny' ? ' on' : ''}`} onClick={() => setFilter('deny')}>
              Block {nBlock.toLocaleString()}
            </button>
            <button className={`chip${filter === 'allow' ? ' on' : ''}`} onClick={() => setFilter('allow')}>
              Allow {nAllow.toLocaleString()}
            </button>
          </div>
        </div>

        <div className="table-scroll">
          <table className="stackable rules-table">
            <thead>
              <tr>
                <Th table={table} col="domain">Rule</Th>
                <Th table={table} col="action">Effect</Th>
                <Th table={table} col="category" className="hide-sm">Category</Th>
                <Th table={table} col="added" className="hide-sm">Added</Th>
                {canEdit && <th aria-label="Actions" />}
              </tr>
            </thead>
            <tbody>
              {table.rows.map((r) => (
                <tr key={r.id}>
                  <td className="lead">
                    <span className="domain">{r.domain}</span>
                  </td>
                  <td className="lead-r">
                    <span className={`tag ${r.action === 'deny' ? 'block' : 'ok'}`}>{r.action === 'deny' ? 'Block' : 'Allow'}</span>
                  </td>
                  <td className="cat">{r.action === 'deny' ? catLabel(r.category) : <span className="faint">—</span>}</td>
                  <td className="muted nowrap added">{fmtDate(r.updated_at)}</td>
                  {canEdit && (
                    <td className="actions">
                      <button className="btn sm danger" onClick={() => del(r)} disabled={busy === r.id} aria-label={`Remove ${r.domain}`}>
                        {busy === r.id ? 'Removing…' : 'Remove'}
                      </button>
                    </td>
                  )}
                </tr>
              ))}
              <TableStatusRow loading={!loaded} error={loadErr} empty={table.rows.length === 0} colSpan={cols}>
                {rules.length === 0
                  ? canEdit
                    ? 'No rules yet. Add a domain above to block or allow it everywhere.'
                    : 'No rules yet.'
                  : 'No rules match.'}
              </TableStatusRow>
            </tbody>
          </table>
        </div>
        {!loaded && loadErr && <div className="error inset">Could not load the rules: {loadErr}</div>}
        <Pager table={table} unit="rules" />
      </section>
    </>
  )
}
