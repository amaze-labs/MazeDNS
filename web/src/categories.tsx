import { useEffect, useState } from 'react'
import { api, type CategoryList, type CategorySource, type DomainCategory } from './api'

// Domain categories (social, shopping, adult, …): the list from /api/categories,
// loaded once and shared by every page; reloadCategories refreshes it after a
// change (blocked categories, an override).

let cached: CategoryList | null = null
let inflight: Promise<CategoryList> | null = null
const listeners = new Set<(l: CategoryList) => void>()

function load(): Promise<CategoryList> {
  if (!inflight) {
    inflight = api.categoryList().then(
      (l) => {
        cached = l
        listeners.forEach((f) => f(l))
        return l
      },
      (e) => {
        inflight = null
        throw e
      },
    )
  }
  return inflight
}

export function reloadCategories(): Promise<CategoryList> {
  inflight = null
  return load()
}

export function useCategories(): CategoryList | null {
  const [list, setList] = useState<CategoryList | null>(cached)
  useEffect(() => {
    listeners.add(setList)
    if (!cached) load().catch(() => {})
    return () => {
      listeners.delete(setList)
    }
  }, [])
  return list
}

// categoryLabel is a category's display name ("Chat & messaging"), or the id.
export function categoryLabel(list: CategoryList | null, id: string): string {
  return list?.categories.find((c) => c.id === id)?.label ?? id
}

const SECURITY = new Set(['ads', 'trackers', 'malware', 'phishing'])

// CategoryTag shows a category: security ones coral, "other" and "local" neutral, the rest
// blue — the colours the Queries page already uses for classifications.
export function CategoryTag({ id, list }: { id: string; list: CategoryList | null }) {
  if (!id) return <span className="muted">—</span>
  const tone = SECURITY.has(id) ? 'block' : id === 'other' || id === 'local' ? '' : 'info'
  return <span className={`tag ${tone}`}>{categoryLabel(list, id)}</span>
}

export const SOURCE_LABEL: Record<CategorySource, string> = {
  override: 'set by an administrator',
  classifier: 'the classifier blocks it',
  database: 'category database (UT1)',
  model: 'the language model',
  local: 'a name that only exists on your network',
  '': 'nothing knows this domain',
}

// CategoryBars ranks query volume by category: one bar per category, sized to
// the largest, with the count and its share of the total. A row opens the
// Queries page filtered to that category.
export function CategoryBars({
  rows,
  list,
  limit = 10,
  color = 'var(--fwd)',
  client = '',
}: {
  rows: { category: string; count: number; blocked?: number }[]
  list: CategoryList | null
  limit?: number
  color?: string
  client?: string // narrow the Queries link to one client
}) {
  const sorted = [...rows].filter((r) => r.count > 0).sort((a, b) => b.count - a.count)
  const total = sorted.reduce((n, r) => n + r.count, 0)
  const shown = sorted.slice(0, limit)
  const rest = sorted.slice(limit)
  const max = shown[0]?.count ?? 0
  const pct = (n: number) => (total ? Math.round((n / total) * 1000) / 10 : 0)
  const open = (category: string) => {
    const url = `/queries?content=${encodeURIComponent(category)}${client ? `&client=${encodeURIComponent(client)}` : ''}`
    window.history.pushState({}, '', url)
    window.dispatchEvent(new PopStateEvent('popstate'))
  }
  return (
    <ol className="cat-bars">
      {shown.map((r) => (
        <li key={r.category}>
          <button
            type="button"
            className="cat-row"
            onClick={() => open(r.category)}
            title={`${categoryLabel(list, r.category)}: ${r.count.toLocaleString()} queries (${pct(r.count)}%)${
              r.blocked ? `, ${r.blocked.toLocaleString()} blocked` : ''
            } — show them`}
          >
            <span className="nm">{categoryLabel(list, r.category)}</span>
            <span className="v">
              {r.count.toLocaleString()} <span className="faint">{pct(r.count)}%</span>
            </span>
            <span className="meter">
              <i style={{ ['--k' as string]: color, width: `${max ? (r.count / max) * 100 : 0}%` }} />
            </span>
          </button>
        </li>
      ))}
      {rest.length > 0 && (
        <li className="faint small cat-more">
          {rest.length} more ({pct(rest.reduce((n, r) => n + r.count, 0))}%)
        </li>
      )}
    </ol>
  )
}

// DomainCategoryEditor shows a domain's category and where it came from, and
// lets an administrator set it for the whole registered domain (or go back to
// automatic). An override wins over every automatic source, and also decides
// whether the domain is caught by a blocked category.
export function DomainCategoryEditor({ domain, canEdit }: { domain: string; canEdit: boolean }) {
  const list = useCategories()
  const [dc, setDc] = useState<DomainCategory | null>(null)
  const [err, setErr] = useState('')
  const [editing, setEditing] = useState(false)
  const [pick, setPick] = useState('')
  const [busy, setBusy] = useState(false)

  useEffect(() => {
    let alive = true
    setDc(null)
    setErr('')
    setEditing(false)
    api
      .domainCategory(domain)
      .then((r) => alive && setDc(r))
      .catch((e) => alive && setErr(e.message))
    return () => {
      alive = false
    }
  }, [domain])

  if (list && !list.enabled) return <span className="muted">Domain categories are turned off.</span>
  if (err) return <span className="muted">Couldn’t load the category: {err}</span>
  if (!dc) return <span className="muted">Loading…</span>

  const save = async (category: string | null) => {
    setBusy(true)
    setErr('')
    try {
      if (category === null) await api.clearCategoryOverride(dc.domain)
      else await api.setCategoryOverride(dc.domain, category)
      setDc(await api.domainCategory(domain))
      setEditing(false)
    } catch (e: any) {
      setErr(e.message)
    } finally {
      setBusy(false)
    }
  }

  if (editing) {
    return (
      <span className="cat-edit">
        <select aria-label={`Category of ${dc.domain}`} value={pick} onChange={(e) => setPick(e.target.value)} disabled={busy}>
          {(list?.categories ?? []).map((c) => (
            <option key={c.id} value={c.id}>
              {c.label}
            </option>
          ))}
        </select>
        <button type="button" className="btn sm primary" disabled={busy} onClick={() => save(pick)}>
          Save for all of {dc.domain}
        </button>
        {dc.source === 'override' && (
          <button type="button" className="btn sm" disabled={busy} onClick={() => save(null)}>
            Use automatic
          </button>
        )}
        <button type="button" className="btn sm quiet" disabled={busy} onClick={() => setEditing(false)}>
          Cancel
        </button>
      </span>
    )
  }
  return (
    <span className="cat-edit">
      <CategoryTag id={dc.category} list={list} />
      <small className="muted">
        {SOURCE_LABEL[dc.source]}
        {dc.override?.set_by ? ` (${dc.override.set_by})` : ''}
      </small>
      {canEdit && (
        <button
          type="button"
          className="btn sm quiet"
          onClick={() => {
            setPick(dc.category)
            setEditing(true)
          }}
        >
          Change
        </button>
      )}
    </span>
  )
}
