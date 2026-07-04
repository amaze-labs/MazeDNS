import { useMemo, useState, type ReactNode } from 'react'

// tableKit standardizes every client-side table in the app: clickable header
// sorting (click again to flip) and pagination capped at PAGE_SIZE rows per
// page, with the same pager UI the Requests log uses. Server-side tables
// (Requests, AI verdicts) implement the same interaction against their APIs and
// share PAGE_SIZE.
export const PAGE_SIZE = 25

// A column's sort accessor: extracts the comparable value for a row. Numbers
// compare numerically, everything else as case-insensitive strings. Define the
// accessor map at module level so its identity is stable.
export type SortAccessors<T> = Record<string, (row: T) => string | number>

export interface Table<T> {
  rows: T[] // current page, sorted
  sortKey: string
  desc: boolean
  sort: (key: string) => void
  page: number
  lastPage: number
  total: number
  setPage: (p: number) => void
}

// useTable sorts + paginates rows client-side. `accessors` maps a column key to
// its sortable value; `defaultKey` picks the initial column (desc by default
// only for numeric-feeling columns — pass defaultDesc).
export function useTable<T>(rows: T[], accessors: SortAccessors<T>, defaultKey: string, defaultDesc = false): Table<T> {
  const [sortKey, setSortKey] = useState(defaultKey)
  const [desc, setDesc] = useState(defaultDesc)
  const [page, setPage] = useState(0)

  const sorted = useMemo(() => {
    const acc = accessors[sortKey]
    if (!acc) return rows
    return [...rows].sort((a, b) => {
      const va = acc(a)
      const vb = acc(b)
      const cmp =
        typeof va === 'number' && typeof vb === 'number'
          ? va - vb
          : String(va).localeCompare(String(vb), undefined, { sensitivity: 'base' })
      return desc ? -cmp : cmp
    })
    // accessors is a module-level constant per table; exclude it from deps.
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [rows, sortKey, desc])

  const lastPage = Math.max(0, Math.ceil(sorted.length / PAGE_SIZE) - 1)
  const cur = Math.min(page, lastPage)
  const pageRows = useMemo(() => sorted.slice(cur * PAGE_SIZE, (cur + 1) * PAGE_SIZE), [sorted, cur])

  const sort = (key: string) => {
    if (key === sortKey) {
      setDesc((d) => !d)
    } else {
      setSortKey(key)
      setDesc(false)
    }
    setPage(0)
  }

  return { rows: pageRows, sortKey, desc, sort, page: cur, lastPage, total: sorted.length, setPage }
}

// Th renders a sortable header cell with the active column's direction arrow.
export function Th<T>({ table, col, children, className }: { table: Table<T>; col: string; children: ReactNode; className?: string }) {
  const arrow = table.sortKey === col ? (table.desc ? ' ↓' : ' ↑') : ''
  return (
    <th className={`sortable ${className || ''}`} onClick={() => table.sort(col)}>
      {children}
      {arrow}
    </th>
  )
}

// Pager renders the standard "N items · page X of Y · Prev/Next" bar. Hidden
// when everything fits on one page and there is nothing to page through.
export function Pager<T>({ table, unit = 'items' }: { table: Table<T>; unit?: string }) {
  if (table.total <= PAGE_SIZE) return null
  return (
    <div className="pager">
      <span className="muted">
        {table.total.toLocaleString()} {unit} · page {table.page + 1} of {table.lastPage + 1}
      </span>
      <div className="spacer" />
      <button className="btn" disabled={table.page <= 0} onClick={() => table.setPage(Math.max(0, table.page - 1))}>
        ‹ Prev
      </button>
      <button className="btn" disabled={table.page >= table.lastPage} onClick={() => table.setPage(Math.min(table.lastPage, table.page + 1))}>
        Next ›
      </button>
    </div>
  )
}

// timeAgo renders a compact relative time ("just now", "5m ago", "2d ago") from
// a unix-milliseconds timestamp; "—" when absent.
export function timeAgo(ms: number): string {
  if (!ms) return '—'
  const s = Math.max(0, Math.floor((Date.now() - ms) / 1000))
  if (s < 10) return 'just now'
  if (s < 60) return `${s}s ago`
  const m = Math.floor(s / 60)
  if (m < 60) return `${m}m ago`
  const h = Math.floor(m / 60)
  if (h < 48) return `${h}h ago`
  return `${Math.floor(h / 24)}d ago`
}
