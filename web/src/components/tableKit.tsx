import { useMemo, useState, type ReactNode } from 'react'
import Spinner from './Spinner'
import { RANGES } from './filters'

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

// Sortable is the part of a table Th needs: useTable's result, or a server-side
// table's own sort state ({ sortKey, desc, sort }).
export type Sortable = Pick<Table<unknown>, 'sortKey' | 'desc' | 'sort'>

// Th renders a sortable header cell with the active column's direction arrow.
export function Th({ table, col, children, className }: { table: Sortable; col: string; children: ReactNode; className?: string }) {
  const on = table.sortKey === col
  const arrow = on ? (table.desc ? ' ↓' : ' ↑') : ''
  return (
    <th
      className={`sortable${on ? ' sorted' : ''}${className ? ` ${className}` : ''}`}
      aria-sort={on ? (table.desc ? 'descending' : 'ascending') : undefined}
      onClick={() => table.sort(col)}
    >
      {children}
      {arrow}
    </th>
  )
}

// Pager renders the standard "Showing 1–25 of N items · Previous/Next" bar.
// Hidden when everything fits on one page and there is nothing to page through.
export function Pager<T>({ table, unit = 'items' }: { table: Table<T>; unit?: string }) {
  if (table.total <= PAGE_SIZE) return null
  const from = table.page * PAGE_SIZE + 1
  const to = Math.min(table.total, (table.page + 1) * PAGE_SIZE)
  return (
    <div className="pager">
      <span>
        Showing {from.toLocaleString()}–{to.toLocaleString()} of {table.total.toLocaleString()} {unit}
      </span>
      <div className="spacer" />
      <button className="btn sm" disabled={table.page <= 0} onClick={() => table.setPage(Math.max(0, table.page - 1))}>
        Previous
      </button>
      <button className="btn sm" disabled={table.page >= table.lastPage} onClick={() => table.setPage(Math.min(table.lastPage, table.page + 1))}>
        Next
      </button>
    </div>
  )
}

// TableStatusRow is the last row of every table body: it tells "not loaded
// yet" apart from "loaded and empty". While `loading` (no successful response
// yet for what the table shows) it renders a spinner row when the table has
// nothing else to show, or nothing when the request failed (`error` — the page
// already shows the error, and an empty-state message next to it would read as
// lost configuration). Once loaded it renders `children` as the usual muted
// empty message, only when `empty`. Errors after a successful load (a failed
// refresh or action) never hide the empty message of loaded data.
export function TableStatusRow({
  loading,
  error,
  empty,
  colSpan,
  children,
}: {
  loading: boolean
  error?: unknown
  empty: boolean
  colSpan?: number
  children: ReactNode
}) {
  if (loading) {
    if (error || !empty) return null
    return (
      <tr>
        <td colSpan={colSpan}>
          <Spinner label="Loading…" />
        </td>
      </tr>
    )
  }
  if (!empty) return null
  return (
    <tr>
      <td colSpan={colSpan} className="muted">
        {children}
      </td>
    </tr>
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

// fmtMs renders a latency: two decimals under 1 ms (so 0.04 ms doesn't read as
// "0 ms"), one under 10 ms, whole milliseconds above.
export function fmtMs(ms: number | null | undefined): string {
  if (ms == null || !Number.isFinite(ms)) return '—'
  if (ms < 1) return `${ms.toFixed(2)} ms`
  if (ms < 10) return `${ms.toFixed(1)} ms`
  return `${Math.round(ms).toLocaleString()} ms`
}

// fmtWhen splits a timestamp into the time of day and, when it isn't today, a
// short date ("5 Oct") — so multi-day windows don't show bare times.
export function fmtWhen(ts: number): { time: string; date: string; full: string } {
  const d = new Date(ts)
  const now = new Date()
  const today = d.toDateString() === now.toDateString()
  return {
    time: d.toLocaleTimeString(undefined, { hour: '2-digit', minute: '2-digit', second: '2-digit' }),
    date: today ? '' : d.toLocaleDateString(undefined, { day: 'numeric', month: 'short', year: d.getFullYear() === now.getFullYear() ? undefined : 'numeric' }),
    full: d.toLocaleString(),
  }
}

// windowLabel names a time window the way the window picker shows it ("24h").
export const windowLabel = (hours: number) => RANGES.find((r) => r.hours === hours)?.label ?? `${hours}h`

// WindowPicker is the time-window control of a page header: a segmented control
// on wide screens, a compact select on phones.
export function WindowPicker({ hours, onChange }: { hours: number; onChange: (h: number) => void }) {
  return (
    <>
      <div className="seg hide-sm" role="group" aria-label="Time window">
        {RANGES.map((r) => (
          <button key={r.hours} className={hours === r.hours ? 'on' : ''} aria-pressed={hours === r.hours} onClick={() => onChange(r.hours)}>
            {r.label}
          </button>
        ))}
      </div>
      <select className="show-sm" aria-label="Time window" value={hours} onChange={(e) => onChange(Number(e.target.value))} style={{ width: 'auto' }}>
        {RANGES.map((r) => (
          <option key={r.hours} value={r.hours}>
            Last {r.label}
          </option>
        ))}
      </select>
    </>
  )
}

// SearchBox is the search field of a list toolbar, with its magnifier icon.
export function SearchBox({
  value,
  onChange,
  placeholder,
  maxWidth = 420,
}: {
  value: string
  onChange: (v: string) => void
  placeholder: string
  maxWidth?: number
}) {
  return (
    <label style={{ position: 'relative', flex: '1 1 220px', minWidth: 0, maxWidth, display: 'block' }}>
      <svg
        viewBox="0 0 24 24"
        aria-hidden="true"
        style={{ position: 'absolute', left: 11, top: '50%', transform: 'translateY(-50%)', width: 15, height: 15, stroke: 'var(--faint)', fill: 'none', strokeWidth: 2, pointerEvents: 'none' }}
      >
        <circle cx="11" cy="11" r="7" />
        <path d="M20 20l-3.5-3.5" />
      </svg>
      <input
        type="search"
        aria-label={placeholder}
        placeholder={placeholder}
        value={value}
        onChange={(e) => onChange(e.target.value)}
        style={{ paddingLeft: 33 }}
      />
    </label>
  )
}
