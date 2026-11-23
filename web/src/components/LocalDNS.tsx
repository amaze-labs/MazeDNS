import { useCallback, useEffect, useMemo, useState, type FormEvent } from 'react'
import { api, type Rewrite } from '../api'
import EditScopedModal from './EditScopedModal'
import TestQuery from './TestQuery'
import { Icon } from './icons'
import { relName, zoneFor } from './recordZones'
import ScopePicker, { ALL_SCOPE, scopeBadge, useIsAdmin, type Scope } from './ScopePicker'
import { useTable, Th, Pager, SearchBox, TableStatusRow, type SortAccessors } from './tableKit'
import { invalidateAllClientNames } from '../useClientNames'
import '../styles/local-dns.css'

const COLS: SortAccessors<Rewrite> = {
  domain: (r) => r.domain,
  value: (r) => `${r.rrtype} ${r.value}`,
  scope: (r) => `${r.scope_type || 'all'} ${(r.scope_values ?? []).join(',')}`,
}

// The page's search matches any part of what a row shows: name, type, answer,
// scope targets, and the integration that owns it.
const rewriteMatches = (r: Rewrite, q: string) =>
  [r.domain, r.rrtype, r.value, r.source, ...(r.scope_values ?? [])].some((f) => f.toLowerCase().includes(q))

const plural = (n: number, one: string, many: string) => `${n.toLocaleString()} ${n === 1 ? one : many}`

const errMsg = (e: unknown) => (e instanceof Error ? e.message : String(e)) || 'Request failed'

export default function LocalDNS() {
  const admin = useIsAdmin() === true
  const [testing, setTesting] = useState(false)
  const [rows, setRows] = useState<Rewrite[]>([])
  const [loaded, setLoaded] = useState(false)
  const [domain, setDomain] = useState('')
  const [rrtype, setRrtype] = useState('A')
  const [value, setValue] = useState('')
  const [scope, setScope] = useState<Scope>(ALL_SCOPE)
  const [adding, setAdding] = useState(false)
  const [err, setErr] = useState('')

  const [search, setSearch] = useState('')
  const [view, setView] = useState<View>(() => (readStore(VIEW_KEY) === 'list' ? 'list' : 'grouped'))
  const pickView = (v: View) => {
    setView(v)
    writeStore(VIEW_KEY, v)
  }

  const [nodes, setNodes] = useState<string[] | null>(null)
  const [sites, setSites] = useState<string[] | null>(null)

  const [editing, setEditing] = useState<Rewrite | null>(null)
  const closeEdit = useCallback(() => setEditing(null), [])

  const load = () => {
    api
      .rewrites()
      .then((rs) => {
        setRows(rs)
        setLoaded(true)
      })
      .catch((e) => setErr(errMsg(e)))
  }
  useEffect(() => {
    load()
    // Cluster lists feed the scope pickers; on a standalone control plane the
    // calls fail and scoping simply collapses to "Everyone".
    api.clusterNodes().then((ns) => setNodes(ns.map((n) => n.name))).catch(() => {})
    api.clusterSites().then((ss) => setSites(ss.map((s) => s.name))).catch(() => {})
  }, [])

  const add = async (e: FormEvent) => {
    e.preventDefault()
    if (!domain.trim() || !value.trim() || adding) return
    setAdding(true)
    try {
      await api.addRewrite(domain.trim(), rrtype, value.trim(), scope.scope_type, scope.scope_values)
      setDomain('')
      setValue('')
      setScope(ALL_SCOPE)
      setErr('')
      invalidateAllClientNames()
      load()
    } catch (e) {
      setErr(errMsg(e))
    } finally {
      setAdding(false)
    }
  }

  const del = async (r: Rewrite) => {
    if (!window.confirm(`Delete the ${r.rrtype} record for ${r.domain}?`)) return
    try {
      await api.deleteRewrite(r.id)
      setErr('')
      invalidateAllClientNames()
      load()
    } catch (e) {
      setErr(errMsg(e))
    }
  }

  const toggle = async (r: Rewrite) => {
    try {
      await api.updateRewrite(r.id, r.value, !r.enabled, r.scope_type || 'all', r.scope_values ?? [])
      setErr('')
      // A disabled A/AAAA record no longer names its client.
      invalidateAllClientNames()
      load()
    } catch (e) {
      setErr(errMsg(e))
    }
  }

  const detach = async (r: Rewrite) => {
    if (
      !window.confirm(
        `Detach the ${r.rrtype} record for ${r.domain} from ${r.source}? It becomes a manual record you can edit or delete, and ${r.source} will report it as a conflict instead of updating it.`,
      )
    )
      return
    try {
      await api.detachRewrite(r.id)
      setErr('')
      load()
    } catch (e) {
      setErr(errMsg(e))
    }
  }

  const saveEdit = async (r: Rewrite, value: string, s: Scope) => {
    if (!value) throw new Error('Enter an answer')
    await api.updateRewrite(r.id, value, r.enabled, s.scope_type, s.scope_values)
    setEditing(null)
    invalidateAllClientNames()
    load()
  }

  // Manual records first; each integration that owns records gets its own
  // section below them. The search narrows every list at once.
  const q = search.trim().toLowerCase()
  const shown = q ? rows.filter((r) => rewriteMatches(r, q)) : rows
  const manualAll = rows.filter((r) => !r.source)
  const manual = shown.filter((r) => !r.source)
  const sources = [...new Set(rows.map((r) => r.source).filter(Boolean))].sort()
  // "3 of 40 records" while searching, "40 records" otherwise.
  const count = (n: number, of: number, one: string, many: string) =>
    q ? `${n.toLocaleString()} of ${plural(of, one, many)}` : plural(of, one, many)
  const matches = shown.length
  const known = (t?: string) => (t === 'nodes' ? nodes ?? undefined : t === 'sites' ? sites ?? undefined : undefined)
  // Zones come from every record, not just the matches, so a search never
  // moves a record to another group.
  const zones = useMemo(() => zoneFor(rows.map((r) => r.domain)), [rows])
  const recordTable = (rs: Rewrite[], empty: string) => (
    <RecordTable
      rows={rs}
      query={q}
      loaded={loaded}
      err={err}
      admin={admin}
      known={known}
      empty={empty}
      view={view}
      zones={zones}
      onToggle={toggle}
      onEdit={setEditing}
      onDelete={del}
      onDetach={detach}
    />
  )

  return (
    <div className="pg-local-dns">
      <header className="page-head">
        <h1>Local DNS</h1>
        <span className="spacer" />
        <button className="btn sm" onClick={() => setTesting(true)}>
          Test a query
        </button>
      </header>
      {testing && <TestQuery onClose={() => setTesting(false)} />}
      <p className="intro">
        Answer names on your own network. Records are pushed to every resolver; scope one to a site or a single resolver for
        split-horizon answers. To send a whole domain to another DNS server, use the conditional forwarders in{' '}
        <a
          href="/settings?section=resolver"
          onClick={(e) => {
            if (e.button !== 0 || e.metaKey || e.ctrlKey || e.shiftKey || e.altKey) return
            e.preventDefault()
            window.history.pushState({}, '', '/settings?section=resolver')
            window.dispatchEvent(new PopStateEvent('popstate'))
          }}
        >
          Settings
        </a>
        .
      </p>
      <div className="rw-explain">
        <span>
          <b className="mono">*.lab.lan</b> matches every subdomain, not the bare name
        </span>
        <span>
          <b>Most specific scope wins:</b> resolver › site › everyone
        </span>
        <span>
          <b>A/AAAA records</b> also name the client on every page and answer reverse lookups
        </span>
      </div>

      <div className="toolbar">
        <SearchBox
          value={search}
          onChange={setSearch}
          placeholder="Search names, answers, resolvers, integrations…"
          maxWidth={460}
        />
        {q && (
          <span className="muted" role="status">
            {matches === 0 ? 'Nothing matches' : plural(matches, 'match', 'matches')}
          </span>
        )}
        <span className="spacer" />
        <div className="seg" role="group" aria-label="Layout">
          <button type="button" aria-pressed={view === 'grouped'} onClick={() => pickView('grouped')}>
            By zone
          </button>
          <button type="button" aria-pressed={view === 'list'} onClick={() => pickView('list')}>
            List
          </button>
        </div>
      </div>

      <section className="card flush">
        <div className="card-head">
          <div>
            <h2>Local records</h2>
            <p className="sub">
              {loaded ? count(manual.length, manualAll.length, 'record', 'records') : 'Loading…'}
            </p>
          </div>
        </div>
        {admin && (
          <form className="rw-addrow" onSubmit={add}>
            <label className="field">
              <span>Name</span>
              <input
                className="mono"
                placeholder="nas.home.lan or *.lab.lan"
                value={domain}
                onChange={(e) => setDomain(e.target.value)}
              />
            </label>
            <label className="field">
              <span>Type</span>
              <select value={rrtype} onChange={(e) => setRrtype(e.target.value)}>
                <option>A</option>
                <option>AAAA</option>
                <option>CNAME</option>
              </select>
            </label>
            <label className="field">
              <span>Answer</span>
              <input
                className="mono"
                placeholder={rrtype === 'CNAME' ? 'nas.home.lan' : rrtype === 'AAAA' ? 'fd00::5' : '192.168.1.5'}
                value={value}
                onChange={(e) => setValue(e.target.value)}
              />
            </label>
            <div className="field">
              <label htmlFor="rw-scope">Scope</label>
              <ScopePicker id="rw-scope" value={scope} onChange={setScope} nodes={nodes} sites={sites} />
            </div>
            <button type="submit" className="btn primary" disabled={adding || !domain.trim() || !value.trim()}>
              {adding ? 'Adding…' : 'Add'}
            </button>
          </form>
        )}
        {err && (
          <div className="error rw-err" role="alert">
            {err}
          </div>
        )}
        {recordTable(
          manual,
          q
            ? `No local records match “${search.trim()}”.`
            : sources.length > 0
              ? 'No manual records.'
              : `No records yet.${admin ? ' Add one above to answer a name on your network.' : ''}`,
        )}
      </section>

      {sources.map((src) => {
        const ownedAll = rows.filter((r) => r.source === src)
        const owned = shown.filter((r) => r.source === src)
        // While searching, an integration with no match drops out of the page.
        if (q && owned.length === 0) return null
        return (
          <div key={src}>
            <h2 className="section">
              Synced from <span className="mono">{src}</span>
            </h2>
            <p className="section">
              {count(owned.length, ownedAll.length, 'record', 'records')} pushed and kept up to date by the {src}{' '}
              integration. Switching one off sticks; to edit or delete one by hand, detach it and it moves to your local
              records.
            </p>
            <section className="card flush">{recordTable(owned, 'No records.')}</section>
          </div>
        )
      })}

      {editing && (
        <EditScopedModal
          title={`Edit ${editing.domain}`}
          intro={
            <>
              The name <code>{editing.domain}</code> and type <code>{editing.rrtype}</code> identify the record and can't
              be changed. To change them, delete the record and add a new one.
            </>
          }
          fieldLabel={editing.rrtype === 'CNAME' ? 'Answer (target name)' : `Answer (${editing.rrtype === 'AAAA' ? 'IPv6' : 'IPv4'} address)`}
          fieldPlaceholder={editing.rrtype === 'CNAME' ? 'nas.home.lan' : editing.rrtype === 'AAAA' ? 'fd00::5' : '192.168.1.5'}
          initialText={editing.value}
          initialScope={{ scope_type: editing.scope_type || 'all', scope_values: editing.scope_values ?? [] }}
          nodes={nodes}
          sites={sites}
          onClose={closeEdit}
          onSave={(text, s) => saveEdit(editing, text, s)}
        />
      )}
    </div>
  )
}

// The table's layout, remembered per browser: records grouped by zone (the
// default) or one flat list; and which zones are folded.
type View = 'grouped' | 'list'
const VIEW_KEY = 'mazedns.localdns.view'
const FOLDED_KEY = 'mazedns.localdns.folded'
const readStore = (k: string) => {
  try {
    return localStorage.getItem(k)
  } catch {
    return null
  }
}
const writeStore = (k: string, v: string) => {
  try {
    localStorage.setItem(k, v)
  } catch {
    /* private mode: not remembered */
  }
}

// RecordTable lists local records. A manual record can be edited and deleted;
// one an integration owns can only be switched, or detached to make it manual.
// Grouped, records sit under their zone (recordZones.ts) with the short name,
// and a zone folds away; the list view is the plain sortable, paged table.
function RecordTable({
  rows,
  query,
  loaded,
  err,
  admin,
  known,
  empty,
  view,
  zones,
  onToggle,
  onEdit,
  onDelete,
  onDetach,
}: {
  rows: Rewrite[]
  query: string
  loaded: boolean
  err: string
  admin: boolean
  known: (scopeType?: string) => string[] | undefined
  empty: string
  view: View
  zones: Map<string, string>
  onToggle: (r: Rewrite) => void
  onEdit: (r: Rewrite) => void
  onDelete: (r: Rewrite) => void
  onDetach: (r: Rewrite) => void
}) {
  const table = useTable(rows, COLS, 'domain')
  // A new search starts from the first page of matches.
  const { setPage } = table
  useEffect(() => setPage(0), [query, setPage])

  const [folded, setFolded] = useState<Set<string>>(() => new Set(JSON.parse(readStore(FOLDED_KEY) || '[]') as string[]))
  const fold = (zone: string) =>
    setFolded((prev) => {
      const next = new Set(prev)
      if (next.has(zone)) next.delete(zone)
      else next.add(zone)
      writeStore(FOLDED_KEY, JSON.stringify([...next]))
      return next
    })

  // Grouped: zones in name order, records inside sorted like the list view.
  const groups = useMemo(() => {
    if (view !== 'grouped') return []
    const acc = COLS[table.sortKey] ?? COLS.domain
    const cmp = (a: Rewrite, b: Rewrite) => {
      const c = String(acc(a)).localeCompare(String(acc(b)), undefined, { sensitivity: 'base', numeric: true })
      return table.desc ? -c : c
    }
    const by = new Map<string, Rewrite[]>()
    for (const r of rows) {
      const z = zones.get(r.domain) ?? r.domain
      by.set(z, [...(by.get(z) ?? []), r])
    }
    return [...by.entries()]
      .sort(([a], [b]) => a.localeCompare(b))
      .map(([zone, rs]) => ({ zone, rows: rs.sort(cmp) }))
  }, [rows, view, zones, table.sortKey, table.desc])

  const cols = 4
  const row = (r: Rewrite, zone?: string) => (
    <tr key={r.id} className={r.enabled ? '' : 'off'}>
      <td className="lead">
        {zone ? (
          <span className="domain rw-name" title={r.domain}>
            {relName(r.domain, zone)}
            {relName(r.domain, zone) === '*' && <span className="muted rw-hint"> every name in the zone</span>}
            {relName(r.domain, zone) === '@' && <span className="muted rw-hint"> the zone itself</span>}
          </span>
        ) : (
          <span className="domain">{r.domain}</span>
        )}
      </td>
      <td>
        <span className="tag rewrite">{r.rrtype}</span> <span className="domain">{r.value}</span>
      </td>
      <td>
        {(r.scope_type || 'all') === 'all' ? (
          <span className="muted rw-everyone">Everyone</span>
        ) : (
          scopeBadge(r.scope_type, r.scope_values, known(r.scope_type))
        )}
      </td>
      <td className="lead-r rw-ctl">
        {admin ? (
          <span className="rw-ctl-in">
            <button
              type="button"
              role="switch"
              aria-checked={r.enabled}
              aria-label={`${r.enabled ? 'Disable' : 'Enable'} ${r.domain}`}
              className="switch-btn"
              onClick={() => onToggle(r)}
              title={r.enabled ? 'On — click to turn off' : 'Off — click to turn on'}
            >
              <span className={`switch${r.enabled ? ' on' : ''}`} />
            </button>
            {r.source ? (
              <button
                className="btn sm quiet"
                onClick={() => onDetach(r)}
                title={`Stop ${r.source} from managing this record and edit it by hand`}
              >
                Detach
              </button>
            ) : (
              <>
                <button className="icon-btn" onClick={() => onEdit(r)} aria-label={`Edit ${r.domain}`} title="Edit">
                  <Icon name="pencil" size={16} />
                </button>
                <button className="icon-btn rw-del" onClick={() => onDelete(r)} aria-label={`Delete ${r.domain}`} title="Delete">
                  <Icon name="trash" size={16} />
                </button>
              </>
            )}
          </span>
        ) : r.enabled ? (
          <span className="tag ok">On</span>
        ) : (
          <span className="tag">Off</span>
        )}
      </td>
    </tr>
  )

  return (
    <>
      <div className="table-scroll">
        <table className={`stackable rw-table${view === 'grouped' ? ' grouped' : ''}`}>
          <thead>
            <tr>
              <Th table={table} col="domain">Name</Th>
              <Th table={table} col="value">Answer</Th>
              <Th table={table} col="scope">Scope</Th>
              <th>
                <span className="sr-only">{admin ? 'Enabled and actions' : 'Status'}</span>
              </th>
            </tr>
          </thead>
          {view === 'grouped' ? (
            groups.map(({ zone, rows: rs }) => {
              // While searching every zone with a match stays open.
              const open = !!query || !folded.has(zone)
              const off = rs.filter((r) => !r.enabled).length
              return (
                <tbody key={zone} className="rw-group">
                  <tr className="rw-zone">
                    <th colSpan={cols} scope="rowgroup">
                      <button
                        type="button"
                        className="rw-zone-btn"
                        aria-expanded={open}
                        aria-label={`${zone}: ${plural(rs.length, 'record', 'records')}${off > 0 ? `, ${off} off` : ''}`}
                        onClick={() => fold(zone)}
                      >
                        <Icon name="chevron-down" size={16} className={open ? '' : 'folded'} />
                        <span className="domain">{zone}</span>
                        <span className="muted">
                          {plural(rs.length, 'record', 'records')}
                          {off > 0 ? ` · ${off} off` : ''}
                        </span>
                      </button>
                    </th>
                  </tr>
                  {open && rs.map((r) => row(r, zone))}
                </tbody>
              )
            })
          ) : (
            <tbody>{table.rows.map((r) => row(r))}</tbody>
          )}
          <tbody>
            <TableStatusRow
              loading={!loaded}
              error={err}
              empty={(view === 'grouped' ? rows.length : table.rows.length) === 0}
              colSpan={cols}
            >
              {empty}
            </TableStatusRow>
          </tbody>
        </table>
      </div>
      {view === 'list' && <Pager table={table} unit="records" />}
    </>
  )
}
