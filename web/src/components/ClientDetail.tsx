import { useEffect, useState } from 'react'
import { Bar, BarChart, ResponsiveContainer, Tooltip, XAxis, YAxis } from 'recharts'
import { api, type ClientDetail as Detail, type ClientIdentity } from '../api'
import { invalidateClientName } from '../useClientNames'
import Modal from './Modal'
import Spinner from './Spinner'
import { SOURCE_LABEL } from './ClientLabel'
import { fmtMs, timeAgo, windowLabel } from './tableKit'
import '../styles/queries.css'

// How a query was answered: the label, tag variant and chart colour of each
// query-log action. Shared by the Queries and Clients pages so a result reads
// the same everywhere (teal cache, blue forwarded, coral blocked, amber rewrite).
export const RESULTS: Record<string, { label: string; tag: string; color: string }> = {
  blocked: { label: 'Blocked', tag: 'block', color: 'var(--block)' },
  forward: { label: 'Forwarded', tag: 'fwd', color: 'var(--fwd)' },
  cache: { label: 'Cache', tag: 'cache', color: 'var(--cache)' },
  rewrite: { label: 'Rewritten', tag: 'rewrite', color: 'var(--rewrite)' },
  authoritative: { label: 'Local zone', tag: 'ok', color: 'var(--ok)' },
  error: { label: 'Error', tag: 'warn', color: 'var(--warn)' },
  refused: { label: 'Refused', tag: '', color: 'var(--faint)' },
}
export const resultOf = (action: string) => RESULTS[action] ?? { label: action || 'Unknown', tag: '', color: 'var(--faint)' }

// A client counts as active if it queried in the last 5 minutes.
export const ACTIVE_MS = 5 * 60 * 1000

const pct = (n: number, total: number) => (total > 0 ? Math.round((n / total) * 100) : 0)
const fmtAbs = (ms: number) => (ms ? new Date(ms).toLocaleString() : '')

// ClientDetail is the per-client drawer: the static-name editor (which overrides
// NetBird/rewrite/reverse-DNS names everywhere), headline figures, how its
// queries were answered, its top blocked and queried domains, and what was
// blocked by category. onShowQueries opens the Queries page filtered to the
// client; without it the drawer navigates there itself.
export default function ClientDetail({
  client,
  hours,
  nodes,
  names,
  onClose,
  onShowQueries,
}: {
  client: string
  hours: number
  nodes: string[]
  names: Map<string, ClientIdentity>
  onClose: () => void
  onShowQueries?: (client: string) => void
}) {
  const [d, setD] = useState<Detail | null>(null)
  const [err, setErr] = useState('')
  const id = names.get(client)
  // Prefill with the existing static name; otherwise the field is empty and the
  // detected NetBird/rewrite/reverse-DNS name (if any) shows as a hint.
  const [host, setHost] = useState(id?.source === 'manual' ? id.name : '')
  const [saving, setSaving] = useState(false)
  const [saveErr, setSaveErr] = useState('')
  const [saveMsg, setSaveMsg] = useState('')

  useEffect(() => {
    let alive = true
    setErr('')
    api
      .clientDetail(client, hours, nodes)
      .then((r) => alive && setD(r))
      .catch((e) => alive && setErr(e.message))
    return () => {
      alive = false
    }
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [client, hours, nodes.join(',')])

  const saveHost = async () => {
    setSaving(true)
    setSaveErr('')
    setSaveMsg('')
    try {
      await api.setClientName(client, host.trim())
      invalidateClientName(client)
      setSaveMsg(host.trim() ? 'Name saved. It shows everywhere this client appears.' : 'Name cleared.')
    } catch (e: any) {
      setSaveErr(e.message)
    } finally {
      setSaving(false)
    }
  }

  const showQueries = () => {
    if (onShowQueries) {
      onShowQueries(client)
      return
    }
    // Deep-link into the Queries page filtered to this client.
    window.history.pushState({}, '', `/queries?client=${encodeURIComponent(client)}`)
    window.dispatchEvent(new PopStateEvent('popstate'))
    onClose()
  }

  const detected = id?.name && id.source !== 'manual' ? id.name : ''
  const t = d?.totals
  const lastSeen = d?.last_seen ?? 0
  const active = lastSeen > 0 && Date.now() - lastSeen < ACTIVE_MS
  const win = `last ${windowLabel(hours)}`

  const eyebrow = (
    <span className="cd-eyebrow">
      {d && <span className={`dot ${active ? 'pulse' : 'off'}`} />}
      {d ? (active ? 'Active now' : lastSeen ? `Last seen ${timeAgo(lastSeen)}` : 'No queries in this window') : 'Client'}
      {id?.name && (
        <>
          <span> · </span>
          <span className="mono">{client}</span>
        </>
      )}
    </span>
  )

  const actions = (d?.actions ?? []).filter((a) => a.count > 0).sort((a, b) => b.count - a.count)
  const cats = (d?.categories ?? []).map((c) => ({ name: c.category || 'uncategorised', value: c.count }))

  return (
    <Modal
      title={id?.name || <span className="mono" style={{ fontSize: 17 }}>{client}</span>}
      eyebrow={eyebrow}
      onClose={onClose}
      footer={
        <>
          <button className="btn primary" onClick={showQueries}>
            Show its queries
          </button>
          <span className="spacer" />
          <span className="faint small">Figures cover the {win}</span>
        </>
      }
    >
      <div className="field">
        <label htmlFor="cd-name">Name</label>
        <div className="cd-namefield">
          <input
            id="cd-name"
            placeholder={detected || 'Name this device'}
            value={host}
            onChange={(e) => setHost(e.target.value)}
            onKeyDown={(e) => e.key === 'Enter' && !saving && saveHost()}
          />
          <button className="btn" disabled={saving} onClick={saveHost}>
            {saving ? 'Saving…' : 'Save'}
          </button>
        </div>
        <small>
          {detected ? (
            <>
              Detected {id?.source === 'rewrite' ? 'from a rewrite' : `from ${SOURCE_LABEL[id?.source ?? ''] ?? id?.source}`} as{' '}
              <b>{detected}</b>
              {id?.aliases && id.aliases.length > 0 ? ` (also ${id.aliases.join(', ')})` : ''}.{' '}
            </>
          ) : id?.source === 'manual' ? (
            'You named this client. Leave the field empty and save to clear the name. '
          ) : (
            'No name detected for this address. '
          )}
          A name you set here wins over NetBird, rewrites and reverse DNS.
        </small>
      </div>
      {saveErr && <div className="error" style={{ margin: 0 }}>{saveErr}</div>}
      {saveMsg && <div className="ok-msg" style={{ margin: 0 }}>{saveMsg}</div>}

      {err && <div className="error" style={{ margin: 0 }}>{err}</div>}
      {!d && !err && <Spinner label="Loading…" />}
      {d && t && (
        <>
          <div className="cd-split">
            <div>
              <b>{t.total.toLocaleString()}</b>
              <span>queries, {win}</span>
            </div>
            <div>
              <b className={t.blocked > 0 ? 'bad-text' : ''}>{t.total ? `${pct(t.blocked, t.total)}%` : '—'}</b>
              <span>blocked ({t.blocked.toLocaleString()})</span>
            </div>
            <div>
              <b>{t.total ? fmtMs(d.avg_latency_ms) : '—'}</b>
              <span>average latency</span>
            </div>
          </div>

          <div>
            <h3>How its queries were answered</h3>
            {actions.length === 0 ? (
              <p className="muted small" style={{ margin: 0 }}>
                No queries in this window.
              </p>
            ) : (
              <>
                <div className="mini cd-bar" role="img" aria-label="Queries by result">
                  {actions.map((a) => (
                    <i key={a.category} style={{ ['--k' as string]: resultOf(a.category).color, flex: a.count }} title={`${resultOf(a.category).label}: ${a.count.toLocaleString()}`} />
                  ))}
                </div>
                <div className="legend-keys" style={{ marginTop: 8 }}>
                  {actions.map((a) => (
                    <span key={a.category} style={{ ['--k' as string]: resultOf(a.category).color }}>
                      {resultOf(a.category).label} {pct(a.count, t.total)}%{' '}
                      <span className="faint">({a.count.toLocaleString()})</span>
                    </span>
                  ))}
                </div>
              </>
            )}
          </div>

          <dl className="kv cd-kv">
            <dt>Cache hit rate</dt>
            <dd>{t.total ? `${pct(t.cached, t.total)}%` : '—'} <span className="muted">({t.cached.toLocaleString()} cached)</span></dd>
            <dt>Forwarded</dt>
            <dd>{t.forwarded.toLocaleString()}</dd>
            <dt>Rewritten</dt>
            <dd>{t.rewritten.toLocaleString()}</dd>
            <dt>Errors</dt>
            <dd className={t.errors > 0 ? 'bad-text' : ''}>{t.errors.toLocaleString()}</dd>
            <dt>Unique domains</dt>
            <dd>{(d.unique_domains ?? 0).toLocaleString()}</dd>
            <dt>First query</dt>
            <dd title={fmtAbs(d.first_seen)}>{timeAgo(d.first_seen)}</dd>
            <dt>Last query</dt>
            <dd title={fmtAbs(d.last_seen)}>{timeAgo(d.last_seen)}</dd>
          </dl>

          <TopList title="Most blocked for this client" rows={d.top_blocked} color="var(--block)" empty="Nothing blocked in this window." />
          <TopList title="Most queried" rows={d.top_domains} color="var(--fwd)" empty="No queries in this window." />

          <div>
            <h3>Blocked by category</h3>
            {cats.length === 0 ? (
              <p className="muted small" style={{ margin: 0 }}>
                Nothing blocked in this window.
              </p>
            ) : (
              <ResponsiveContainer width="100%" height={180}>
                <BarChart data={cats} margin={{ top: 6, right: 4, left: -18, bottom: 0 }}>
                  <XAxis dataKey="name" stroke="var(--line)" tick={{ fill: 'var(--muted)', fontSize: 11 }} tickLine={false} interval={0} />
                  <YAxis stroke="var(--line)" tick={{ fill: 'var(--muted)', fontSize: 11 }} tickLine={false} axisLine={false} width={42} allowDecimals={false} />
                  <Tooltip cursor={{ fill: 'var(--raise)' }} formatter={(v: number) => [v.toLocaleString(), 'Blocked']} />
                  <Bar dataKey="value" fill="var(--block)" radius={[4, 4, 0, 0]} maxBarSize={36} />
                </BarChart>
              </ResponsiveContainer>
            )}
          </div>
        </>
      )}
    </Modal>
  )
}

function TopList({ title, rows, color, empty }: { title: string; rows: { name: string; count: number }[]; color: string; empty: string }) {
  const max = rows.reduce((m, r) => Math.max(m, r.count), 0)
  return (
    <div>
      <h3>{title}</h3>
      {rows.length === 0 ? (
        <p className="muted small" style={{ margin: 0 }}>
          {empty}
        </p>
      ) : (
        <ul className="cd-toplist">
          {rows.map((r) => (
            <li key={r.name}>
              <span className="domain" title={r.name}>
                {r.name.replace(/\.$/, '')}
              </span>
              <span className="meter">
                <i style={{ ['--k' as string]: color, width: `${max ? (r.count / max) * 100 : 0}%` }} />
              </span>
              <span className="num muted">{r.count.toLocaleString()}</span>
            </li>
          ))}
        </ul>
      )}
    </div>
  )
}
