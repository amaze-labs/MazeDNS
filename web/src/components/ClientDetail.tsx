import { useEffect, useState } from 'react'
import { Bar, BarChart, Cell, Pie, PieChart, ResponsiveContainer, Tooltip, XAxis, YAxis } from 'recharts'
import { api, type ClientDetail as Detail, type ClientIdentity } from '../api'
import { invalidateClientName } from '../useClientNames'
import Modal from './Modal'
import Spinner from './Spinner'

// Stable colors for the action donut (matches the dashboard query chart palette).
const ACTION_COLORS: Record<string, string> = {
  forward: '#4ea1ff',
  cache: '#3ecf8e',
  blocked: '#ff5d6c',
  rewrite: '#c48aff',
  error: '#ffb454',
  refused: '#8a93a0',
  authoritative: '#56d4dd',
}
const actionColor = (a: string) => ACTION_COLORS[a] ?? '#8a93a0'
const tooltipStyle = { background: '#11151b', border: '1px solid #262d36', borderRadius: 8, fontSize: 12 }

// PieTooltip reads the slice's own colour from the datum so the hover swatch
// matches the legend/slice — Recharts' default pie tooltip mis-colours them.
function PieTooltip({ active, payload }: any) {
  if (!active || !payload?.length) return null
  const p = payload[0]
  const d = p.payload || {}
  const color = d.fill || p.color || '#8a93a0'
  return (
    <div style={{ ...tooltipStyle, padding: '6px 10px', fontSize: 13 }}>
      <span style={{ color }}>● </span>
      {d.name ?? p.name}: {Number(p.value).toLocaleString()}
    </div>
  )
}

// timeAgo renders a compact relative time ("5m ago", "2d ago") from a unix-millis
// timestamp; "—" when there's no data.
const timeAgo = (ms: number): string => {
  if (!ms) return '—'
  const s = Math.max(0, Math.floor((Date.now() - ms) / 1000))
  if (s < 60) return `${s}s ago`
  const m = Math.floor(s / 60)
  if (m < 60) return `${m}m ago`
  const h = Math.floor(m / 60)
  if (h < 24) return `${h}h ago`
  const d = Math.floor(h / 24)
  if (d < 30) return `${d}d ago`
  const mo = Math.floor(d / 30)
  if (mo < 12) return `${mo}mo ago`
  return `${Math.floor(mo / 12)}y ago`
}
const pct = (n: number, total: number) => (total > 0 ? `${Math.round((n / total) * 100)}%` : '—')
const fmtAbs = (ms: number) => (ms ? new Date(ms).toLocaleString() : '')

// ClientDetail is the per-client inspect modal: KPI tiles, an action-breakdown
// donut over all traffic, a blocked-by-category bar, top domains, and the
// static-hostname editor (which overrides NetBird/reverse-DNS everywhere).
export default function ClientDetail({
  client,
  hours,
  nodes,
  names,
  onClose,
}: {
  client: string
  hours: number
  nodes: string[]
  names: Map<string, ClientIdentity>
  onClose: () => void
}) {
  const [d, setD] = useState<Detail | null>(null)
  const [err, setErr] = useState('')
  const id = names.get(client)
  // Prefill with the existing static name; otherwise the field is empty and the
  // detected NetBird/reverse-DNS name (if any) shows as a hint.
  const [host, setHost] = useState(id?.source === 'manual' ? id.name : '')
  const [saving, setSaving] = useState(false)
  const [saveMsg, setSaveMsg] = useState('')

  const load = () =>
    api.clientDetail(client, hours, nodes).then(setD).catch((e) => setErr(e.message))
  useEffect(() => {
    load()
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [client, hours, nodes.join(',')])

  const saveHost = async () => {
    setSaving(true)
    setErr('')
    setSaveMsg('')
    try {
      await api.setClientName(client, host.trim())
      invalidateClientName(client)
      setSaveMsg(host.trim() ? 'Hostname saved.' : 'Hostname cleared.')
    } catch (e: any) {
      setErr(e.message)
    } finally {
      setSaving(false)
    }
  }

  const inspectQueries = () => {
    // Deep-link into the Requests log filtered to this client.
    window.history.pushState({}, '', `/queries?client=${encodeURIComponent(client)}`)
    window.dispatchEvent(new PopStateEvent('popstate'))
  }

  const detected = id?.source && id.source !== 'manual' ? id.name : ''
  const t = d?.totals
  // KPI tiles: raw counts plus derived rates and relative activity times. `sub`
  // is an optional second line; `title` a hover tooltip (e.g. the absolute time).
  type Tile = { label: string; value: string | number; sub?: string; title?: string; tone?: string }
  const tiles: Tile[] = t
    ? [
        { label: 'queries', value: t.total.toLocaleString() },
        { label: 'block rate', value: pct(t.blocked, t.total), sub: `${t.blocked.toLocaleString()} blocked`, tone: t.blocked > 0 ? 'blocked' : '' },
        { label: 'cache hit rate', value: pct(t.cached, t.total), sub: `${t.cached.toLocaleString()} cached`, tone: 'allow' },
        { label: 'forwarded', value: t.forwarded.toLocaleString() },
        { label: 'rewritten', value: t.rewritten.toLocaleString() },
        { label: 'errors', value: t.errors.toLocaleString(), tone: t.errors > 0 ? 'blocked' : '' },
        { label: 'unique domains', value: (d?.unique_domains ?? 0).toLocaleString() },
        { label: 'avg latency', value: `${Math.round(d?.avg_latency_ms ?? 0)} ms` },
        { label: 'active since', value: timeAgo(d?.first_seen ?? 0), title: fmtAbs(d?.first_seen ?? 0) },
        { label: 'last seen', value: timeAgo(d?.last_seen ?? 0), title: fmtAbs(d?.last_seen ?? 0) },
      ]
    : []

  const donut = (d?.actions ?? []).map((a) => ({ name: a.category, value: a.count, fill: actionColor(a.category) }))
  const cats = (d?.categories ?? []).map((c) => ({ name: c.category, value: c.count }))

  return (
    <Modal title={`Client ${client}`} onClose={onClose} size="wide">
      {err && <div className="error">{err}</div>}
      {!d && <Spinner label="Loading…" />}
      {d && (
        <>
          {/* Static hostname editor */}
          <div className="settings-card" style={{ marginBottom: 16 }}>
            <h3>Static hostname</h3>
            <p className="muted" style={{ textAlign: 'left', marginTop: 0 }}>
              Assign a name for this IP (useful for static hosts that aren't NetBird peers). It overrides NetBird and
              reverse-DNS and shows everywhere.
              {detected && (
                <>
                  {' '}
                  Currently detected: <strong>{detected}</strong> ({id?.source}).
                </>
              )}
            </p>
            <div className="row" style={{ alignItems: 'center' }}>
              <input
                className="search"
                placeholder="hostname (leave empty to clear)"
                value={host}
                onChange={(e) => setHost(e.target.value)}
              />
              <button className="btn primary" disabled={saving} onClick={saveHost}>
                {saving ? 'Saving…' : 'Save'}
              </button>
            </div>
            {saveMsg && <div className="ok-msg">{saveMsg}</div>}
          </div>

          <div className="usage-tiles">
            {tiles.map((tile) => (
              <div key={tile.label} className="usage-tile" title={tile.title || undefined}>
                <span className={`num${tile.tone ? ` ${tile.tone}` : ''}`}>{tile.value}</span>
                <span className="muted">{tile.label}</span>
                {tile.sub && <span className="tile-sub muted">{tile.sub}</span>}
              </div>
            ))}
          </div>

          <div className="charts even" style={{ marginTop: 16 }}>
            <div className="panel">
              <h3>Traffic by action</h3>
              {donut.length === 0 ? (
                <p className="muted">No data yet</p>
              ) : (
                <>
                  <ResponsiveContainer width="100%" height={200}>
                    <PieChart>
                      <Pie data={donut} dataKey="value" nameKey="name" innerRadius={50} outerRadius={80} paddingAngle={2}>
                        {donut.map((x) => (
                          <Cell key={x.name} fill={x.fill} />
                        ))}
                      </Pie>
                      <Tooltip content={<PieTooltip />} />
                    </PieChart>
                  </ResponsiveContainer>
                  <div className="legend">
                    {donut.map((x) => (
                      <span key={x.name}>
                        <i style={{ background: x.fill }} /> {x.name} ({x.value.toLocaleString()})
                      </span>
                    ))}
                  </div>
                </>
              )}
            </div>
            <div className="panel">
              <h3>Blocked by category</h3>
              {cats.length === 0 ? (
                <p className="muted">Nothing blocked in this window</p>
              ) : (
                <ResponsiveContainer width="100%" height={200}>
                  <BarChart data={cats} margin={{ top: 8, right: 8, left: -20, bottom: 0 }}>
                    <XAxis dataKey="name" stroke="#8a93a0" fontSize={11} tickLine={false} interval={0} angle={-20} textAnchor="end" height={50} />
                    <YAxis stroke="#8a93a0" fontSize={11} tickLine={false} width={40} allowDecimals={false} />
                    <Tooltip contentStyle={tooltipStyle} cursor={{ fill: '#ffffff10' }} />
                    <Bar dataKey="value" fill="#ff5d6c" radius={[4, 4, 0, 0]} />
                  </BarChart>
                </ResponsiveContainer>
              )}
            </div>
          </div>

          <div className="charts even" style={{ marginTop: 16 }}>
            <DomainList title="Most queried" rows={d.top_domains} />
            <DomainList title="Top blocked" rows={d.top_blocked} />
          </div>

          <div className="pager" style={{ marginTop: 16 }}>
            <div className="spacer" />
            <button className="btn" onClick={inspectQueries}>
              Inspect queries ›
            </button>
          </div>
        </>
      )}
    </Modal>
  )
}

function DomainList({ title, rows }: { title: string; rows: { name: string; count: number }[] }) {
  return (
    <div className="panel">
      <h3>{title}</h3>
      <table className="mini">
        <tbody>
          {rows.map((r) => (
            <tr key={r.name}>
              <td className="name">{r.name}</td>
              <td className="num">{r.count.toLocaleString()}</td>
            </tr>
          ))}
          {rows.length === 0 && (
            <tr>
              <td className="muted">No data</td>
            </tr>
          )}
        </tbody>
      </table>
    </div>
  )
}
