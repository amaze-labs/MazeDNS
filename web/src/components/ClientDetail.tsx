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
  const tiles: [string, string | number][] = t
    ? [
        ['queries', t.total.toLocaleString()],
        ['blocked', t.blocked.toLocaleString()],
        ['cached', t.cached.toLocaleString()],
        ['forwarded', t.forwarded.toLocaleString()],
        ['errors', t.errors.toLocaleString()],
        ['unique domains', (d?.unique_domains ?? 0).toLocaleString()],
        ['avg latency', `${Math.round(d?.avg_latency_ms ?? 0)} ms`],
        ['last seen', d?.last_seen ? new Date(d.last_seen).toLocaleString() : '—'],
      ]
    : []

  const donut = (d?.actions ?? []).map((a) => ({ name: a.category, value: a.count, fill: actionColor(a.category) }))
  const cats = (d?.categories ?? []).map((c) => ({ name: c.category, value: c.count }))

  return (
    <Modal title={`Client ${client}`} onClose={onClose}>
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
            {tiles.map(([label, val]) => (
              <div key={label} className="usage-tile">
                <span className="num">{val}</span>
                <span className="muted">{label}</span>
              </div>
            ))}
          </div>

          <div className="charts" style={{ marginTop: 16 }}>
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
                      <Tooltip contentStyle={tooltipStyle} />
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

          <div className="charts" style={{ marginTop: 16 }}>
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
