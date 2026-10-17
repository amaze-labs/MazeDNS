import { useEffect, useMemo, useState, type MouseEvent } from 'react'
import Spinner from './Spinner'
import { TableStatusRow } from './tableKit'
import {
  Bar,
  BarChart,
  CartesianGrid,
  Cell,
  Line,
  LineChart,
  Pie,
  PieChart,
  ResponsiveContainer,
  Tooltip,
  XAxis,
  YAxis,
} from 'recharts'
import {
  api,
  type SeriesPoint,
  type Insights,
  type Node,
  type LatencyPoint,
  type DomainStat,
  type Protection,
} from '../api'
import { RANGES, RangeNodeBar, OVERALL_COLOR, makeNodeColor, siteGroups } from './filters'
import { pollWhileVisible } from '../poll'
import { useClientNames } from '../useClientNames'
import ClientLabel from './ClientLabel'
import '../styles/overview.css'

const ONLINE_WINDOW = 120
const POLL_MS = 15000
// Top domains scan the raw query log (the server caches the answer), so they
// refresh less often and only while the card is open.
const TOP_POLL_MS = 60000

const fmt = (n?: number) => (n == null ? '—' : n.toLocaleString())
const pct = (num: number, den: number) => (den > 0 ? (num / den) * 100 : 0)
const fmtPct = (v: number) => (v > 0 && v < 0.1 ? '<0.1' : v >= 99.95 || v === 0 ? v.toFixed(0) : v.toFixed(1))
const fmtMs = (v: number) => (v >= 100 ? v.toFixed(0) : String(+v.toFixed(v >= 10 ? 1 : 2)))
// Compact axis numbers: 1500 -> 1.5k, 2000 -> 2k.
const compact = (n: number) =>
  Math.abs(n) >= 1e6
    ? `${+(n / 1e6).toFixed(1)}M`
    : Math.abs(n) >= 1000
    ? `${+(n / 1000).toFixed(1)}k`
    : String(n)

// Persist dashboard view prefs (time window + agent focus + top domains open)
// in the browser.
const loadHours = (): number => {
  const v = Number(localStorage.getItem('mazedns.hours'))
  return RANGES.some((r) => r.hours === v) ? v : 24
}
const loadFocus = (): string[] => {
  try {
    const v = JSON.parse(localStorage.getItem('mazedns.focusNodes') || '[]')
    return Array.isArray(v) ? v : []
  } catch {
    return []
  }
}

// windowPhrase: "the last 24 hours", "the last hour", "the last 15 days".
const windowPhrase = (hours: number) => {
  if (hours === 1) return 'the last hour'
  if (hours < 1) return `the last ${Math.round(hours * 60)} minutes`
  if (hours >= 48 && hours % 24 === 0) return `the last ${hours / 24} days`
  return `the last ${hours} hours`
}

const bucketLabel = (ts: number, hours: number) => {
  const d = new Date(ts * 1000)
  return hours <= 48
    ? d.toLocaleTimeString([], { hour: '2-digit', minute: '2-digit', hour12: false })
    : d.toLocaleDateString([], { month: 'short', day: 'numeric' })
}
const stepPhrase = (step: number) => {
  if (step < 60) return `${step}-second`
  if (step < 3600) return `${Math.round(step / 60)}-minute`
  const h = step / 3600
  return `${Number.isInteger(h) ? h : h.toFixed(1)}-hour`
}

// go navigates inside the single-page app (App listens to popstate), keeping
// real links so middle-click / open in new tab still work.
const navigate = (path: string) => {
  window.history.pushState({}, '', path)
  window.dispatchEvent(new PopStateEvent('popstate'))
}
const go = (path: string) => (e: MouseEvent) => {
  if (e.defaultPrevented || e.button !== 0 || e.metaKey || e.ctrlKey || e.shiftKey || e.altKey) return
  e.preventDefault()
  navigate(path)
}

const ago = (ts: number) => {
  const s = Math.max(0, Date.now() / 1000 - ts)
  if (s < 90) return 'just now'
  if (s < 5400) return `${Math.round(s / 60)} min ago`
  if (s < 172800) return `${Math.round(s / 3600)} h ago`
  return `${Math.round(s / 86400)} days ago`
}
const fmtLeft = (s: number) => (s >= 3600 ? `${Math.floor(s / 3600)} h ${Math.round((s % 3600) / 60)} min` : s >= 60 ? `${Math.round(s / 60)} min` : `${s} s`)

// The four ways a query is answered, in band / legend / stack order.
const FLOW = [
  { key: 'cached', k: 'cache', label: 'From cache' },
  { key: 'forwarded', k: 'fwd', label: 'Forwarded' },
  { key: 'blocked', k: 'block', label: 'Blocked' },
  { key: 'rewritten', k: 'rewrite', label: 'Rewritten' },
] as const

// The traffic chart stacks the series the time-series API returns; whatever
// is left (rewrites, errors) goes on top in the rewrite hue.
const STACK = [
  { key: 'cached', k: 'cache', label: 'Cache' },
  { key: 'forwarded', k: 'fwd', label: 'Forwarded' },
  { key: 'blocked', k: 'block', label: 'Blocked' },
  { key: 'other', k: 'rewrite', label: 'Rewritten and other' },
] as const

type TrafficRow = {
  ts: number
  cached: number
  forwarded: number
  blocked: number
  other: number
  total: number
  partial: boolean
}

function TrafficTooltip({ active, payload, hours, step }: any) {
  if (!active || !payload?.length) return null
  const row: TrafficRow = payload[0].payload
  return (
    <div className="ov-tip">
      <div className="ov-tip-head">
        {bucketLabel(row.ts, hours)} – {bucketLabel(row.ts + step, hours)}
        {row.partial && <span className="muted"> · still filling</span>}
      </div>
      {STACK.filter((s) => s.key !== 'other' || row.other > 0).map((s) => (
        <div key={s.key} className="ov-tip-row" style={{ ['--k' as any]: `var(--${s.k})` }}>
          <span>{s.label}</span>
          <b>{row[s.key].toLocaleString()}</b>
        </div>
      ))}
      <div className="ov-tip-row total">
        <span>Total</span>
        <b>{row.total.toLocaleString()}</b>
      </div>
    </div>
  )
}

function LatencyTooltip({ active, payload, label, hours, color }: any) {
  if (!active || !payload?.length) return null
  const rows = payload.filter((p: any) => p.value != null)
  return (
    <div className="ov-tip">
      <div className="ov-tip-head">{bucketLabel(label, hours)}</div>
      {rows.length === 0 && <div className="muted">No queries</div>}
      {rows.map((p: any) => (
        <div
          key={p.dataKey}
          className="ov-tip-row"
          style={{ ['--k' as any]: p.dataKey === 'overall' ? OVERALL_COLOR : color(p.dataKey) }}
        >
          <span>{p.dataKey === 'overall' ? 'All agents' : p.dataKey}</span>
          <b>{fmtMs(p.value)} ms</b>
        </div>
      ))}
    </div>
  )
}

function PieTip({ active, payload }: any) {
  if (!active || !payload?.length) return null
  const d = payload[0].payload || {}
  return (
    <div className="ov-tip">
      <div className="ov-tip-row" style={{ ['--k' as any]: d.fill }}>
        <span>{d.name}</span>
        <b>{Number(d.value).toLocaleString()}</b>
      </div>
    </div>
  )
}

// Donut: one share-of-total ring with a key under it.
function Donut({ title, data }: { title: string; data: { name: string; value: number; fill: string }[] }) {
  const total = data.reduce((s, d) => s + d.value, 0)
  return (
    <div className="ov-donut">
      <h3>{title}</h3>
      {total === 0 ? (
        <p className="muted small">No queries in this window.</p>
      ) : (
        <div className="ov-donut-body">
          <div className="ov-donut-ring">
            <ResponsiveContainer width="100%" height={150}>
              <PieChart>
                <Pie
                  data={data}
                  dataKey="value"
                  nameKey="name"
                  innerRadius={46}
                  outerRadius={70}
                  paddingAngle={data.length > 1 ? 2 : 0}
                  stroke="var(--panel)"
                  strokeWidth={2}
                  isAnimationActive={false}
                >
                  {data.map((d) => (
                    <Cell key={d.name} fill={d.fill} />
                  ))}
                </Pie>
                <Tooltip content={<PieTip />} />
              </PieChart>
            </ResponsiveContainer>
          </div>
          <ul className="ov-donut-keys">
            {data.map((d) => (
              <li key={d.name} style={{ ['--k' as any]: d.fill }}>
                <span className="nm">{d.name}</span>
                <span className="num">{d.value.toLocaleString()}</span>
                <span className="num muted">{fmtPct(pct(d.value, total))}%</span>
              </li>
            ))}
          </ul>
        </div>
      )}
    </div>
  )
}

// TimeTick is an x-axis label; the in-progress bucket reads "now" in full ink.
function TimeTick({ x, y, payload, textAnchor, label }: any) {
  const t = label(payload.value)
  return (
    <text
      x={x}
      y={y}
      dy="0.71em"
      textAnchor={t === 'now' ? 'middle' : textAnchor}
      fontSize={11}
      fill={t === 'now' ? 'var(--text)' : 'var(--faint)'}
      fontWeight={t === 'now' ? 500 : 400}
    >
      {t}
    </text>
  )
}

// Load is a widget's state while its first answer is pending or failed.
function Load({ error, what }: { error?: string; what: string }) {
  return error ? <p className="muted small">Couldn't load {what}.</p> : <Spinner label="Loading…" />
}

export default function Dashboard() {
  const [hours, setHours] = useState(loadHours)
  const [focus, setFocus] = useState<string[]>(loadFocus)
  const [series, setSeries] = useState<{ step: number; points: SeriesPoint[] } | null>(null)
  const [ins, setIns] = useState<Insights | null>(null)
  const [lat, setLat] = useState<{ step: number; nodes: string[]; points: LatencyPoint[] } | null>(null)
  const [nodes, setNodes] = useState<Node[] | null>(null)
  const [prot, setProt] = useState<Protection | null>(null)
  // Per-request errors, so one failing endpoint stops only its own spinner and
  // the others keep showing their data.
  const [errs, setErrs] = useState<Record<string, string>>({})
  // updating: a window/focus change is in flight (cleared when every request
  // of that change has answered or failed — never left spinning).
  const [updating, setUpdating] = useState(true)
  // Context for the legend hints (fetched once; optional).
  const [upstreams, setUpstreams] = useState<string[] | null>(null)
  const [listCount, setListCount] = useState<number | null>(null)
  const [ruleCount, setRuleCount] = useState<number | null>(null)

  // Top domains are loaded lazily (heavy raw-log scan) only while the card is open.
  const [topOpen, setTopOpen] = useState(() => localStorage.getItem('mazedns.topDomains') === '1')
  const [topKind, setTopKind] = useState<'blocked' | 'queried'>('blocked')
  const [topDom, setTopDom] = useState<{ top_queried: DomainStat[]; top_blocked: DomainStat[] } | null>(null)
  const [topErr, setTopErr] = useState('')

  useEffect(() => {
    localStorage.setItem('mazedns.hours', String(hours))
  }, [hours])
  useEffect(() => {
    localStorage.setItem('mazedns.focusNodes', JSON.stringify(focus))
  }, [focus])
  useEffect(() => {
    localStorage.setItem('mazedns.topDomains', topOpen ? '1' : '0')
  }, [topOpen])

  useEffect(() => {
    let alive = true
    setUpdating(true)
    const setErr = (k: string, m: string) => alive && setErrs((e) => (e[k] === m ? e : { ...e, [k]: m }))
    // Fire each request independently and update its widget as soon as it
    // arrives, so a slow endpoint never blocks the rest of the page.
    const tick = () => {
      const req = <T,>(k: string, p: Promise<T>, ok: (v: T) => void) =>
        p.then(
          (v) => {
            if (!alive) return
            ok(v)
            setErr(k, '')
          },
          (e: any) => setErr(k, e?.message || 'Request failed'),
        )
      return Promise.all([
        req('series', api.timeseries(hours, focus), setSeries),
        req('insights', api.insights(hours, focus), setIns),
        req('latency', api.latency(hours, focus), setLat),
        // Cluster and protection status are context: a failure here (cluster
        // off, viewer role) just hides their parts instead of raising an error.
        api.clusterNodes().then((n) => alive && setNodes(n), () => alive && setNodes((cur) => cur ?? [])),
        api.protection().then((p) => alive && setProt(p), () => {}),
      ])
    }
    tick().finally(() => alive && setUpdating(false))
    const stop = pollWhileVisible(tick, POLL_MS)
    return () => {
      alive = false
      stop()
    }
  }, [hours, focus])

  useEffect(() => {
    api.settings().then((s) => setUpstreams(s.upstreams ?? []), () => {})
    api.lists().then((l) => setListCount(l.filter((x) => x.enabled).length), () => {})
    api.rules().then((r) => setRuleCount(r.filter((x) => x.enabled && x.action !== 'allow').length), () => {})
  }, [])

  useEffect(() => {
    if (!topOpen) return
    let alive = true
    const tick = () =>
      api.topDomains(hours, focus).then(
        (d) => {
          if (!alive) return
          setTopDom(d)
          setTopErr('')
        },
        (e: any) => alive && setTopErr(e?.message || 'Request failed'),
      )
    tick()
    const stop = pollWhileVisible(tick, TOP_POLL_MS)
    return () => {
      alive = false
      stop()
    }
  }, [topOpen, hours, focus])

  // A node keeps the SAME colour on every page: colour comes from its position
  // in the sorted list of enrolled agents (the list Queries/Clients use too).
  const agentNames = useMemo(() => [...new Set((nodes ?? []).map((n) => n.name))], [nodes])
  const nodeColor = useMemo(() => makeNodeColor(agentNames), [agentNames])

  const totals = ins?.totals
  const total = totals?.total ?? 0
  const errorList = [...new Set(Object.values(errs).filter(Boolean))]

  // ---- traffic ----
  const step = series?.step ?? 0
  const nowSec = Date.now() / 1000
  const traffic: TrafficRow[] = (series?.points ?? []).map((p) => ({
    ts: p.ts,
    cached: p.cached,
    forwarded: p.forwarded,
    blocked: p.blocked,
    other: Math.max(0, p.total - p.cached - p.forwarded - p.blocked),
    total: p.total,
    partial: step > 0 && p.ts + step > nowSec,
  }))
  const hasOther = traffic.some((r) => r.other > 0)
  const stack = STACK.filter((s) => s.key !== 'other' || hasOther)
  // The in-progress bucket ("now"), from whichever series has answered.
  const partialTs = new Set([
    ...traffic.filter((r) => r.partial).map((r) => r.ts),
    ...(lat?.points ?? []).filter((p) => lat!.step > 0 && p.ts + lat!.step > nowSec).map((p) => p.ts),
  ])
  const xTick = (ts: number) => (partialTs.has(ts) ? 'now' : bucketLabel(ts, hours))

  // ---- latency ----
  const latNodes = lat?.nodes ?? []
  // Per-agent lines only add information when there is more than one agent.
  const showNodeLines = latNodes.length > 1
  const round2 = (n: number) => Math.round(n * 100) / 100
  const latData = (lat?.points ?? []).map((p) => {
    // A bucket with no queries has no latency: leave a gap, not a dip to zero.
    const row: Record<string, number | null> = { ts: p.ts, overall: p.overall > 0 ? round2(p.overall) : null }
    for (const n of latNodes) row[n] = p.by_node[n] != null && p.by_node[n] > 0 ? round2(p.by_node[n]) : null
    return row
  })
  // A point with no neighbours would be invisible on a line: draw it as a dot.
  const loneDot = (key: string, color: string) => (props: any) => {
    const { cx, cy, index } = props
    const prev = latData[index - 1]?.[key]
    const next = latData[index + 1]?.[key]
    if (latData[index]?.[key] == null || prev != null || next != null || cx == null || cy == null)
      return <g key={`${key}-${index}`} />
    return <circle key={`${key}-${index}`} cx={cx} cy={cy} r={3.5} fill={color} stroke="var(--panel)" strokeWidth={2} />
  }

  // ---- distribution ----
  const sourceData = totals
    ? [
        ...FLOW.map((f) => ({ name: f.label, value: totals[f.key], fill: `var(--${f.k})` })),
        { name: 'Errors', value: totals.errors, fill: 'var(--faint)' },
      ].filter((d) => d.value > 0)
    : []
  const byNodeData = (ins?.by_node ?? [])
    .filter((n) => n.total > 0)
    .map((n) => ({ name: n.node, value: n.total, fill: nodeColor(n.node) }))

  // ---- clients ----
  const clientRows = ins?.clients ?? []
  const maxClient = clientRows.reduce((m, c) => Math.max(m, c.total), 0)
  const clientNames = useClientNames(clientRows.map((c) => c.client))

  // ---- agents ----
  const windowSec = hours * 3600
  const byNode = new Map((ins?.by_node ?? []).map((n) => [n.node, n]))
  const agents = [...(nodes ?? [])].sort((a, b) => (a.site || '￿').localeCompare(b.site || '￿') || a.name.localeCompare(b.name))
  // Traffic attributed to a name that isn't an enrolled agent (e.g. the
  // control plane's own rows from older versions, or a removed agent).
  const strays = (ins?.by_node ?? []).filter((n) => n.total > 0 && !agentNames.includes(n.node))
  const online = agents.filter((n) => n.last_seen && nowSec - n.last_seen < ONLINE_WINDOW).length
  const showAgents = (nodes?.length ?? 0) > 0

  // ---- flow hints ----
  const flowHint: Record<string, string> = {
    cached: 'answered locally',
    forwarded: upstreams && upstreams.length > 0 ? `to ${upstreams.slice(0, 2).map((u) => u.replace(/:53$/, '')).join(', ')}${upstreams.length > 2 ? ` +${upstreams.length - 2}` : ''}` : 'to upstream resolvers',
    blocked:
      // Lists from MAZEDNS_BLOCKLIST_FILES block too but aren't in the API, so
      // "0 lists, 0 rules" would contradict a non-zero blocked count.
      listCount != null && ruleCount != null && listCount + ruleCount > 0
        ? `by ${listCount} ${listCount === 1 ? 'list' : 'lists'}, ${ruleCount} ${ruleCount === 1 ? 'rule' : 'rules'}`
        : 'by blocklists and rules',
    rewritten: 'local records',
  }

  const topRows = topKind === 'blocked' ? topDom?.top_blocked : topDom?.top_queried
  const topMax = (topRows ?? []).reduce((m, d) => Math.max(m, d.count), 0)

  return (
    <div className={`pg-overview${updating ? ' is-updating' : ''}`}>
      <header className="page-head">
        <h1>Overview</h1>
        <ProtectionPill prot={prot} />
        <span className="spacer" />
        {updating && <Spinner size={14} label="Updating…" />}
        <RangeNodeBar
          hours={hours}
          setHours={setHours}
          focus={focus}
          setFocus={setFocus}
          nodeNames={agentNames}
          color={nodeColor}
          sites={siteGroups(nodes ?? [])}
        />
      </header>

      {errorList.length > 0 && <div className="error">{errorList.join(' · ')}</div>}

      {/* Hero: how the window's queries were answered. */}
      <section className="ov-flow" aria-label="How queries were answered">
        <div className="ov-flow-head">
          <span className="ov-total">{totals ? total.toLocaleString() : '—'}</span>
          <span className="ov-what">queries in {windowPhrase(hours)}</span>
          <span className="ov-meta">
            {ins ? (
              <>
                <span>
                  <b>{total > 0 ? `${fmtMs(ins.avg_latency_ms)} ms` : '—'}</b> avg latency
                </span>
                <span>
                  <b>{fmt(ins.unique_clients)}</b> {ins.unique_clients === 1 ? 'client' : 'clients'}
                </span>
                {totals && totals.errors > 0 && (
                  <span className="warn-text">
                    <b>{fmt(totals.errors)}</b> {totals.errors === 1 ? 'error' : 'errors'}
                  </span>
                )}
              </>
            ) : (
              !errs.insights && <Spinner size={14} />
            )}
          </span>
        </div>
        <div className="ov-band" role="img" aria-label={FLOW.map((f) => `${f.label} ${fmtPct(pct(totals?.[f.key] ?? 0, total))}%`).join(', ')}>
          {total > 0 ? (
            FLOW.filter((f) => (totals?.[f.key] ?? 0) > 0).map((f) => {
              const v = totals![f.key]
              const p = pct(v, total)
              return (
                <div key={f.key} style={{ background: `var(--${f.k})`, flex: `${v} 1 0` }} title={`${f.label}: ${v.toLocaleString()} (${fmtPct(p)}%)`}>
                  {p >= 12 && (
                    <span>
                      {f.label} · {Math.round(p)}%
                    </span>
                  )}
                </div>
              )
            })
          ) : (
            <div className="empty-band">{totals ? 'No queries in this window yet' : ''}</div>
          )}
        </div>
        <div className="ov-legend">
          {FLOW.map((f) => {
            const v = totals?.[f.key]
            return (
              <div key={f.key} style={{ ['--k' as any]: `var(--${f.k})` }}>
                <div className="n">{fmt(v)}</div>
                <div className="l">
                  <b>{f.label}</b>
                  {v != null && <> · {fmtPct(pct(v, total))}%</>} · {flowHint[f.key]}
                </div>
              </div>
            )
          })}
        </div>
      </section>

      <div className="cols ov-grid">
        <section className={`card ov-chart-card${showAgents ? '' : ' ov-span'}`}>
          <div className="card-head">
            <div>
              <h2>Queries over time</h2>
              <p className="sub">
                {step ? `${stepPhrase(step)} buckets` : 'Queries per bucket'}; the current bucket is still filling.
              </p>
            </div>
            <span className="spacer" />
            <div className="legend-keys">
              {stack.map((s) => (
                <span key={s.key} style={{ ['--k' as any]: `var(--${s.k})` }}>
                  {s.label}
                </span>
              ))}
            </div>
          </div>
          {!series ? (
            <div className="ov-chart-load">
              <Load error={errs.series} what="the traffic series" />
            </div>
          ) : (
            <div className="ov-chart">
              <ResponsiveContainer width="100%" height={260}>
                <BarChart syncId="ov-time" data={traffic} margin={{ top: 6, right: 4, left: 0, bottom: 0 }} barCategoryGap="16%">
                  <defs>
                    {STACK.map((s) => (
                      <pattern
                        key={s.k}
                        id={`ov-part-${s.k}`}
                        width="5"
                        height="5"
                        patternUnits="userSpaceOnUse"
                        patternTransform="rotate(45)"
                      >
                        <rect width="5" height="5" fill={`var(--${s.k})`} fillOpacity={0.3} />
                        <rect width="2" height="5" fill={`var(--${s.k})`} fillOpacity={0.85} />
                      </pattern>
                    ))}
                  </defs>
                  <CartesianGrid stroke="var(--soft)" vertical={false} />
                  <XAxis
                    dataKey="ts"
                    stroke="var(--line)"
                    tick={<TimeTick label={xTick} />}
                    tickLine={false}
                    interval="preserveStartEnd"
                    minTickGap={28}
                    tickMargin={8}
                    height={28}
                  />
                  <YAxis
                    tickFormatter={compact}
                    tick={{ fill: 'var(--faint)', fontSize: 11 }}
                    axisLine={false}
                    tickLine={false}
                    width={42}
                    allowDecimals={false}
                    tickCount={5}
                  />
                  <Tooltip
                    cursor={{ fill: 'var(--raise)', opacity: 0.6 }}
                    content={<TrafficTooltip hours={hours} step={step} />}
                    isAnimationActive={false}
                  />
                  {stack.map((s) => (
                    <Bar key={s.key} dataKey={s.key} stackId="q" isAnimationActive={false}>
                      {traffic.map((r) => (
                        <Cell key={r.ts} fill={r.partial ? `url(#ov-part-${s.k})` : `var(--${s.k})`} />
                      ))}
                    </Bar>
                  ))}
                </BarChart>
              </ResponsiveContainer>
            </div>
          )}
        </section>

        {showAgents && (
          <section className="card flush">
            <div className="card-head ov-nowrap">
              <div>
                <h2>Agents</h2>
                <p className="sub">
                  Clients query these directly · {online} of {agents.length} online
                </p>
              </div>
              <span className="spacer" />
              <a className="btn sm quiet" href="/agents" onClick={go('/agents')}>
                Manage
              </a>
            </div>
            <div className="rowlist ov-agents">
              {agents.map((n) => {
                const isOnline = !!n.last_seen && nowSec - n.last_seen < ONLINE_WINDOW
                const st = byNode.get(n.name)
                const syncing = !!n.version && !!n.expected_version && n.version !== n.expected_version
                const dot = !n.approved || n.maintenance || (isOnline && syncing) ? 'warn' : isOnline ? '' : 'off'
                const state = !n.approved ? (
                  <span className="warn-text">waiting for approval</span>
                ) : !isOnline ? (
                  <span>offline · seen {n.last_seen ? ago(n.last_seen) : 'never'}</span>
                ) : n.maintenance ? (
                  <span className="warn-text">draining</span>
                ) : syncing ? (
                  <span className="warn-text">config syncing</span>
                ) : (
                  <span>in sync</span>
                )
                return (
                  <a key={n.id} className="rowitem" href="/agents" onClick={go('/agents')}>
                    <span className={`dot ${dot}`} />
                    <div>
                      <div className="title">
                        <span className="ov-swatch" style={{ background: nodeColor(n.name) }} />
                        {n.name}
                      </div>
                      <div className="meta">
                        <span>{[n.site || 'No site', n.role].filter(Boolean).join(' · ')}</span>
                        {state}
                      </div>
                    </div>
                    <div className="num ov-agent-num">
                      {st ? `${(st.total / windowSec).toFixed(2)} q/s` : ins ? '0 q/s' : '—'}
                      <div className="muted">
                        {st ? `${fmt(st.total)} · ${fmtPct(pct(st.blocked, st.total))}% blocked` : ''}
                      </div>
                    </div>
                  </a>
                )
              })}
              {strays.map((s) => (
                <div key={s.node} className="rowitem">
                  <span className="dot off" />
                  <div>
                    <div className="title">{s.node === 'master' ? 'Control plane' : s.node}</div>
                    <div className="meta">
                      <span>{s.node === 'master' ? 'answered on the control plane' : 'no longer enrolled'}</span>
                    </div>
                  </div>
                  <div className="num ov-agent-num">
                    {(s.total / windowSec).toFixed(2)} q/s
                    <div className="muted">
                      {fmt(s.total)} · {fmtPct(pct(s.blocked, s.total))}% blocked
                    </div>
                  </div>
                </div>
              ))}
            </div>
          </section>
        )}

        <section className="card flush">
          <div className="card-head ov-nowrap">
            <div>
              <h2>Top clients</h2>
              <p className="sub">Who is asking, and how much of it gets blocked.</p>
            </div>
            <span className="spacer" />
            <a className="btn sm quiet" href="/clients" onClick={go('/clients')}>
              All clients
            </a>
          </div>
          <table className="stackable ov-clients">
            <thead>
              <tr>
                <th>Client</th>
                <th className="num">Queries</th>
                <th className="num">Blocked</th>
                <th className="hide-sm">Share</th>
              </tr>
            </thead>
            <tbody>
              {clientRows.map((c) => {
                const allowed = c.total - c.blocked
                const href = `/queries?client=${encodeURIComponent(c.client)}`
                return (
                  <tr key={c.client} className="click" onClick={() => navigate(href)}>
                    <td className="lead">
                      {clientNames.get(c.client)?.name ? (
                        <ClientLabel ip={c.client} names={clientNames} />
                      ) : (
                        <span className="domain">{c.client}</span>
                      )}
                    </td>
                    <td className="num lead-r">{c.total.toLocaleString()}</td>
                    <td className="num ov-blocked">
                      {c.blocked.toLocaleString()} blocked <span className="muted">({fmtPct(pct(c.blocked, c.total))}%)</span>
                    </td>
                    <td className="hide-sm ov-share">
                      <div
                        className="mini"
                        style={{ width: `${maxClient ? Math.max(4, (c.total / maxClient) * 100) : 0}%` }}
                        title={`${allowed.toLocaleString()} answered, ${c.blocked.toLocaleString()} blocked`}
                      >
                        {allowed > 0 && <i style={{ ['--k' as any]: 'var(--muted)', flex: allowed }} />}
                        {c.blocked > 0 && <i style={{ ['--k' as any]: 'var(--block)', flex: c.blocked }} />}
                      </div>
                    </td>
                  </tr>
                )
              })}
              <TableStatusRow loading={!ins} error={errs.insights} empty={clientRows.length === 0} colSpan={4}>
                No client activity in this window.
              </TableStatusRow>
            </tbody>
          </table>
          {!ins && errs.insights && <p className="muted small ov-pad">Couldn't load the clients.</p>}
        </section>

        <section className="card ov-top">
          <div className="card-head">
            <div>
              <h2>{topOpen ? (topKind === 'blocked' ? 'Most blocked' : 'Most queried') : 'Top domains'}</h2>
              <p className="sub">
                {topOpen
                  ? topKind === 'blocked'
                    ? 'Domains stopped by blocklists and rules.'
                    : 'The names clients ask for most.'
                  : 'Most blocked and most queried domains.'}
              </p>
            </div>
            <span className="spacer" />
            {topOpen && (
              <div className="seg" role="group" aria-label="Domain ranking">
                <button type="button" className={topKind === 'blocked' ? 'on' : ''} aria-pressed={topKind === 'blocked'} onClick={() => setTopKind('blocked')}>
                  Blocked
                </button>
                <button type="button" className={topKind === 'queried' ? 'on' : ''} aria-pressed={topKind === 'queried'} onClick={() => setTopKind('queried')}>
                  Queried
                </button>
              </div>
            )}
          </div>
          {!topOpen ? (
            <div className="ov-top-off">
              <p className="muted small">Ranking domains reads the full query log for the window, so it loads only when you ask.</p>
              <button type="button" className="btn" onClick={() => setTopOpen(true)}>
                Show top domains
              </button>
            </div>
          ) : (
            <>
              {topErr && <div className="error">{topErr}</div>}
              {!topDom ? (
                !topErr && <Spinner label="Loading…" />
              ) : (topRows ?? []).length === 0 ? (
                <p className="muted small">{topKind === 'blocked' ? 'Nothing was blocked in this window.' : 'No queries in this window.'}</p>
              ) : (
                <ol className="ov-rank">
                  {(topRows ?? []).map((d) => (
                    <li key={d.name}>
                      <span className="domain">{d.name.replace(/\.$/, '')}</span>
                      <span className="v">{d.count.toLocaleString()}</span>
                      <span className="meter">
                        <i
                          style={{
                            ['--k' as any]: topKind === 'blocked' ? 'var(--block)' : 'var(--muted)',
                            width: `${topMax ? (d.count / topMax) * 100 : 0}%`,
                          }}
                        />
                      </span>
                    </li>
                  ))}
                </ol>
              )}
              <div className="ov-top-foot">
                <button type="button" className="btn sm quiet" onClick={() => setTopOpen(false)}>
                  Hide
                </button>
              </div>
            </>
          )}
        </section>

        <section className="card ov-chart-card">
          <div className="card-head">
            <div>
              <h2>Latency</h2>
              <p className="sub">Average time to answer, per bucket{showNodeLines ? ', overall and per agent' : ''}.</p>
            </div>
            <span className="spacer" />
            <div className="legend-keys">
              <span style={{ ['--k' as any]: OVERALL_COLOR }}>{showNodeLines ? 'All agents' : 'Average'}</span>
              {showNodeLines &&
                latNodes.map((n) => (
                  <span key={n} style={{ ['--k' as any]: nodeColor(n) }}>
                    {n}
                  </span>
                ))}
            </div>
          </div>
          {!lat ? (
            <div className="ov-chart-load">
              <Load error={errs.latency} what="latency" />
            </div>
          ) : (
            <div className="ov-chart">
              <ResponsiveContainer width="100%" height={200}>
                <LineChart syncId="ov-time" data={latData} margin={{ top: 6, right: 4, left: 0, bottom: 0 }}>
                  <CartesianGrid stroke="var(--soft)" vertical={false} />
                  <XAxis
                    dataKey="ts"
                    stroke="var(--line)"
                    tick={<TimeTick label={xTick} />}
                    tickLine={false}
                    interval="preserveStartEnd"
                    minTickGap={28}
                    tickMargin={8}
                    height={28}
                  />
                  <YAxis
                    tickFormatter={(v: number) => `${fmtMs(v)} ms`}
                    tick={{ fill: 'var(--faint)', fontSize: 11 }}
                    axisLine={false}
                    tickLine={false}
                    width={58}
                    tickCount={4}
                  />
                  <Tooltip
                    cursor={{ stroke: 'var(--line)' }}
                    content={<LatencyTooltip hours={hours} color={nodeColor} />}
                    isAnimationActive={false}
                  />
                  {showNodeLines &&
                    latNodes.map((n) => (
                      <Line
                        key={n}
                        type="monotone"
                        dataKey={n}
                        stroke={nodeColor(n)}
                        strokeWidth={1.5}
                        dot={loneDot(n, nodeColor(n))}
                        activeDot={{ r: 3.5 }}
                        isAnimationActive={false}
                      />
                    ))}
                  <Line
                    type="monotone"
                    dataKey="overall"
                    stroke={OVERALL_COLOR}
                    strokeWidth={2}
                    dot={loneDot('overall', OVERALL_COLOR)}
                    activeDot={{ r: 4, stroke: 'var(--panel)', strokeWidth: 2 }}
                    isAnimationActive={false}
                  />
                </LineChart>
              </ResponsiveContainer>
            </div>
          )}
        </section>

        <section className="card ov-dist">
          <div className="card-head">
            <div>
              <h2>Distribution</h2>
              <p className="sub">Share of the window's queries{byNodeData.length > 1 ? ' by agent and' : ''} by how they were answered.</p>
            </div>
          </div>
          {!ins ? (
            <Load error={errs.insights} what="the distribution" />
          ) : (
            <div className="ov-donuts">
              {byNodeData.length > 1 && <Donut title="By agent" data={byNodeData} />}
              <Donut title="By answer" data={sourceData} />
            </div>
          )}
        </section>
      </div>
    </div>
  )
}

// ProtectionPill: is blocking on, and a way to pause / resume it (the controls
// live on the Filtering page).
function ProtectionPill({ prot }: { prot: Protection | null }) {
  if (!prot) return null
  return prot.paused ? (
    <span className="ov-shield paused">
      <span className="dot warn pulse" />
      Blocking paused{prot.seconds_left > 0 ? ` · ${fmtLeft(prot.seconds_left)} left` : ''}
      <a href="/filtering" onClick={go('/filtering')}>
        Resume
      </a>
    </span>
  ) : (
    <span className="ov-shield">
      <span className="dot pulse" />
      Protection on
      <a href="/filtering" onClick={go('/filtering')}>
        Pause
      </a>
    </span>
  )
}
