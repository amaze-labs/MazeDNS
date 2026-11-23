import { useEffect, useRef, useState, type FormEvent, type ReactNode } from 'react'
import { api, type TestQueryAnswer, type TestQueryResult } from '../api'
import Modal from './Modal'
import '../styles/test-query.css'

const TYPES = ['A', 'AAAA', 'CNAME', 'MX', 'TXT', 'NS', 'SOA', 'PTR', 'SRV', 'CAA', 'HTTPS']

const errMsg = (e: unknown) => (e instanceof Error ? e.message : String(e)) || 'Request failed'

// The "as seen by" picker encodes its choice as "", "site:<name>" or "node:<name>".
function parseView(v: string): { node?: string; site?: string } {
  if (v.startsWith('node:')) return { node: v.slice(5) }
  if (v.startsWith('site:')) return { site: v.slice(5) }
  return {}
}

function scopeText(r: TestQueryResult): string {
  const on = (r.rewrite_scope_values || []).join(', ')
  switch (r.rewrite_scope) {
    case 'sites':
      return `site ${on}`
    case 'nodes':
      return `resolver ${on}`
    case 'all':
      return 'everyone'
    default:
      return ''
  }
}

const ms = (v?: number) => (v === undefined ? '' : v < 1 ? `${v.toFixed(2)} ms` : `${Math.round(v)} ms`)

// verdict says, in plain words, which step answered and why.
function verdict(r: TestQueryResult): { tone: 'ok' | 'bad' | 'warn' | ''; title: ReactNode; detail?: ReactNode } {
  switch (r.decision) {
    case 'authoritative':
      return { tone: 'ok', title: 'Authoritative zone', detail: <>Answered by the zone <b className="mono">{r.zone}</b> this control plane serves.</> }
    case 'rewrite': {
      const scope = scopeText(r)
      return {
        tone: 'ok',
        title: 'Local record',
        detail: (
          <>
            <b className="mono">{r.rewrite}</b>
            {scope ? <> (scope: {scope})</> : r.type === 'PTR' ? ' (reverse lookup of a local record)' : null}
          </>
        ),
      }
    }
    case 'blocked':
      return {
        tone: 'bad',
        title: 'Blocked',
        detail: r.schedule ? (
          <>
            The schedule <b>{r.schedule}</b> is on right now
            {r.client ? (
              <>
                {' '}
                and covers <b className="mono">{r.client}</b>
              </>
            ) : null}
            {r.category && r.category !== 'scheduled' ? (
              <>
                {' '}
                (category <b>{r.category}</b>)
              </>
            ) : null}
            .
          </>
        ) : r.category_block ? (
          <>
            The category <b>{r.category}</b> is blocked network-wide.
          </>
        ) : (
          <>
            A block rule or list matches (category <b>{r.category}</b>).
          </>
        ),
      }
    case 'forward':
      return {
        tone: '',
        title: r.forwarder ? 'Conditional forwarder' : 'Default upstream',
        detail: r.forwarder ? (
          <>
            Forwarded to <b className="mono">{r.upstream}</b> by the forwarder for <b className="mono">{r.forwarder}</b>,{' '}
            {ms(r.rtt_ms)}.
          </>
        ) : (
          <>
            Forwarded to <b className="mono">{r.upstream}</b>, {ms(r.rtt_ms)}.
          </>
        ),
      }
    default:
      return {
        tone: 'bad',
        title: 'Forwarding failed',
        detail: (
          <>
            {r.forwarder ? (
              <>
                The forwarder for <b className="mono">{r.forwarder}</b> did not answer:{' '}
              </>
            ) : (
              'No upstream answered: '
            )}
            <code>{r.error}</code>
          </>
        ),
      }
  }
}

function Records({ a }: { a: TestQueryAnswer }) {
  const rows = [...a.answer, ...(a.authority || []).map((r) => ({ ...r, auth: true }))]
  if (rows.length === 0) return <p className="muted tq-empty">No records{a.rcode ? ` (${a.rcode})` : ''}.</p>
  return (
    <table className="tq-records">
      <thead>
        <tr>
          <th>Name</th>
          <th>Type</th>
          <th className="num">TTL</th>
          <th>Data</th>
        </tr>
      </thead>
      <tbody>
        {rows.map((r, i) => (
          <tr key={i} className={'auth' in r ? 'muted' : undefined} title={'auth' in r ? 'Authority section' : undefined}>
            <td className="mono">{r.name}</td>
            <td>{r.type}</td>
            <td className="num mono">{r.ttl}</td>
            <td className="mono">{r.data}</td>
          </tr>
        ))}
      </tbody>
    </table>
  )
}

// TestQuery is the "Test a query" tool: what a name resolves to, and why, as a
// chosen resolver or site sees it — evaluated on the control plane without the
// cache.
export default function TestQuery({ initialName = '', onClose }: { initialName?: string; onClose: () => void }) {
  const [name, setName] = useState(initialName)
  const [type, setType] = useState('A')
  const [view, setView] = useState('')
  const [client, setClient] = useState('')
  const [forwardBlocked, setForwardBlocked] = useState(false)
  const [nodes, setNodes] = useState<string[]>([])
  const [sites, setSites] = useState<string[]>([])
  const [busy, setBusy] = useState(false)
  const [err, setErr] = useState('')
  const [res, setRes] = useState<TestQueryResult | null>(null)
  const field = useRef<HTMLInputElement>(null)

  useEffect(() => {
    api.clusterNodes().then((ns) => setNodes(ns.map((n) => n.name))).catch(() => {})
    api.clusterSites().then((ss) => setSites(ss.map((s) => s.name))).catch(() => {})
    const t = setTimeout(() => field.current?.focus(), 0)
    return () => clearTimeout(t)
  }, [])

  const run = async (e?: FormEvent) => {
    e?.preventDefault()
    if (!name.trim() || busy) return
    setBusy(true)
    setErr('')
    try {
      setRes(
        await api.testQuery({
          name: name.trim(),
          type,
          ...parseView(view),
          client: client.trim() || undefined,
          forward_blocked: forwardBlocked,
        }),
      )
    } catch (e) {
      setRes(null)
      setErr(errMsg(e))
    } finally {
      setBusy(false)
    }
  }

  const v = res ? verdict(res) : null
  const seenAs = res?.node ? `resolver ${res.node}${res.site ? ` (site ${res.site})` : ''}` : res?.site ? `site ${res.site}` : 'everywhere'

  return (
    <Modal
      title="Test a query"
      eyebrow="Bypasses the cache"
      size="wide"
      onClose={onClose}
      footer={
        <>
          <span className="spacer" />
          <button className="btn ghost" onClick={onClose}>
            Close
          </button>
          <button className="btn primary" onClick={() => run()} disabled={busy || !name.trim()}>
            {busy ? 'Resolving…' : 'Resolve'}
          </button>
        </>
      }
    >
      <form className="tq-form" onSubmit={run}>
        <label className="field tq-name">
          <span>Name</span>
          <input
            ref={field}
            className="mono"
            placeholder="nas.home.lan"
            value={name}
            onChange={(e) => setName(e.target.value)}
            autoCapitalize="none"
            spellCheck={false}
          />
        </label>
        <label className="field">
          <span>Type</span>
          <select value={type} onChange={(e) => setType(e.target.value)}>
            {TYPES.map((t) => (
              <option key={t}>{t}</option>
            ))}
          </select>
        </label>
        <label className="field">
          <span>As seen by</span>
          <select value={view} onChange={(e) => setView(e.target.value)}>
            <option value="">Everywhere (unscoped)</option>
            {sites.length > 0 && (
              <optgroup label="Site">
                {sites.map((s) => (
                  <option key={s} value={`site:${s}`}>
                    {s}
                  </option>
                ))}
              </optgroup>
            )}
            {nodes.length > 0 && (
              <optgroup label="Resolver">
                {nodes.map((n) => (
                  <option key={n} value={`node:${n}`}>
                    {n}
                  </option>
                ))}
              </optgroup>
            )}
          </select>
        </label>
        <label className="field">
          <span>Client IP</span>
          <input
            className="mono"
            placeholder="optional, for schedules"
            value={client}
            onChange={(e) => setClient(e.target.value)}
            spellCheck={false}
          />
        </label>
        <label className="tq-check">
          <input type="checkbox" checked={forwardBlocked} onChange={(e) => setForwardBlocked(e.target.checked)} />
          <span>Show what a blocked name would resolve to</span>
        </label>
        <button type="submit" hidden />
      </form>
      {type === 'PTR' && <p className="muted tq-hint">For PTR, an IP address is turned into its reverse name for you.</p>}

      {err && (
        <div className="error" role="alert">
          {err}
        </div>
      )}

      {res && v && (
        <section className="tq-result" aria-live="polite">
          <div className={`callout ${v.tone}`}>
            <div>
              <b>{v.title}</b>
              {v.detail && <p>{v.detail}</p>}
              {res.rewrite_yielded && (
                <p className="muted">
                  The wildcard <b className="mono">{res.rewrite_yielded}</b> matches too, but a more specific conditional
                  forwarder takes this name.
                </p>
              )}
              {res.allowed && (
                <p className="muted">
                  An allow rule lets this name through: it would be blocked otherwise (category <b>{res.category}</b>).
                </p>
              )}
              {res.schedule && res.decision !== 'blocked' && (
                <p className="muted">
                  The schedule <b>{res.schedule}</b> is on right now and would block this name.
                </p>
              )}
              {res.block_paused && (
                <p className="muted">
                  Blocking is paused
                  {res.category ? (
                    <>
                      : this name would be blocked otherwise (category <b>{res.category}</b>)
                    </>
                  ) : null}
                  .
                </p>
              )}
            </div>
          </div>

          <h3>
            Answer <span className="muted tq-rcode">{res.answer.rcode}</span>
            {res.answer.ad && <span className="tag ok">DNSSEC validated</span>}
          </h3>
          <Records a={res.answer} />

          {res.upstream_answer && (
            <>
              <h3>
                Upstream would answer{' '}
                <span className="muted tq-rcode">
                  {res.upstream_answer.rcode}
                  {res.upstream ? ` · ${res.upstream}, ${ms(res.rtt_ms)}` : ''}
                </span>
              </h3>
              <Records a={res.upstream_answer} />
            </>
          )}
          {res.decision === 'blocked' && forwardBlocked && !res.upstream_answer && res.error && (
            <p className="muted">
              The upstream did not answer: <code>{res.error}</code>
            </p>
          )}

          <p className="muted tq-foot">
            {res.name} {res.type}, as seen by {seenAs}. Ran on the control plane without the cache: blocking and local records
            are exactly what that resolver runs; a forwarded answer is what the upstream says now.
            {(res.decision === 'error' || res.decision === 'forward') && res.forwarder
              ? ' A forwarder reachable only from the resolver’s network may time out here even when it works there.'
              : ''}
          </p>
        </section>
      )}
    </Modal>
  )
}
