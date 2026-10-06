import { useEffect, useMemo, useRef, useState } from 'react'
import { api, type LogEntry, type Node } from '../api'
import { pollWhileVisible } from '../poll'
import Spinner from './Spinner'
import '../styles/logs.css'

const CONTROL_PLANE = 'control-plane'
const ALL = 'all'
const LIMIT = 500
// Levels in rank order; the chips filter on these.
const LEVELS = ['debug', 'info', 'warn', 'error'] as const
type Level = (typeof LEVELS)[number]
const LEVEL_WORD: Record<string, string> = { debug: 'Debug', info: 'Info', warn: 'Warning', error: 'Error' }
const CHIP_WORD: Record<Level, string> = { debug: 'Debug', info: 'Info', warn: 'Warnings', error: 'Errors' }
const rank = (l: string) => {
  const i = LEVELS.indexOf(l as Level)
  return i < 0 ? 1 : i
}

// A line as rendered: the entry plus the machine it came from.
interface Line extends LogEntry {
  src: string // source id ('control-plane' or a node id)
}

// splitMsg separates the human message from its trailing key=value attributes
// (the log handler writes "message k=v k2=v2"), so the attributes can be muted.
function splitMsg(msg: string): [string, string] {
  const m = /\s[\w.-]+=/.exec(msg)
  if (!m) return [msg, '']
  return [msg.slice(0, m.index), msg.slice(m.index + 1)]
}

const initialSource = () => new URLSearchParams(window.location.search).get('source') || ALL

// Logs shows recent process-log lines from the control plane and every agent.
// Rings are in-memory and bounded: history has `docker logs` semantics, and
// agent lines lag by up to one poll interval (~30s). "All sources" merges the
// per-machine rings in the browser.
export default function Logs() {
  const [nodes, setNodes] = useState<Node[]>([])
  const [nodesLoaded, setNodesLoaded] = useState(false)
  const [source, setSource] = useState(initialSource)
  const [levels, setLevels] = useState<Level[]>([]) // empty = every level
  const [input, setInput] = useState('')
  const [search, setSearch] = useState('')
  const [lines, setLines] = useState<Line[]>([])
  const [err, setErr] = useState('')
  const [loading, setLoading] = useState(true)
  const [following, setFollowing] = useState(true)
  // Which query the rendered rows belong to, so a source switch clears them
  // instead of showing the old machine's lines under the new selection.
  const renderedSource = useRef(source)

  useEffect(() => {
    api
      .clusterNodes()
      .then(setNodes)
      .catch(() => setNodes([]))
      .finally(() => setNodesLoaded(true))
  }, [])

  // Keep ?source= in the URL so an agent's logs are linkable (the agent drawer
  // links here).
  useEffect(() => {
    const p = new URLSearchParams(window.location.search)
    if (source === ALL) p.delete('source')
    else p.set('source', source)
    const qs = p.toString()
    const url = `${window.location.pathname}${qs ? `?${qs}` : ''}`
    if (url !== `${window.location.pathname}${window.location.search}`) window.history.replaceState({}, '', url)
  }, [source])

  // Debounce the search box.
  useEffect(() => {
    const t = setTimeout(() => setSearch(input.trim()), 400)
    return () => clearTimeout(t)
  }, [input])

  // The server filters by minimum level; the chips can pick any subset, so ask
  // for the lowest picked level and drop the rest here.
  const minLevel = levels.length ? LEVELS[Math.min(...levels.map(rank))] : ''
  const sources = useMemo(
    () => (source === ALL ? [CONTROL_PLANE, ...nodes.map((n) => n.id)] : [source]),
    [source, nodes],
  )
  // "All sources" waits for the agent list so it doesn't render a control-plane
  // only view first.
  const ready = source !== ALL || nodesLoaded

  useEffect(() => {
    if (!ready) return
    let alive = true
    // Overlapping polls (a stalled tick resolving after a newer one) must not
    // replace fresh rows with older ones: only the latest request may land.
    let latest = 0
    const key = source
    if (renderedSource.current !== key) {
      setLines([])
      renderedSource.current = key
    }
    setLoading(true)
    const fetchLogs = () => {
      const id = ++latest
      return Promise.allSettled(
        sources.map((src) =>
          api.processLogs({ source: src, level: minLevel, search, limit: LIMIT }).then((r) => r.entries.map((e) => ({ ...e, src }))),
        ),
      ).then((results) => {
        if (!alive || id !== latest) return
        const ok = results.filter((r): r is PromiseFulfilledResult<Line[]> => r.status === 'fulfilled')
        const failed = results.find((r): r is PromiseRejectedResult => r.status === 'rejected')
        if (ok.length) {
          const merged = ok.flatMap((r) => r.value)
          merged.sort((a, b) => b.ts - a.ts || b.seq - a.seq)
          setLines(merged.slice(0, LIMIT))
        }
        setErr(failed ? (failed.reason instanceof Error ? failed.reason.message : String(failed.reason)) : '')
        setLoading(false)
      })
    }
    fetchLogs()
    const stop = following ? pollWhileVisible(fetchLogs, 5000) : () => {}
    return () => {
      alive = false
      stop()
    }
  }, [ready, source, sources, minLevel, search, following])

  const nameOf = (src: string) =>
    src === CONTROL_PLANE ? 'control' : nodes.find((n) => n.id === src)?.name || src.slice(0, 8)
  const shown = levels.length ? lines.filter((l) => levels.includes((LEVELS.includes(l.level as Level) ? l.level : 'info') as Level)) : lines
  const count = (l: Level) => lines.filter((x) => x.level === l).length
  const toggleLevel = (l: Level) => setLevels((cur) => (cur.includes(l) ? cur.filter((x) => x !== l) : [...cur, l]))
  const hasDebug = levels.includes('debug') || lines.some((l) => l.level === 'debug')
  const sourceNode = nodes.find((n) => n.id === source)
  const showSrc = source === ALL

  const download = () => {
    const text = shown
      .slice()
      .reverse()
      .map((l) => `${new Date(l.ts).toISOString()} ${l.level.toUpperCase().padEnd(5)} ${nameOf(l.src)} ${l.msg}`)
      .join('\n')
    const blob = new Blob([text + '\n'], { type: 'text/plain' })
    const a = document.createElement('a')
    a.href = URL.createObjectURL(blob)
    const who = source === ALL ? 'all' : nameOf(source)
    a.download = `mazedns-logs-${who}-${new Date().toISOString().slice(0, 19).replace(/[:T]/g, '-')}.log`
    a.click()
    setTimeout(() => URL.revokeObjectURL(a.href), 1000)
  }

  // Many agents don't fit a segmented control: fall back to a select.
  const useSelect = nodes.length > 4

  return (
    <div className="pg-logs">
      <header className="page-head">
        <h1>Logs</h1>
        {loading && <Spinner />}
        <span className="spacer" />
        <button
          className="btn quiet lg-follow"
          aria-pressed={following}
          onClick={() => setFollowing((f) => !f)}
          title={following ? 'Pause: stop fetching new lines' : 'Resume fetching new lines every 5 seconds'}
        >
          <span className={`dot ${following ? 'pulse' : 'off'}`} />
          {following ? 'Following new lines' : 'Paused'}
        </button>
        <button className="btn" onClick={download} disabled={shown.length === 0}>
          Download
        </button>
      </header>
      <p className="intro">
        Recent process logs from the control plane and every agent. They live in memory only, and agent lines arrive with
        the agent's next poll — up to 30 seconds late.
      </p>

      <div className="toolbar lg-toolbar">
        {useSelect ? (
          <select className="lg-source" value={source} onChange={(e) => setSource(e.target.value)} aria-label="Source">
            <option value={ALL}>All sources</option>
            <option value={CONTROL_PLANE}>Control plane</option>
            {nodes.map((n) => (
              <option key={n.id} value={n.id}>
                {n.name}
              </option>
            ))}
          </select>
        ) : (
          <div className="seg" role="group" aria-label="Source">
            <button className={source === ALL ? 'on' : ''} onClick={() => setSource(ALL)}>
              All sources
            </button>
            <button className={source === CONTROL_PLANE ? 'on' : ''} onClick={() => setSource(CONTROL_PLANE)}>
              Control plane
            </button>
            {nodes.map((n) => (
              <button key={n.id} className={source === n.id ? 'on' : ''} onClick={() => setSource(n.id)}>
                {n.name}
              </button>
            ))}
            {/* An agent linked by id that is no longer listed. */}
            {source !== ALL && source !== CONTROL_PLANE && nodesLoaded && !sourceNode && (
              <button className="on">{source.slice(0, 8)}</button>
            )}
          </div>
        )}
        <div className="lg-levels" role="group" aria-label="Levels">
          {LEVELS.filter((l) => l !== 'debug' || hasDebug).map((l) => {
            const n = count(l)
            const on = levels.includes(l)
            return (
              <button
                key={l}
                className={`chip${on ? ' on' : ''}`}
                aria-pressed={on}
                onClick={() => toggleLevel(l)}
                title={on ? 'Stop filtering on this level' : `Show ${CHIP_WORD[l].toLowerCase()}${levels.length ? ' too' : ' only'}`}
              >
                {l === 'warn' && <span className="dot warn" />}
                {l === 'error' && <span className="dot bad" />}
                {CHIP_WORD[l]}
                {(l === 'warn' || l === 'error') && n > 0 && <b>{n}</b>}
              </button>
            )
          })}
        </div>
        <span className="spacer" />
        <div className="lg-search">
          <input
            type="search"
            placeholder="Search log lines"
            value={input}
            onChange={(e) => setInput(e.target.value)}
            aria-label="Search log lines"
          />
        </div>
      </div>

      {err && (
        <div className="error" role="alert">
          {err}
        </div>
      )}

      <section className={`card flush lg-log${showSrc ? '' : ' no-src'}`}>
        {shown.map((l) => {
          const [msg, attrs] = splitMsg(l.msg)
          const lvl = LEVELS.includes(l.level as Level) ? l.level : 'info'
          return (
            <div className={`lg-line ${lvl}`} key={`${l.src}-${l.seq}-${l.ts}`}>
              <span className="lg-t" title={new Date(l.ts).toLocaleString()}>
                {new Date(l.ts).toLocaleTimeString([], { hour12: false })}
              </span>
              <span className={`lg-lvl ${lvl}`}>{LEVEL_WORD[l.level] || l.level}</span>
              {showSrc && <span className="lg-src">{nameOf(l.src)}</span>}
              <span className="lg-msg">
                {msg}
                {attrs && <span className="lg-k"> {attrs}</span>}
              </span>
            </div>
          )
        })}
        {shown.length === 0 && (
          <div className="lg-empty">
            {loading || err ? (
              loading && !err ? <Spinner label="Loading…" /> : null
            ) : search || levels.length ? (
              'No lines match these filters.'
            ) : source === CONTROL_PLANE || source === ALL ? (
              'No log lines yet.'
            ) : (
              `No lines received from ${sourceNode?.name ?? 'this agent'} yet. Agents ship logs on their poll cycle, and older agent versions don't ship them at all.`
            )}
          </div>
        )}
      </section>
      <p className="hint">
        Showing up to {LIMIT} lines{source === ALL ? ' across all sources' : ''}, newest first.
      </p>
    </div>
  )
}
