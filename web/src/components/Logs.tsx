import { useEffect, useRef, useState } from 'react'
import { api, type LogEntry, type Node } from '../api'
import { pollWhileVisible } from '../poll'
import Spinner from './Spinner'

const LEVELS = ['debug', 'info', 'warn', 'error']
const CONTROL_PLANE = 'control-plane'

// Badge tone per level, matching the query-log's action badge conventions.
const levelClass = (l: string) => (l === 'error' ? 'blocked' : l === 'warn' ? 'info' : 'allow')

// Logs shows recent process-log lines from the control plane and every agent.
// Rings are in-memory and bounded: history has `docker logs` semantics, and
// agent lines lag by up to one poll interval (~30s).
export default function Logs() {
  const [nodes, setNodes] = useState<Node[]>([])
  const [source, setSource] = useState(CONTROL_PLANE)
  const [level, setLevel] = useState('')
  const [input, setInput] = useState('')
  const [search, setSearch] = useState('')
  const [entries, setEntries] = useState<LogEntry[]>([])
  const [err, setErr] = useState('')
  const [loading, setLoading] = useState(true)
  // Which source the rendered rows belong to, so a source switch clears them
  // instead of showing the old machine's lines under the new selection.
  const renderedSource = useRef(source)

  useEffect(() => {
    api.clusterNodes().then(setNodes).catch(() => setNodes([]))
  }, [])

  // Debounce the search box.
  useEffect(() => {
    const t = setTimeout(() => setSearch(input.trim()), 400)
    return () => clearTimeout(t)
  }, [input])

  useEffect(() => {
    let alive = true
    // Overlapping polls (a stalled tick resolving after a newer one) must not
    // replace fresh rows with older ones: only the latest request may land.
    let latest = 0
    if (renderedSource.current !== source) {
      setEntries([])
      renderedSource.current = source
    }
    setLoading(true)
    const fetchLogs = () => {
      const id = ++latest
      return api
        .processLogs({ source, level, search, limit: 500 })
        .then((r) => {
          if (alive && id === latest) {
            setEntries(r.entries)
            setErr('')
            setLoading(false)
          }
        })
        .catch((e) => {
          if (alive && id === latest) {
            setErr(e.message)
            setLoading(false)
          }
        })
    }
    fetchLogs()
    const stop = pollWhileVisible(fetchLogs, 5000)
    return () => {
      alive = false
      stop()
    }
  }, [source, level, search])

  const sourceNode = nodes.find((n) => n.id === source)

  return (
    <div>
      <h2 style={{ display: 'flex', alignItems: 'center', gap: 10 }}>
        Logs {loading && <Spinner />}
      </h2>
      <p className="muted" style={{ textAlign: 'left' }}>
        Recent process logs from the control plane and each agent. Logs are kept in memory only
        (bounded, lost on restart); agent lines arrive with the agent's next poll, so they can lag
        by ~30s.
      </p>
      {err && <div className="error">{err}</div>}

      <div className="ql-filters" style={{ margin: '12px 0' }}>
        <select className="ql-select" value={source} onChange={(e) => setSource(e.target.value)}>
          <option value={CONTROL_PLANE}>Control plane</option>
          {nodes.map((n) => (
            <option key={n.id} value={n.id}>
              agent: {n.name}
            </option>
          ))}
        </select>
        <select className="ql-select" value={level} onChange={(e) => setLevel(e.target.value)}>
          <option value="">All levels</option>
          {LEVELS.map((l) => (
            <option key={l} value={l}>
              {l} and up
            </option>
          ))}
        </select>
        <input
          className="search"
          placeholder="search log lines…"
          value={input}
          onChange={(e) => setInput(e.target.value)}
        />
      </div>

      <div className="table-scroll">
        <table>
          <thead>
            <tr>
              <th style={{ width: 110 }}>Time</th>
              <th style={{ width: 70 }}>Level</th>
              <th>Message</th>
            </tr>
          </thead>
          <tbody>
            {entries.map((e) => (
              <tr key={`${e.seq}-${e.ts}`}>
                <td className="muted" style={{ whiteSpace: 'nowrap' }}>
                  {new Date(e.ts).toLocaleTimeString()}
                </td>
                <td>
                  <span className={`badge ${levelClass(e.level)}`}>{e.level}</span>
                </td>
                <td style={{ fontFamily: 'ui-monospace, monospace', fontSize: 12, wordBreak: 'break-word' }}>
                  {e.msg}
                </td>
              </tr>
            ))}
            {entries.length === 0 && !loading && (
              <tr>
                <td colSpan={3} className="muted">
                  {source === CONTROL_PLANE
                    ? 'No matching log lines'
                    : `No log lines received from ${sourceNode?.name ?? 'this agent'} yet — it ships logs on its poll cycle, and agents running an older version don't ship them at all.`}
                </td>
              </tr>
            )}
          </tbody>
        </table>
      </div>
      <p className="muted" style={{ textAlign: 'left', marginTop: 8 }}>
        Showing up to 500 lines, newest first.
      </p>
    </div>
  )
}
