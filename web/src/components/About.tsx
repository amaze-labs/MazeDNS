import { useEffect, useState, type ReactNode } from 'react'
import { api, type Node, type Release, type UpdateStatus } from '../api'
import { agentOutdated, latestAgent } from '../agentVersion'
import Spinner from './Spinner'
import { SkelGroups } from './Skeleton'

// About & updates (Settings): the version this control plane runs, whether a
// newer release is out and what it changes, and the version every agent runs.

const IMAGE = 'ghcr.io/amaze-labs/mazedns-control-plane'

function ago(unixSec: number): string {
  const s = Math.max(0, Math.floor(Date.now() / 1000 - unixSec))
  if (s < 60) return 'just now'
  if (s < 3600) return `${Math.floor(s / 60)} min ago`
  if (s < 86400) return `${Math.floor(s / 3600)} h ago`
  const d = Math.floor(s / 86400)
  return `${d} ${d === 1 ? 'day' : 'days'} ago`
}

const day = (iso: string) =>
  iso ? new Date(iso).toLocaleDateString(undefined, { day: 'numeric', month: 'short', year: 'numeric' }) : ''

// Inline markdown of a release note line: **bold** and `code`.
function inline(text: string): ReactNode[] {
  const out: ReactNode[] = []
  const re = /(\*\*[^*]+\*\*|`[^`]+`)/g
  let last = 0
  let m: RegExpExecArray | null
  while ((m = re.exec(text))) {
    if (m.index > last) out.push(text.slice(last, m.index))
    const t = m[0]
    out.push(t.startsWith('**') ? <b key={m.index}>{t.slice(2, -2)}</b> : <code key={m.index}>{t.slice(1, -1)}</code>)
    last = m.index + t.length
  }
  if (last < text.length) out.push(text.slice(last))
  return out
}

// Notes renders the release notes the release workflow writes: "### Section"
// headings, "- item" bullets and plain lines. Nothing is injected as HTML.
function Notes({ md }: { md: string }) {
  const blocks: ReactNode[] = []
  let items: ReactNode[] = []
  const flush = () => {
    if (items.length) blocks.push(<ul key={`u${blocks.length}`}>{items}</ul>)
    items = []
  }
  md.split('\n').forEach((raw, i) => {
    const line = raw.trimEnd()
    if (/^#{1,6} /.test(line)) {
      flush()
      blocks.push(<h4 key={i}>{inline(line.replace(/^#+ /, ''))}</h4>)
    } else if (/^\s*[-*] /.test(line)) {
      items.push(<li key={i}>{inline(line.replace(/^\s*[-*] /, ''))}</li>)
    } else if (line.trim()) {
      flush()
      blocks.push(<p key={i}>{inline(line)}</p>)
    } else {
      flush()
    }
  })
  flush()
  return <div className="ab-notes">{blocks.length ? blocks : <p className="muted">No notes for this release.</p>}</div>
}

function ReleaseItem({ r, current }: { r: Release; current: string }) {
  return (
    <li className="ab-release">
      <div className="ab-release-head">
        <b className="mono">{r.version}</b>
        {r.version === current && <span className="tag info">Running</span>}
        {r.agent_build && r.agent_build !== r.version && (
          <span className="tag" title={`The agent image is ${r.agent_build}'s, with the new version`}>
            Control plane only
          </span>
        )}
        {r.control_plane_build && r.control_plane_build !== r.version && (
          <span className="tag" title={`The control plane image is ${r.control_plane_build}'s, with the new version`}>
            Agents only
          </span>
        )}
        <span className="muted small">{day(r.published_at)}</span>
        <span className="spacer" />
        {r.url && (
          <a className="small" href={r.url} target="_blank" rel="noreferrer">
            On GitHub
          </a>
        )}
      </div>
      <Notes md={r.notes} />
    </li>
  )
}

export default function About() {
  const [st, setSt] = useState<UpdateStatus | null>(null)
  const [err, setErr] = useState('')
  const [checking, setChecking] = useState(false)
  const [nodes, setNodes] = useState<Node[] | null>(null)
  const [agentBuild, setAgentBuild] = useState('')

  const load = async (refresh: boolean) => {
    setChecking(refresh)
    try {
      setSt(await api.updates(refresh))
      setErr('')
    } catch (e: any) {
      setErr(e.message)
    } finally {
      setChecking(false)
    }
  }
  useEffect(() => {
    load(false)
    api
      .clusterNodes()
      .then(setNodes)
      .catch(() => setNodes([]))
    api
      .serverVersion()
      .then((v) => setAgentBuild(v.agent_build ?? ''))
      .catch(() => {})
  }, [])

  // Agents grouped by the version they report.
  const byVersion = new Map<string, string[]>()
  for (const n of nodes ?? []) {
    if (!n.approved) continue
    const v = n.app_version || 'unknown'
    byVersion.set(v, [...(byVersion.get(v) ?? []), n.name])
  }
  const versions = [...byVersion.entries()].sort((a, b) => b[1].length - a[1].length)

  // The newest agent code: what this control plane ships with, or a later
  // release GitHub knows about.
  const newestAgent = latestAgent(agentBuild, st?.agent_latest)

  if (!st) {
    return err ? <div className="error">Couldn’t load the version: {err}</div> : <SkelGroups groups={2} />
  }

  const state = st.disabled
    ? { tone: '', text: 'Update checks are off' }
    : st.update_available
      ? { tone: 'warn', text: `Update available: ${st.latest}` }
      : st.comparable && st.latest
        ? { tone: 'ok', text: 'Up to date' }
        : !st.comparable
          ? { tone: '', text: 'Development build' }
          : { tone: '', text: 'Not checked yet' }

  return (
    <div className="pg-about">
      <section className="sg">
        <header>
          <h2>This control plane</h2>
          <p>The version it runs, and whether a newer release is out.</p>
        </header>
        <div className="sg-body">
          <div className={`ab-hero ${state.tone}`}>
            <div className="ab-hero-ver">
              <span className="muted small">Running</span>
              <b className="mono">{st.current}</b>
            </div>
            <span className={`tag ${state.tone}`}>
              {state.tone && <span className={`dot ${state.tone === 'ok' ? '' : state.tone}`} />}
              {state.text}
            </span>
            <span className="spacer" />
            {!st.disabled && (
              <button type="button" className="btn sm" onClick={() => load(true)} disabled={checking}>
                {checking ? <Spinner size={12} label="Checking…" /> : 'Check now'}
              </button>
            )}
          </div>
          <p className="hint">
            {st.disabled ? (
              <>
                Turned off with <code>MAZEDNS_UPDATE_CHECK=off</code>; releases are listed on GitHub.
              </>
            ) : (
              <>
                {st.latest && (
                  <>
                    Latest release <b className="mono">{st.latest}</b>
                    {st.releases[0]?.published_at && <>, {day(st.releases[0].published_at)}</>}.{' '}
                  </>
                )}
                {st.checked_at ? `Checked ${ago(st.checked_at)} from GitHub releases.` : 'Not checked yet.'}
                {st.error && <span className="bad-text"> Last check failed: {st.error}</span>}
              </>
            )}
          </p>
          {st.update_available && (
            <div className="callout warn">
              <div>
                <b>How to update</b>
                <p>
                  Pull <code>{`${IMAGE}:${st.latest}`}</code> (or <code>:latest</code>) and restart the control plane,
                  then update the agents to the same version if the agents below say so. Settings, rules and history stay
                  in the database.
                </p>
              </div>
            </div>
          )}
        </div>
      </section>

      {nodes && nodes.length > 0 && (
        <section className="sg">
          <header>
            <h2>Agents</h2>
            <p>
              The version each agent reports. A release rebuilds only what changed, so an agent on an earlier version
              is still current when the releases since then only changed the control plane.
            </p>
          </header>
          <div className="sg-body">
            <ul className="ab-agents">
              {versions.map(([v, names]) => (
                <li key={v}>
                  <b className="mono">{v}</b>
                  {agentOutdated(v === 'unknown' ? '' : v, st.current, newestAgent) ? (
                    <span className="tag warn">Update to {st.latest || st.current}</span>
                  ) : v === st.current ? (
                    <span className="tag ok">Same as the control plane</span>
                  ) : (
                    <span className="tag ok">Current</span>
                  )}
                  <span className="muted small ab-names">{names.join(', ')}</span>
                </li>
              ))}
            </ul>
            {newestAgent && (
              <p className="hint">
                The latest agent code is from <b className="mono">{newestAgent}</b>
                {st.latest && newestAgent !== st.latest && <> (the releases after it only changed the control plane)</>}.
                {st.update_available && versions.some(([v]) => agentOutdated(v === 'unknown' ? '' : v, st.current, newestAgent)) && (
                  <> Update the control plane to {st.latest} first, then the agents.</>
                )}
              </p>
            )}
          </div>
        </section>
      )}

      {st.releases.length > 0 && (
        <section className="sg">
          <header>
            <h2>{st.update_available ? 'What’s new' : 'Changelog'}</h2>
            <p>
              {st.update_available
                ? `Everything in the ${st.releases.length === 1 ? 'release' : `${st.releases.length} releases`} since ${st.current}.`
                : 'The latest releases.'}
            </p>
          </header>
          <div className="sg-body">
            <ol className="ab-releases">
              {st.releases.map((r) => (
                <ReleaseItem key={r.version} r={r} current={st.current} />
              ))}
            </ol>
          </div>
        </section>
      )}
    </div>
  )
}
