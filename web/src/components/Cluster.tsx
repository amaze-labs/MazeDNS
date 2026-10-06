import { useCallback, useEffect, useRef, useState, type FormEvent, type ReactNode } from 'react'
import { api, type EnrollKey, type Node, type RevokedNode, type Site } from '../api'
import { pollWhileVisible } from '../poll'
import Modal from './Modal'
import Spinner from './Spinner'
import { useIsAdmin } from './ScopePicker'
import { useTable, Th, Pager, TableStatusRow, type SortAccessors } from './tableKit'
import '../styles/agents.css'

const ONLINE_WINDOW = 120 // seconds
const IMAGE = 'ghcr.io/amaze-labs/mazedns-agent:latest'
const RATE_HOURS = 1 // window behind the per-agent q/s and latency figures

const errMsg = (e: unknown) => (e instanceof Error ? e.message : String(e)) || 'Request failed'

function ago(unixSec: number): string {
  if (!unixSec) return 'never'
  const s = Math.max(0, Math.floor(Date.now() / 1000 - unixSec))
  if (s < 60) return `${s}s ago`
  if (s < 3600) return `${Math.floor(s / 60)}m ago`
  if (s < 86400) return `${Math.floor(s / 3600)}h ago`
  return `${Math.floor(s / 86400)}d ago`
}

function dateStr(unixSec: number): string {
  if (!unixSec) return '—'
  return new Date(unixSec * 1000).toLocaleString(undefined, { dateStyle: 'medium', timeStyle: 'short' })
}

function dayStr(unixSec: number): string {
  if (!unixSec) return '—'
  return new Date(unixSec * 1000).toLocaleDateString(undefined, { day: 'numeric', month: 'short', year: 'numeric' })
}

// until renders an expiry relative to now ("in 5 days", "in 3 hours") or the
// date once it has passed.
function until(unixSec: number): string {
  if (!unixSec) return 'never'
  const s = Math.floor(unixSec - Date.now() / 1000)
  if (s <= 0) return dayStr(unixSec)
  if (s < 3600) return `in ${Math.max(1, Math.round(s / 60))} min`
  if (s < 86400) return `in ${Math.round(s / 3600)} h`
  const d = Math.round(s / 86400)
  return `in ${d} ${d === 1 ? 'day' : 'days'}`
}

function CodeBlock({ label, text }: { label: string; text: string }) {
  const [copied, setCopied] = useState(false)
  const copy = async () => {
    try {
      await navigator.clipboard.writeText(text)
      setCopied(true)
      setTimeout(() => setCopied(false), 1500)
    } catch {
      /* clipboard unavailable */
    }
  }
  return (
    <div className="ag-code">
      <div className="ag-code-head">
        <span>{label}</span>
        <button type="button" className="btn sm quiet" onClick={copy}>
          {copied ? 'Copied' : 'Copy'}
        </button>
      </div>
      <pre>{text}</pre>
    </div>
  )
}

const ONLINE = (n: Node) => !!n.last_seen && Date.now() / 1000 - n.last_seen < ONLINE_WINDOW
const SERVING = (n: Node) => ONLINE(n) && n.approved && !n.maintenance
const BEHIND = (n: Node) => n.approved && !!n.expected_version && n.version !== n.expected_version

// statusOf summarises an agent's DNS state for the status dot + label.
function statusOf(n: Node): { dot: '' | 'off' | 'warn'; label: string } {
  if (!n.approved) return { dot: 'warn', label: 'Waiting for approval' }
  if (!ONLINE(n)) return { dot: 'off', label: 'Offline' }
  if (n.maintenance) return { dot: 'warn', label: 'In maintenance' }
  if (BEHIND(n)) return { dot: 'warn', label: 'Serving DNS, config behind' }
  return { dot: '', label: 'Serving DNS' }
}

// Advisory DNS roles within a site: primary answers first, secondary is the
// resolver clients fail over to, backup is the last resort.
const ROLES = ['primary', 'secondary', 'backup'] as const
const roleRank = (r: string) => (r === 'primary' ? 0 : r === 'secondary' ? 1 : r === 'backup' ? 2 : 3)
const roleLabel = (r: string) =>
  r === 'primary' ? 'Primary' : r === 'secondary' ? 'Secondary' : r === 'backup' ? 'Backup' : 'No role'
const nodeIP = (n: Node) => (n.address || '').replace(/:\d+$/, '')

// Sort accessors for the enrollment-keys table.
const ENROLL_COLS: SortAccessors<EnrollKey> = {
  name: (k) => k.name || k.key_prefix,
  status: (k) => k.status,
  expires: (k) => k.expires_at || Number.MAX_SAFE_INTEGER,
  uses: (k) => k.use_count,
  created: (k) => k.created_at,
}

// versionKnown reports whether the control plane has a comparable build version
// (local "dev" builds can't meaningfully flag anyone as outdated).
const versionKnown = (cp?: string) => !!cp && cp !== 'dev'
// outdated: the agent reports a build version different from the control plane's
// (or none at all — an agent from before version reporting is by definition old).
const outdated = (n: Node, cp?: string) => versionKnown(cp) && n.app_version !== cp

type CPVersion = { version: string; config_version: string }
type Rate = { qps?: number; ms?: number }

// Navigation to other pages goes through history + popstate, which App listens
// to (the same pattern ClientDetail uses for its "show queries" link).
function go(path: string) {
  window.history.pushState({}, '', path)
  window.dispatchEvent(new PopStateEvent('popstate'))
}
function showQueriesOf(n: Node) {
  // The Queries page restores its agent focus from this key on mount.
  try {
    localStorage.setItem('mazedns.ql.focus', JSON.stringify([n.name]))
  } catch {
    /* storage unavailable: the page opens unfiltered */
  }
  go('/queries')
}

export default function Cluster() {
  const isAdmin = useIsAdmin()
  const admin = isAdmin === true
  const adminRef = useRef(false)
  adminRef.current = admin

  const [nodes, setNodes] = useState<Node[]>([])
  const [sites, setSites] = useState<Site[]>([])
  const [enrollKeys, setEnrollKeys] = useState<EnrollKey[]>([])
  const [keysLoaded, setKeysLoaded] = useState(false)
  const [revoked, setRevoked] = useState<RevokedNode[]>([])
  const [rates, setRates] = useState<Record<string, Rate>>({})
  // Set on the first successful load; polling refreshes never clear it.
  const [loaded, setLoaded] = useState(false)
  const [err, setErr] = useState('') // agents/sites load + page-level actions
  const [keysErr, setKeysErr] = useState('') // enrollment keys load + actions
  const [revokedErr, setRevokedErr] = useState('')
  const [cpVer, setCpVer] = useState<CPVersion | null>(null)

  const [newKey, setNewKey] = useState<{ name: string; key: string } | null>(null)
  const [newEnrollKey, setNewEnrollKey] = useState<{ name: string; key: string } | null>(null)
  const [selected, setSelected] = useState<string | null>(null) // agent id whose drawer is open
  const [addingSite, setAddingSite] = useState(false)
  const [deployOpen, setDeployOpen] = useState(false)
  const [pendingBusy, setPendingBusy] = useState('')
  const [pendingErr, setPendingErr] = useState<{ id: string; msg: string } | null>(null)

  // Agents, sites and the version are readable by everyone; enrollment keys and
  // revoked agents are admin-only, so they load separately and only for admins
  // (a readonly user would get 403 and must still see the agents).
  const loadCore = useCallback(async () => {
    const [n, s, v] = await Promise.allSettled([api.clusterNodes(), api.clusterSites(), api.serverVersion()])
    if (n.status === 'fulfilled') {
      setNodes(n.value)
      setLoaded(true)
      setErr('')
    } else {
      setErr(errMsg(n.reason))
    }
    if (s.status === 'fulfilled') setSites(s.value)
    if (v.status === 'fulfilled') setCpVer(v.value)
  }, [])
  const loadAdmin = useCallback(async () => {
    if (!adminRef.current) return
    const [k, rv] = await Promise.allSettled([api.enrollKeys(), api.listRevoked()])
    if (k.status === 'fulfilled') {
      setEnrollKeys(k.value)
      setKeysLoaded(true)
      setKeysErr('')
    } else setKeysErr(errMsg(k.reason))
    if (rv.status === 'fulfilled') {
      setRevoked(rv.value)
      setRevokedErr('')
    } else setRevokedErr(errMsg(rv.reason))
  }, [])
  const load = useCallback(() => Promise.all([loadCore(), loadAdmin()]).then(() => undefined), [loadCore, loadAdmin])

  // Per-agent query rate and latency over the last hour (from the same rollups
  // the overview charts use). Best effort: the rows simply omit them on failure.
  const loadRates = useCallback(async () => {
    const [ins, lat] = await Promise.allSettled([api.insights(RATE_HOURS), api.latency(RATE_HOURS)])
    const next: Record<string, Rate> = {}
    if (ins.status === 'fulfilled') {
      for (const b of ins.value.by_node) next[b.node] = { qps: b.total / (RATE_HOURS * 3600) }
    }
    if (lat.status === 'fulfilled') {
      const sums: Record<string, { s: number; c: number }> = {}
      for (const p of lat.value.points) {
        for (const [name, ms] of Object.entries(p.by_node)) {
          if (!ms) continue
          const a = (sums[name] ||= { s: 0, c: 0 })
          a.s += ms
          a.c++
        }
      }
      for (const [name, a] of Object.entries(sums)) next[name] = { ...next[name], ms: a.s / a.c }
    }
    setRates(next)
  }, [])

  useEffect(() => {
    loadCore()
    return pollWhileVisible(load, 10000)
  }, [loadCore, load])
  useEffect(() => {
    if (admin) loadAdmin()
  }, [admin, loadAdmin])
  useEffect(() => {
    loadRates()
    return pollWhileVisible(loadRates, 30000)
  }, [loadRates])

  // ---- actions ----
  const issueManualKey = async (name: string) => {
    const r = await api.addNode(name)
    setNewKey(r)
    load()
  }

  // Agent actions are used from the agent drawer, which shows their errors next
  // to the control that failed, so they throw instead of calling setErr.
  // Cancelling a confirm is not an error. The drawer only closes once a removal
  // has actually succeeded.
  const del = async (n: Node, revoke: boolean) => {
    const msg = revoke
      ? `Remove and revoke agent “${n.name}”? Its identity is tombstoned so the running agent cannot rejoin the cluster — it keeps serving DNS standalone until you stop it or un-revoke.`
      : `Remove agent “${n.name}” only? A still-running agent may re-enroll as a NEW node. Use this for intentional replacement.`
    if (!window.confirm(msg)) return
    await api.deleteNode(n.id, revoke)
    if (newKey?.name === n.name) setNewKey(null)
    setSelected((s) => (s === n.id ? null : s))
    load()
  }

  const unrevoke = async (r: RevokedNode) => {
    if (!window.confirm(`Un-revoke “${r.name || r.id}”? Its agent can rejoin (as a new node) on its next attempt.`)) return
    try {
      await api.unrevokeNode(r.id)
      setRevokedErr('')
      load()
    } catch (e) {
      setRevokedErr(errMsg(e))
    }
  }

  const purgeRevoked = async (r: RevokedNode) => {
    const msg =
      `Permanently delete revoked agent “${r.name || r.id}”? ` +
      `Its record disappears from this list and cannot be restored. If the agent is still running somewhere, ` +
      `it is no longer blocked — but rejoining still requires a valid enrollment key.`
    if (!window.confirm(msg)) return
    try {
      await api.purgeRevokedNode(r.id)
      setRevokedErr('')
      load()
    } catch (e) {
      setRevokedErr(errMsg(e))
    }
  }

  const renew = async (n: Node) => {
    if (!window.confirm(`Rotate the key for “${n.name}”? The running agent adopts the new key on its next poll.`)) return
    const r = await api.renewNodeKey(n.id)
    setNewKey({ name: n.name, key: r.key })
    load()
  }

  // rename validation (non-empty, not reserved, not used by another live node)
  // is the backend's; its message is shown next to the drawer's rename field.
  const rename = async (n: Node, name: string) => {
    await api.renameNode(n.id, name)
    await load() // refresh before the field closes so the new name shows at once
  }

  const approve = async (n: Node) => {
    await api.approveNode(n.id, !n.approved)
    load()
  }

  const toggleMaintenance = async (n: Node) => {
    const on = !n.maintenance
    if (on && !window.confirm(`Put “${n.name}” into maintenance? It stops serving DNS (SERVFAIL) so clients fail over to another agent.`)) return
    await api.setNodeMaintenance(n.id, on)
    load()
  }

  const assignSite = async (n: Node, site: string, role: string) => {
    await api.setNodeSite(n.id, site, role)
    load()
  }

  // Approve / reject straight from the "wants to join" card.
  const pendingAction = async (n: Node, what: 'approve' | 'reject') => {
    if (what === 'reject') {
      const msg = `Reject “${n.name}”? It is removed and its identity revoked, so this agent can't join again unless you un-revoke it.`
      if (!window.confirm(msg)) return
    }
    setPendingBusy(n.id)
    setPendingErr(null)
    try {
      if (what === 'approve') await api.approveNode(n.id, true)
      else await api.deleteNode(n.id, true)
      load()
    } catch (e) {
      setPendingErr({ id: n.id, msg: errMsg(e) })
    } finally {
      setPendingBusy('')
    }
  }

  const createSite = async (name: string, description: string) => {
    await api.createSite(name, description)
    load()
  }
  const delSite = async (name: string) => {
    if (!window.confirm(`Delete site “${name}”? Its agents are unassigned (they keep serving DNS).`)) return
    try {
      await api.deleteSite(name)
      setErr('')
      load()
    } catch (e) {
      setErr(errMsg(e))
    }
  }

  // Throws so the form that called it can keep its input and show the error.
  const createEnrollKey = async (name: string, ttlHours: number, maxUses: number) => {
    const r = await api.createEnrollKey(name, ttlHours, maxUses)
    setNewEnrollKey({ name: r.name || r.key_prefix, key: r.key })
    loadAdmin()
  }
  const revokeEnrollKey = async (k: EnrollKey) => {
    if (!window.confirm(`Revoke enrollment key “${k.name || k.key_prefix}”? Agents can no longer join with it.`)) return
    try {
      await api.revokeEnrollKey(k.id)
      setKeysErr('')
      loadAdmin()
    } catch (e) {
      setKeysErr(errMsg(e))
    }
  }
  const deleteEnrollKey = async (k: EnrollKey) => {
    if (!window.confirm(`Permanently delete ${k.status} enrollment key “${k.name || k.key_prefix}”? This cannot be undone.`)) return
    try {
      await api.deleteEnrollKey(k.id)
      setKeysErr('')
      loadAdmin()
    } catch (e) {
      setKeysErr(errMsg(e))
    }
  }

  const closeAgent = useCallback(() => setSelected(null), [])
  const closeSite = useCallback(() => setAddingSite(false), [])
  const closeDeploy = useCallback(() => setDeployOpen(false), [])

  // ---- derived ----
  const serving = nodes.filter(SERVING).length
  const behind = nodes.filter(BEHIND).length
  const pending = nodes.filter((n) => !n.approved).sort((a, b) => b.created_at - a.created_at)
  const admitted = nodes.filter((n) => n.approved)
  const sitesInUse = Array.from(new Set([...sites.map((s) => s.name), ...nodes.map((n) => n.site).filter(Boolean)])).sort()
  const byRole = (a: Node, b: Node) => roleRank(a.role) - roleRank(b.role) || a.name.localeCompare(b.name)
  const membersOf = (site: string) => admitted.filter((n) => n.site === site).sort(byRole)
  const unassigned = admitted.filter((n) => !n.site).sort((a, b) => a.name.localeCompare(b.name))
  const selectedNode = selected ? nodes.find((n) => n.id === selected) || null : null
  const stale = admitted.filter((n) => outdated(n, cpVer?.version))

  const agentRow = (n: Node) => (
    <AgentRow
      key={n.id}
      node={n}
      rate={rates[n.name]}
      cp={cpVer?.version}
      selected={selected === n.id}
      onOpen={() => setSelected(n.id)}
    />
  )

  return (
    <div className="pg-agents">
      <header className="page-head">
        <h1>Agents</h1>
        <span className="spacer" />
        {admin && (
          <>
            <button className="btn" onClick={() => setAddingSite(true)}>
              Add a site
            </button>
            <button className="btn primary" onClick={() => setDeployOpen(true)}>
              Add an agent
            </button>
          </>
        )}
      </header>
      <p className="intro">
        Agents answer DNS for your clients and copy their settings from this control plane, which doesn't answer DNS
        itself. They keep resolving from their last copy if the control plane goes away.
      </p>
      {err && (
        <div className="error" role="alert">
          {err}
        </div>
      )}

      {/* "—" until loaded: a zero "serving DNS" figure would raise a false alarm. */}
      <div className="strip ag-strip">
        <div>
          <b className={loaded && nodes.length > 0 && serving === 0 ? 'bad' : ''}>
            {loaded ? serving : '—'}
            {loaded && <small> of {nodes.length}</small>}
          </b>
          <span>agents serving DNS</span>
        </div>
        <div>
          <b>{loaded ? sitesInUse.length : '—'}</b>
          <span>{sitesInUse.length === 1 ? 'site' : 'sites'}</span>
        </div>
        <div>
          <b className={behind > 0 ? 'warn' : ''}>{loaded ? behind : '—'}</b>
          <span>{behind === 1 ? 'agent' : 'agents'} behind on config</span>
        </div>
        <div>
          <b className="ag-ver">{cpVer?.version || '—'}</b>
          <span>
            control plane
            {cpVer?.config_version && (
              <>
                , config <span className="mono">{cpVer.config_version.slice(0, 6)}</span>
              </>
            )}
          </span>
        </div>
      </div>

      {stale.length > 0 && (
        <div className="callout warn">
          <div>
            <b>
              {stale.length === 1 ? '1 agent runs' : `${stale.length} agents run`} a different version than the control
              plane ({cpVer!.version})
            </b>
            <p>
              Update {stale.length === 1 ? 'its container image' : 'their container images'}:{' '}
              {stale.map((n) => n.name).join(', ')}.
            </p>
          </div>
        </div>
      )}

      {pending.map((n) => (
        <section className="card ag-pending" key={n.id}>
          <span className="dot warn pulse" />
          <div className="ag-pending-text">
            <b>
              <button className="linklike ag-name-link" onClick={() => setSelected(n.id)}>
                {n.name}
              </button>{' '}
              wants to join
            </b>
            <div className="muted small">
              {nodeIP(n) ? (
                <>
                  Enrolled from <span className="mono">{nodeIP(n)}</span>, {ago(n.created_at)}.
                </>
              ) : (
                <>Enrolled {ago(n.created_at)}.</>
              )}{' '}
              {admin ? "It won't serve DNS until you approve it." : "It won't serve DNS until an administrator approves it."}
            </div>
            {pendingErr?.id === n.id && (
              <div className="error ag-inline-err" role="alert">
                {pendingErr.msg}
              </div>
            )}
          </div>
          {admin && (
            <div className="ag-pending-actions">
              <button className="btn primary" disabled={pendingBusy === n.id} onClick={() => pendingAction(n, 'approve')}>
                Approve
              </button>
              <button className="btn danger" disabled={pendingBusy === n.id} onClick={() => pendingAction(n, 'reject')}>
                Reject
              </button>
            </div>
          )}
        </section>
      ))}

      {!loaded ? (
        !err && <Spinner label="Loading…" />
      ) : nodes.length === 0 && sitesInUse.length === 0 ? (
        <section className="card ag-empty">
          <h2>No agents yet</h2>
          <p className="muted">
            Agents do the resolving. {admin ? 'Create an enrollment key and start one with it — ' : ''}
            {admin ? (
              <button className="linklike" onClick={() => setDeployOpen(true)}>
                see how to add an agent
              </button>
            ) : (
              'An administrator can add one.'
            )}
          </p>
        </section>
      ) : (
        <div className="ag-sites">
          {sitesInUse.map((site) => {
            const members = membersOf(site)
            const desc = sites.find((s) => s.name === site)?.description
            return (
              <section className="card ag-site" key={site}>
                <div className="ag-site-head">
                  <h2>{site}</h2>
                  <small>
                    {members.length} {members.length === 1 ? 'agent' : 'agents'}
                    {members.length > 1 && ' · clients fail over in this order'}
                  </small>
                  <span className="spacer" />
                  {admin && (
                    <button className="btn sm quiet ag-site-del" onClick={() => delSite(site)} title={`Delete site ${site}`}>
                      Delete
                    </button>
                  )}
                </div>
                {desc && <p className="ag-site-desc">{desc}</p>}
                <div className="ag-list">
                  {members.map(agentRow)}
                  {members.length === 0 && (
                    <p className="muted small ag-list-empty">
                      No agents here yet{admin ? '. Open an agent and pick this site.' : '.'}
                    </p>
                  )}
                </div>
              </section>
            )
          })}
          {unassigned.length > 0 && (
            <section className="card ag-site ag-unassigned">
              <div className="ag-site-head">
                <h2>Not in a site</h2>
                <small>
                  {unassigned.length} {unassigned.length === 1 ? 'agent' : 'agents'}
                </small>
              </div>
              {sitesInUse.length === 0 && (
                <p className="ag-site-desc">
                  Group agents into sites and give each a role (primary, secondary, backup) to record the order clients
                  fail over in. Roles are advisory: every agent serves DNS.
                </p>
              )}
              <div className="ag-list">{unassigned.map(agentRow)}</div>
            </section>
          )}
        </div>
      )}

      {admin && (
        <>
          <h2 className="section">Enrollment keys</h2>
          <p className="section">
            A new agent presents one of these once to join, as <code>MAZEDNS_JOIN_TOKEN</code>. Keys only enroll — they
            never serve DNS — and the secret is shown only when you create it.
          </p>
          <section className="card flush ag-keys">
            <EnrollKeyForm onCreate={createEnrollKey} />
            {newEnrollKey && <NewEnrollKey created={newEnrollKey} onDismiss={() => setNewEnrollKey(null)} />}
            {keysErr && (
              <div className="error ag-card-err" role="alert">
                {keysErr}
              </div>
            )}
            <EnrollKeysTable
              keys={enrollKeys}
              loading={!keysLoaded}
              error={keysErr}
              onRevoke={revokeEnrollKey}
              onDelete={deleteEnrollKey}
            />
          </section>

          {(revoked.length > 0 || revokedErr) && (
            <>
              <h2 className="section">Revoked agents</h2>
              <p className="section">
                These identities are tombstoned: their agents are refused when they try to rejoin. Un-revoke lets one
                rejoin as a new agent on its next attempt; delete removes the record for good.
              </p>
              {revokedErr && (
                <div className="error" role="alert">
                  {revokedErr}
                </div>
              )}
              {revoked.length > 0 && (
                <section className="card flush">
                  <div className="table-scroll">
                    <table className="stackable">
                      <thead>
                        <tr>
                          <th>Agent</th>
                          <th className="hide-sm">ID</th>
                          <th>Revoked</th>
                          <th></th>
                        </tr>
                      </thead>
                      <tbody>
                        {revoked.map((r) => (
                          <tr key={r.id}>
                            <td className="lead">{r.name || <span className="muted">unnamed</span>}</td>
                            <td className="hide-sm">
                              <span className="mono muted">{r.id}</span>
                            </td>
                            <td>
                              {r.revoked_at ? dateStr(r.revoked_at) : '—'}
                              {r.revoked_by && <span className="muted"> by {r.revoked_by}</span>}
                            </td>
                            <td className="actions">
                              <button className="btn sm" onClick={() => unrevoke(r)}>
                                Un-revoke
                              </button>
                              <button className="btn sm danger" onClick={() => purgeRevoked(r)}>
                                Delete
                              </button>
                            </td>
                          </tr>
                        ))}
                      </tbody>
                    </table>
                  </div>
                </section>
              )}
            </>
          )}
        </>
      )}

      {addingSite && <AddSiteDialog onClose={closeSite} onCreate={createSite} />}

      {deployOpen && (
        <DeployDrawer
          onClose={closeDeploy}
          enrollKey={newEnrollKey}
          onCreateKey={createEnrollKey}
          manualKey={newKey}
          onIssueManualKey={issueManualKey}
        />
      )}

      {selectedNode && (
        <AgentDrawer
          key={selectedNode.id}
          node={selectedNode}
          admin={admin}
          rate={rates[selectedNode.name]}
          cpVer={cpVer}
          sites={sitesInUse}
          newKey={newKey?.name === selectedNode.name ? newKey : null}
          onClose={closeAgent}
          onApprove={() => approve(selectedNode)}
          onMaintenance={() => toggleMaintenance(selectedNode)}
          onRenew={() => renew(selectedNode)}
          onRename={(name) => rename(selectedNode, name)}
          onDelete={(revoke) => del(selectedNode, revoke)}
          onAssign={(site, role) => assignSite(selectedNode, site, role)}
        />
      )}
    </div>
  )
}

const fmtRate = (q?: number) => (q === undefined ? null : q >= 10 ? q.toFixed(0) : q >= 1 ? q.toFixed(1) : q.toFixed(2))
const fmtMs = (ms?: number) => (ms === undefined ? null : ms >= 10 ? ms.toFixed(0) : ms.toFixed(1))

// SyncText describes whether the agent runs the config the control plane expects.
function syncText(n: Node): { text: string; warn: boolean } {
  if (!n.approved) return { text: 'waiting for approval', warn: true }
  if (!n.version) return { text: 'no config yet', warn: true }
  if (BEHIND(n)) return { text: 'config behind', warn: true }
  return { text: 'in sync', warn: false }
}

function AgentRow({
  node: n,
  rate,
  cp,
  selected,
  onOpen,
}: {
  node: Node
  rate?: Rate
  cp?: string
  selected: boolean
  onOpen: () => void
}) {
  const st = statusOf(n)
  const sync = syncText(n)
  const ip = nodeIP(n)
  const qps = fmtRate(rate?.qps)
  const ms = fmtMs(rate?.ms)
  return (
    <div
      className={`ag-agent${selected ? ' sel' : ''}`}
      role="button"
      tabIndex={0}
      onClick={onOpen}
      onKeyDown={(e) => {
        if (e.key === 'Enter' || e.key === ' ') {
          e.preventDefault()
          onOpen()
        }
      }}
      aria-label={`${n.name}: ${st.label}`}
    >
      <span className={`dot ${st.dot}`} title={st.label} />
      <div className="ag-agent-main">
        <div className="ag-agent-name">{n.name}</div>
        <div className="ag-agent-role">
          {n.site ? roleLabel(n.role) : st.label}
          {ip && (
            <>
              {' · '}
              <span className="mono">{ip}</span>
            </>
          )}
        </div>
      </div>
      <div className="ag-agent-num" title={`Average over the last ${RATE_HOURS === 1 ? 'hour' : `${RATE_HOURS} hours`}`}>
        {qps !== null ? `${qps} q/s` : <span className="muted">{n.total.toLocaleString()} queries</span>}
        {ms !== null && <small>{ms} ms</small>}
      </div>
      <div className="ag-agent-meta">
        {n.maintenance && <span className="warn-text">maintenance</span>}
        {!ONLINE(n) && n.approved && <span className="bad-text">offline</span>}
        <span className={sync.warn ? 'warn-text' : ''}>{sync.text}</span>
        <span>
          {n.app_version || 'version unknown'}
          {n.app_version && outdated(n, cp) && <span className="warn-text"> · update available</span>}
        </span>
        <span>seen {ago(n.last_seen)}</span>
      </div>
    </div>
  )
}

function AddSiteDialog({ onClose, onCreate }: { onClose: () => void; onCreate: (name: string, desc: string) => Promise<void> }) {
  const [name, setName] = useState('')
  const [desc, setDesc] = useState('')
  const [busy, setBusy] = useState(false)
  const [err, setErr] = useState('')
  const field = useRef<HTMLInputElement>(null)
  useEffect(() => {
    const t = setTimeout(() => field.current?.focus(), 0)
    return () => clearTimeout(t)
  }, [])
  const submit = async (e?: FormEvent) => {
    e?.preventDefault()
    if (!name.trim() || busy) return
    setBusy(true)
    setErr('')
    try {
      await onCreate(name.trim(), desc.trim())
      onClose()
    } catch (e) {
      setErr(errMsg(e))
      setBusy(false)
    }
  }
  return (
    <Modal
      kind="dialog"
      title="Add a site"
      onClose={onClose}
      footer={
        <>
          <span className="spacer" />
          <button className="btn ghost" onClick={onClose} disabled={busy}>
            Cancel
          </button>
          <button className="btn primary" onClick={() => submit()} disabled={busy || !name.trim()}>
            {busy ? 'Adding…' : 'Add site'}
          </button>
        </>
      }
    >
      <form className="ag-form" onSubmit={submit}>
        <p className="muted">
          A site groups the agents that serve one network. Give each agent a role in it — primary, secondary, backup —
          to record the order clients fail over in.
        </p>
        <label className="field">
          <span>Name</span>
          <input ref={field} placeholder="office-london" value={name} onChange={(e) => setName(e.target.value)} />
        </label>
        <label className="field">
          <span>
            Description <span className="muted">(optional)</span>
          </span>
          <input placeholder="London office, floor 2" value={desc} onChange={(e) => setDesc(e.target.value)} />
        </label>
        {err && (
          <div className="error" role="alert">
            {err}
          </div>
        )}
        <button type="submit" hidden />
      </form>
    </Modal>
  )
}

// DeployDrawer: how to start a new agent (the former "Deploy a DNS agent"
// reference section), with the newest enrollment key filled into the commands.
function DeployDrawer({
  onClose,
  enrollKey,
  onCreateKey,
  manualKey,
  onIssueManualKey,
}: {
  onClose: () => void
  enrollKey: { name: string; key: string } | null
  onCreateKey: (name: string, ttlHours: number, maxUses: number) => Promise<void>
  manualKey: { name: string; key: string } | null
  onIssueManualKey: (name: string) => Promise<void>
}) {
  const [manualName, setManualName] = useState('')
  const [manualBusy, setManualBusy] = useState(false)
  const [manualErr, setManualErr] = useState('')

  const cpHost = window.location.hostname || '<control-plane-host>'
  const cpURL = `${window.location.protocol}//${cpHost}${window.location.port ? ':' + window.location.port : ''}`
  const enrollSecret = enrollKey?.key || '<enrollment-key>'
  // Host networking is the recommended deployment: the resolver sees each
  // client's real source IP (per-client stats) and the control plane records the
  // node's real host IP instead of a docker bridge address (e.g. 172.18.0.2).
  // Under host networking compose/docker DNS is unavailable, so the control
  // plane's IP must be pinned with MAZEDNS_CP_IP. The HTTP API moves to :9090 in
  // case :8080 is already taken on the host.
  const cpIP = '<control-plane-ip>'
  const bridgeAlt = `# Prefer bridge networking instead? Drop --network host and publish the ports:
#   -p 53:53/udp -p 53:53/tcp -p 9090:8080
# (Note: the dashboard then shows the docker bridge IP for clients and this node.)`
  const joinRun = `docker run -d --name mazedns-agent --restart unless-stopped \\
  --network host \\
  -e MAZEDNS_CP_URL=${cpURL} \\
  -e MAZEDNS_CP_IP=${cpIP} \\
  -e MAZEDNS_JOIN_TOKEN=${enrollSecret} \\
  -e MAZEDNS_NODE_NAME=site-a-1 \\
  -e MAZEDNS_DB_PATH=/data/mazedns.db \\
  -e MAZEDNS_API_ADDRESS=0.0.0.0 \\
  -e MAZEDNS_API_PORT=9090 \\
  -v mazedns-agent-data:/data \\
  ${IMAGE}
${bridgeAlt}`
  const joinCompose = `services:
  dns-agent:
    image: ${IMAGE}
    restart: unless-stopped
    network_mode: host          # recommended: real client IPs + real node IP
    environment:
      MAZEDNS_CP_URL: "${cpURL}"
      MAZEDNS_CP_IP: "${cpIP}"  # required: pins the control-plane IP (no docker DNS under host networking)
      MAZEDNS_JOIN_TOKEN: "${enrollSecret}"
      MAZEDNS_NODE_NAME: "site-a-1"
      MAZEDNS_DB_PATH: "/data/mazedns.db"
      MAZEDNS_API_ADDRESS: "0.0.0.0"
      MAZEDNS_API_PORT: "9090"  # agent /metrics + /healthz (keeps :8080 free on the host)
    volumes:
      - mazedns-agent-data:/data
    # Prefer bridge networking instead? Remove network_mode + MAZEDNS_CP_IP +
    # MAZEDNS_API_PORT and publish the ports (the dashboard then shows the
    # docker bridge IP for clients and this node):
    # ports:
    #   - "53:53/udp"
    #   - "53:53/tcp"
    #   - "9090:8080"
volumes:
  mazedns-agent-data:`
  const manualRun = manualKey
    ? `docker run -d --name mazedns-${manualKey.name} --restart unless-stopped \\
  --network host \\
  -e MAZEDNS_CP_URL=${cpURL} \\
  -e MAZEDNS_CP_IP=${cpIP} \\
  -e MAZEDNS_NODE_KEY=${manualKey.key} \\
  -e MAZEDNS_NODE_NAME=${manualKey.name} \\
  -e MAZEDNS_DB_PATH=/data/mazedns.db \\
  -e MAZEDNS_API_ADDRESS=0.0.0.0 \\
  -e MAZEDNS_API_PORT=9090 \\
  -v mazedns-${manualKey.name}-data:/data \\
  ${IMAGE}
${bridgeAlt}`
    : ''

  const issue = async (e: FormEvent) => {
    e.preventDefault()
    if (!manualName.trim() || manualBusy) return
    setManualBusy(true)
    setManualErr('')
    try {
      await onIssueManualKey(manualName.trim())
      setManualName('')
    } catch (e) {
      setManualErr(errMsg(e))
    } finally {
      setManualBusy(false)
    }
  }

  return (
    <Modal title="Add an agent" eyebrow="Deploy a DNS agent" onClose={onClose} size="wide">
      <section className="ag-step">
        <h3>1. Get an enrollment key</h3>
        <p className="muted">
          Agents join with an enrollment key passed as <code>MAZEDNS_JOIN_TOKEN</code>; the secret is only shown when the
          key is created.{' '}
          {enrollKey
            ? `The commands below use the key “${enrollKey.name}” you just created.`
            : 'Create one here and it is filled into the commands below, or paste an existing key in its place.'}
        </p>
        {!enrollKey && <EnrollKeyForm onCreate={onCreateKey} compact />}
      </section>

      <section className="ag-step">
        <h3>2. Start the agent</h3>
        <p className="muted">
          Run the agent image on the machine that should answer DNS. It appears on this page by itself — set{' '}
          <code>MAZEDNS_REQUIRE_APPROVAL=true</code> on the control plane to hold new agents until you approve them.
          After joining, each agent authenticates with its own key, which the control plane rotates automatically.
        </p>
        <CodeBlock label="docker run" text={joinRun} />
        <CodeBlock label="docker compose" text={joinCompose} />
      </section>

      <section className="ag-step">
        <h3>Keep the /data volume</h3>
        <p className="muted">
          It stores the agent's identity (its ID and rotating key), so a recreated container rejoins at once as the same
          agent. If the volume is lost anyway, a stable <code>MAZEDNS_NODE_NAME</code> is the safety net: once the old
          container stops polling (about 2 minutes) the new one reclaims the same agent — its history, site and role —
          instead of appearing as a duplicate.
        </p>
      </section>

      <details className="ag-manual">
        <summary>Prefer a fixed per-agent key? Issue one manually</summary>
        <form className="ag-inline-form" onSubmit={issue}>
          <label className="field">
            <span>Agent name</span>
            <input placeholder="site-b" value={manualName} onChange={(e) => setManualName(e.target.value)} />
          </label>
          <button type="submit" className="btn" disabled={manualBusy || !manualName.trim()}>
            {manualBusy ? 'Issuing…' : 'Issue key'}
          </button>
        </form>
        {manualErr && (
          <div className="error" role="alert">
            {manualErr}
          </div>
        )}
        {manualKey && (
          <>
            <div className="ok-msg">
              <span>
                <b>Key for “{manualKey.name}”, shown once.</b> Set it as <code>MAZEDNS_NODE_KEY</code> on the agent.
              </span>
            </div>
            <CodeBlock label="docker run" text={manualRun} />
          </>
        )}
      </details>
    </Modal>
  )
}

function AgentDrawer({
  node,
  admin,
  rate,
  cpVer,
  sites,
  newKey,
  onClose,
  onApprove,
  onMaintenance,
  onRenew,
  onRename,
  onDelete,
  onAssign,
}: {
  node: Node
  admin: boolean
  rate?: Rate
  cpVer: CPVersion | null
  sites: string[]
  newKey: { name: string; key: string } | null
  onClose: () => void
  onApprove: () => Promise<void>
  onMaintenance: () => Promise<void>
  onRenew: () => Promise<void>
  onRename: (name: string) => Promise<void>
  onDelete: (revoke: boolean) => Promise<void>
  onAssign: (site: string, role: string) => Promise<void>
}) {
  // Errors are kept per action and shown next to the control that failed.
  // State lives in the drawer, so it is dropped when the drawer closes.
  const [actionErr, setActionErr] = useState<{ at: string; msg: string } | null>(null)
  const [busy, setBusy] = useState('')
  const run = async (at: string, fn: () => Promise<void>) => {
    setActionErr(null)
    setBusy(at)
    try {
      await fn()
    } catch (e) {
      setActionErr({ at, msg: errMsg(e) })
    } finally {
      setBusy('')
    }
  }
  const errFor = (at: string) =>
    actionErr?.at === at ? (
      <div className="error ag-inline-err" role="alert">
        {actionErr.msg}
      </div>
    ) : null

  // Inline rename: the Rename row turns into a field pre-filled with the name.
  const [renaming, setRenaming] = useState(false)
  const [draft, setDraft] = useState('')
  const startRename = () => {
    setDraft(node.name)
    setActionErr(null)
    setRenaming(true)
  }
  const cancelRename = () => {
    setRenaming(false)
    if (actionErr?.at === 'rename') setActionErr(null)
  }
  const saveRename = (e: FormEvent) => {
    e.preventDefault()
    const next = draft.trim()
    if (next === node.name) {
      cancelRename()
      return
    }
    run('rename', async () => {
      await onRename(next)
      setRenaming(false)
    })
  }

  const st = statusOf(node)
  const pct = node.total > 0 ? (node.blocked / node.total) * 100 : 0
  const ms = fmtMs(rate?.ms)
  const breakdown: { label: string; value: number; k: string }[] = [
    { label: 'Cached', value: node.cached, k: 'var(--cache)' },
    { label: 'Forwarded', value: node.forwarded, k: 'var(--fwd)' },
    { label: 'Blocked', value: node.blocked, k: 'var(--block)' },
    { label: 'Rewritten', value: node.rewritten, k: 'var(--rewrite)' },
    { label: 'Errors', value: node.errors, k: 'var(--faint)' },
  ]
  const synced = !!node.version && node.version === (node.expected_version ?? cpVer?.config_version)

  const action = (key: string, button: ReactNode, text: ReactNode) => (
    <div className="ag-action" key={key}>
      {button}
      <div className="ag-action-text">
        <p>{text}</p>
        {errFor(key)}
      </div>
    </div>
  )

  return (
    <Modal
      title={node.name}
      onClose={onClose}
      eyebrow={
        <span className="ag-eyebrow">
          <span className={`dot ${st.dot}${st.dot === '' ? ' pulse' : ''}`} /> {st.label}
          {node.site && (
            <>
              {' · '}
              {node.site}, {roleLabel(node.role).toLowerCase()}
            </>
          )}
        </span>
      }
      footer={
        <>
          <button className="btn primary" onClick={() => showQueriesOf(node)}>
            Show its queries
          </button>
          {admin && (
            <button className="btn quiet" onClick={() => go(`/logs?source=${encodeURIComponent(node.id)}`)}>
              Open its logs
            </button>
          )}
        </>
      }
    >
      <div>
        <div className="strip ag-drawer-strip">
          <div>
            <b>{node.total.toLocaleString()}</b>
            <span>queries</span>
          </div>
          <div>
            <b className={node.blocked > 0 ? 'bad' : ''}>{node.total > 0 ? `${pct.toFixed(pct >= 10 ? 0 : 1)}%` : '—'}</b>
            <span>blocked</span>
          </div>
          <div>
            <b>{ms !== null ? `${ms} ms` : '—'}</b>
            <span>avg latency, last hour</span>
          </div>
        </div>
        {node.total > 0 && (
          <>
            <div className="mini ag-mini" aria-hidden="true">
              {breakdown.map((b) =>
                b.value > 0 ? <i key={b.label} style={{ ['--k' as string]: b.k, flexGrow: b.value }} /> : null,
              )}
            </div>
            <div className="ag-breakdown">
              {breakdown.map((b) => (
                <span key={b.label} style={{ ['--k' as string]: b.k }}>
                  {b.label} <b>{b.value.toLocaleString()}</b>
                </span>
              ))}
            </div>
          </>
        )}
      </div>

      <div>
        <h3>Details</h3>
        <dl className="kv">
          <dt>Address</dt>
          <dd className="mono">{nodeIP(node) || '—'}</dd>
          <dt>Version</dt>
          <dd>
            {node.app_version || <span className="muted">unknown — predates version reporting</span>}
            {node.app_version && versionKnown(cpVer?.version) && (
              outdated(node, cpVer?.version) ? (
                <span className="tag warn ag-tag-gap" title={`Control plane runs ${cpVer!.version}`}>
                  update available
                </span>
              ) : (
                <span className="tag ok ag-tag-gap">current</span>
              )
            )}
          </dd>
          <dt>Config</dt>
          <dd title="Whether this agent has applied the rules and records the control plane expects it to run (scoped entries make this differ between agents).">
            {!node.version ? (
              <span className="muted">none applied yet</span>
            ) : (
              <>
                {synced ? <span className="tag ok">in sync</span> : <span className="tag warn">syncing</span>}{' '}
                <span className="mono muted">{node.version.slice(0, 8)}</span>
              </>
            )}
          </dd>
          <dt>Node key</dt>
          <dd>
            <span className="mono">{node.key_prefix ? `${node.key_prefix}…` : '—'}</span>
            {node.key_issued_at ? <span className="muted"> · rotated {ago(node.key_issued_at)}</span> : null}
          </dd>
          <dt>Last seen</dt>
          <dd>{ago(node.last_seen)}</dd>
          <dt>Enrolled</dt>
          <dd>{dateStr(node.created_at)}</dd>
          {!admin && (
            <>
              <dt>Site</dt>
              <dd>{node.site ? `${node.site}, ${roleLabel(node.role).toLowerCase()}` : <span className="muted">not in a site</span>}</dd>
            </>
          )}
          <dt>Node ID</dt>
          <dd className="mono ag-id">{node.id}</dd>
        </dl>
      </div>

      {admin && (
        <div>
          <h3>Site and role</h3>
          <div className="ag-assign">
            <label className="field">
              <span>Site</span>
              <select
                value={node.site}
                disabled={busy === 'assign'}
                onChange={(e) => {
                  const site = e.target.value
                  run('assign', () => onAssign(site, site ? node.role || 'backup' : ''))
                }}
              >
                <option value="">Not in a site</option>
                {sites.map((s) => (
                  <option key={s} value={s}>
                    {s}
                  </option>
                ))}
              </select>
            </label>
            {node.site && (
              <label className="field">
                <span>Role</span>
                <select
                  value={node.role || 'backup'}
                  disabled={busy === 'assign'}
                  onChange={(e) => {
                    const role = e.target.value
                    run('assign', () => onAssign(node.site, role))
                  }}
                >
                  {ROLES.map((r) => (
                    <option key={r} value={r}>
                      {roleLabel(r)}
                    </option>
                  ))}
                </select>
              </label>
            )}
          </div>
          <p className="hint">
            Roles are advisory: every agent serves DNS, and clients fail over in the order of their resolver list (DHCP
            or <code>resolv.conf</code>).
          </p>
          {errFor('assign')}
        </div>
      )}

      {newKey && (
        <div>
          <div className="ok-msg">
            <span>
              <b>New key, shown once.</b> The running agent picks it up by itself; for a manually keyed agent set it as{' '}
              <code>MAZEDNS_NODE_KEY</code> and restart it.
            </span>
          </div>
          <CodeBlock label="Node key" text={newKey.key} />
        </div>
      )}

      {admin && (
        <div>
          <h3>Actions</h3>
          <div className="ag-actions">
            {action(
              'approve',
              <button
                className={`btn ${node.approved ? '' : 'primary'}`}
                disabled={busy === 'approve'}
                onClick={() => run('approve', onApprove)}
              >
                {node.approved ? 'Hold' : 'Approve'}
              </button>,
              node.approved
                ? 'Take back admission: the agent stops pulling config and serving until approved again.'
                : 'Admit this agent so it can pull config and serve DNS.',
            )}
            {action(
              'maintenance',
              <button
                className={`btn ${node.maintenance ? 'primary' : ''}`}
                disabled={busy === 'maintenance'}
                onClick={() => run('maintenance', onMaintenance)}
              >
                {node.maintenance ? 'Resume' : 'Maintenance'}
              </button>,
              node.maintenance
                ? 'Start answering DNS again.'
                : 'Answer SERVFAIL so clients move to the next agent — for reboots and upgrades.',
            )}
            {renaming ? (
              <form className="ag-action ag-rename" onSubmit={saveRename}>
                <div className="ag-rename-field">
                  <input
                    value={draft}
                    onChange={(e) => setDraft(e.target.value)}
                    onKeyDown={(e) => {
                      // Escape cancels the edit only — keep it from reaching the
                      // drawer's window-level Escape handler (which closes it).
                      if (e.key === 'Escape') {
                        e.preventDefault()
                        e.stopPropagation()
                        e.nativeEvent.stopImmediatePropagation()
                        cancelRename()
                      }
                    }}
                    onFocus={(e) => e.target.select()}
                    aria-label="Agent name"
                    aria-invalid={actionErr?.at === 'rename'}
                    disabled={busy === 'rename'}
                    autoFocus
                  />
                  <button type="submit" className="btn primary" disabled={busy === 'rename'}>
                    {busy === 'rename' ? 'Saving…' : 'Save'}
                  </button>
                  <button type="button" className="btn ghost" onClick={cancelRename} disabled={busy === 'rename'}>
                    Cancel
                  </button>
                </div>
                <div className="ag-action-text">
                  <p>Enter to save, Esc to cancel. Identity and history stay the same.</p>
                  {errFor('rename')}
                </div>
              </form>
            ) : (
              action(
                'rename',
                <button className="btn" onClick={startRename}>
                  Rename
                </button>,
                'Change the label. Identity and history stay the same.',
              )
            )}
            {action(
              'renew',
              <button className="btn" disabled={busy === 'renew'} onClick={() => run('renew', onRenew)}>
                Rotate key
              </button>,
              'Issue a new node key. The running agent picks it up on its next poll; the old key keeps working for a short grace period.',
            )}
            {action(
              'delete',
              <button className="btn danger" disabled={busy === 'delete'} onClick={() => run('delete', () => onDelete(true))}>
                Remove &amp; revoke
              </button>,
              "For a retired or compromised agent: it's removed and can't rejoin with this identity.",
            )}
            {action(
              'delete-only',
              <button className="btn danger" disabled={busy === 'delete-only'} onClick={() => run('delete-only', () => onDelete(false))}>
                Remove only
              </button>,
              'Delete the entry but let a running agent enroll again as a new one — for an intentional replacement.',
            )}
          </div>
          <p className="hint">
            An agent whose <code>/data</code> was wiped enrolls without an identity, so revoking can't match it — and with
            the same name it can reclaim this entry once it goes offline. To keep it out, also revoke the enrollment key it
            holds or require approval for new agents.
          </p>
        </div>
      )}
    </Modal>
  )
}

// TTL_OPTIONS maps a friendly label to a number of hours (0 = never expires).
const TTL_OPTIONS: { label: string; hours: number }[] = [
  { label: 'Never', hours: 0 },
  { label: 'In 1 hour', hours: 1 },
  { label: 'In 24 hours', hours: 24 },
  { label: 'In 7 days', hours: 24 * 7 },
  { label: 'In 30 days', hours: 24 * 30 },
]

// EnrollKeyForm keeps its input until the key is created and shows a failure
// right under itself.
function EnrollKeyForm({
  onCreate,
  compact,
}: {
  onCreate: (name: string, ttlHours: number, maxUses: number) => Promise<void>
  compact?: boolean
}) {
  const [name, setName] = useState('')
  const [ttl, setTtl] = useState(0)
  const [maxUses, setMaxUses] = useState(0)
  const [busy, setBusy] = useState(false)
  const [err, setErr] = useState('')

  const submit = async (e: FormEvent) => {
    e.preventDefault()
    if (busy) return
    setBusy(true)
    setErr('')
    try {
      await onCreate(name.trim(), ttl, maxUses)
      setName('')
      setMaxUses(0)
    } catch (e) {
      setErr(errMsg(e))
    } finally {
      setBusy(false)
    }
  }

  return (
    <form className={`ag-keyform${compact ? ' compact' : ''}`} onSubmit={submit}>
      <div className="ag-keyform-row">
        <label className="field">
          <span>Name</span>
          <input placeholder="office rollout" value={name} onChange={(e) => setName(e.target.value)} />
        </label>
        <label className="field">
          <span>Expires</span>
          <select value={ttl} onChange={(e) => setTtl(Number(e.target.value))}>
            {TTL_OPTIONS.map((o) => (
              <option key={o.hours} value={o.hours}>
                {o.label}
              </option>
            ))}
          </select>
        </label>
        <label className="field">
          <span>Max uses</span>
          <input
            type="number"
            min={0}
            placeholder="No limit"
            value={maxUses || ''}
            onChange={(e) => setMaxUses(Math.max(0, Math.floor(Number(e.target.value) || 0)))}
          />
        </label>
        <button type="submit" className="btn primary" disabled={busy}>
          {busy ? 'Creating…' : 'Create key'}
        </button>
      </div>
      {err && (
        <div className="error ag-inline-err" role="alert">
          {err}
        </div>
      )}
    </form>
  )
}

function NewEnrollKey({ created, onDismiss }: { created: { name: string; key: string }; onDismiss: () => void }) {
  return (
    <div className="ag-newkey">
      <div className="ok-msg">
        <span className="grow">
          <b>Enrollment key “{created.name}”, shown once.</b> Use it as <code>MAZEDNS_JOIN_TOKEN</code> on new agents; it
          is stored hashed.
        </span>
        <button className="btn sm quiet" onClick={onDismiss}>
          Dismiss
        </button>
      </div>
      <CodeBlock label="Enrollment key" text={created.key} />
    </div>
  )
}

const KEY_STATUS: Record<EnrollKey['status'], { label: string; cls: string }> = {
  active: { label: 'Active', cls: 'ok' },
  expired: { label: 'Expired', cls: '' },
  exhausted: { label: 'Used up', cls: '' },
  revoked: { label: 'Revoked', cls: 'block' },
}

function EnrollKeysTable({
  keys,
  loading,
  error,
  onRevoke,
  onDelete,
}: {
  keys: EnrollKey[]
  loading: boolean
  error: string
  onRevoke: (k: EnrollKey) => void
  onDelete: (k: EnrollKey) => void
}) {
  const table = useTable(keys, ENROLL_COLS, 'created', true)
  return (
    <>
      <div className="table-scroll">
        <table className="stackable ag-keys-table">
          <thead>
            <tr>
              <Th table={table} col="name">Key</Th>
              <Th table={table} col="status">Status</Th>
              <Th table={table} col="uses" className="hide-sm">Uses</Th>
              <Th table={table} col="expires" className="hide-sm">Expires</Th>
              <Th table={table} col="created" className="hide-sm">Created</Th>
              <th></th>
            </tr>
          </thead>
          <tbody>
            {table.rows.map((k) => {
              const fromConfig = k.created_by === 'config'
              const st = KEY_STATUS[k.status] || { label: k.status, cls: '' }
              return (
                <tr key={k.id} className={k.status === 'active' ? '' : 'inactive'}>
                  <td className="lead">
                    <b>{k.name || 'unnamed'}</b> <span className="mono muted">{k.key_prefix}…</span>
                  </td>
                  <td className="lead-r">
                    {fromConfig && k.status === 'active' ? (
                      <span className="tag warn" title="Imported from the deprecated MAZEDNS_JOIN_TOKEN / cluster.join_token setting">
                        From config
                      </span>
                    ) : (
                      <span className={`tag ${st.cls}`}>{st.label}</span>
                    )}
                  </td>
                  <td>
                    <span className="show-sm">Uses: </span>
                    {k.max_uses ? `${k.use_count} of ${k.max_uses}` : `${k.use_count}, no limit`}
                  </td>
                  <td>
                    <span className="show-sm">Expires: </span>
                    {until(k.expires_at)}
                  </td>
                  <td className="muted">
                    {dayStr(k.created_at)}
                    {fromConfig ? ' from config' : k.created_by ? ` by ${k.created_by}` : ''}
                  </td>
                  <td className="actions">
                    {!k.revoked && (
                      <button className="btn sm danger" onClick={() => onRevoke(k)}>
                        Revoke
                      </button>
                    )}
                    {k.status !== 'active' && (
                      <button className="btn sm quiet" onClick={() => onDelete(k)} title="Delete this key for good">
                        Delete
                      </button>
                    )}
                  </td>
                </tr>
              )
            })}
            <TableStatusRow loading={loading} error={error} empty={table.rows.length === 0} colSpan={6}>
              No enrollment keys yet. Create one above to let agents join.
            </TableStatusRow>
          </tbody>
        </table>
      </div>
      <Pager table={table} unit="keys" />
    </>
  )
}
