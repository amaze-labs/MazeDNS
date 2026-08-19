import { useEffect, useState, type FormEvent } from 'react'
import { api, type EnrollKey, type Node, type RevokedNode, type Site } from '../api'
import { pollWhileVisible } from '../poll'
import Modal from './Modal'
import { useTable, Th, Pager, type SortAccessors } from './tableKit'

const ONLINE_WINDOW = 120 // seconds
const IMAGE = 'ghcr.io/amaze-labs/mazedns-agent:latest'

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
  return new Date(unixSec * 1000).toLocaleString()
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
    <div className="codeblock">
      <div className="codeblock-head">
        <span className="muted">{label}</span>
        <button className="btn ghost" onClick={copy}>
          {copied ? 'Copied ✓' : 'Copy'}
        </button>
      </div>
      <pre className="keybox">{text}</pre>
    </div>
  )
}

const ONLINE = (n: Node) => !!n.last_seen && Date.now() / 1000 - n.last_seen < ONLINE_WINDOW
const SERVING = (n: Node) => ONLINE(n) && n.approved && !n.maintenance
// statusOf summarises an agent's DNS state for the status dot + label.
function statusOf(n: Node): { dot: 'on' | 'off' | 'warn'; label: string } {
  if (!n.approved) return { dot: 'warn', label: 'Pending approval' }
  if (!ONLINE(n)) return { dot: 'off', label: 'Offline' }
  if (n.maintenance) return { dot: 'warn', label: 'Draining' }
  return { dot: 'on', label: 'Serving DNS' }
}

// Advisory DNS roles within a site: primary answers first, secondary is the
// resolver clients fail over to, backup is the last resort.
const ROLES = ['primary', 'secondary', 'backup'] as const
const roleRank = (r: string) => (r === 'primary' ? 0 : r === 'secondary' ? 1 : r === 'backup' ? 2 : 3)
const roleLabel = (r: string) =>
  r === 'primary' ? 'Primary' : r === 'secondary' ? 'Secondary' : r === 'backup' ? 'Backup' : '—'
const roleBadge = (r: string) => (r === 'primary' ? 'allow' : r === 'secondary' ? 'info' : '')
const nodeIP = (n: Node) => (n.address || '').replace(/:\d+$/, '')

// Sort accessors for the enrollment-keys table.
const ENROLL_COLS: SortAccessors<EnrollKey> = {
  name: (k) => k.name || '',
  status: (k) => k.status,
  expires: (k) => k.expires_at || Number.MAX_SAFE_INTEGER,
  uses: (k) => k.use_count,
  created: (k) => k.created_at,
}

// Sort accessors for the agents table.
const AGENT_COLS: SortAccessors<Node> = {
  status: (n) => statusOf(n).label,
  name: (n) => n.name,
  address: (n) => nodeIP(n),
  site: (n) => n.site || '',
  role: (n) => roleRank(n.role),
  total: (n) => n.total,
  blocked: (n) => n.blocked,
  version: (n) => n.app_version || '',
  last_seen: (n) => n.last_seen || 0,
}

// versionKnown reports whether the control plane has a comparable build version
// (local "dev" builds can't meaningfully flag anyone as outdated).
const versionKnown = (cp?: string) => !!cp && cp !== 'dev'
// outdated: the agent reports a build version different from the control plane's
// (or none at all — an agent from before version reporting is by definition old).
const outdated = (n: Node, cp?: string) => versionKnown(cp) && n.app_version !== cp

// AppVersion renders an agent's build version with its up-to-date signal against
// the control plane's version. This is the RUNNING BINARY's version — the rules
// sync state (config hash) is shown separately in the agent modal.
function AppVersion({ v, cp }: { v: string; cp?: string }) {
  if (!v) {
    return (
      <span className="muted" title="This agent predates version reporting — update its image.">
        unknown
      </span>
    )
  }
  const known = versionKnown(cp)
  const stale = known && v !== cp
  return (
    <span style={{ display: 'inline-flex', alignItems: 'center', gap: 6, flexWrap: 'wrap' }}>
      <code>{v}</code>
      {known &&
        (stale ? (
          <span className="badge blocked" title={`Control plane runs ${cp} — update this agent's image.`}>
            outdated
          </span>
        ) : (
          <span className="badge allow" title="Matches the control-plane version.">
            ✓
          </span>
        ))}
    </span>
  )
}

// RoleSelect / SiteSelect: the styled dropdowns used in the agents table and the
// agent modal (a .select-pill wrapper draws the chevron and focus ring).
function RoleSelect({ value, onChange }: { value: string; onChange: (role: string) => void }) {
  return (
    <span className="select-pill">
      <select value={value || 'backup'} onChange={(e) => onChange(e.target.value)}>
        {ROLES.map((r) => (
          <option key={r} value={r}>
            {roleLabel(r)}
          </option>
        ))}
      </select>
    </span>
  )
}

function SiteSelect({ value, sites, onChange }: { value: string; sites: string[]; onChange: (site: string) => void }) {
  return (
    <span className="select-pill">
      <select value={value} onChange={(e) => onChange(e.target.value)}>
        <option value="">— none —</option>
        {sites.map((s) => (
          <option key={s} value={s}>
            {s}
          </option>
        ))}
      </select>
    </span>
  )
}

export default function Cluster() {
  const [nodes, setNodes] = useState<Node[]>([])
  const [sites, setSites] = useState<Site[]>([])
  const [enrollKeys, setEnrollKeys] = useState<EnrollKey[]>([])
  const [revoked, setRevoked] = useState<RevokedNode[]>([])
  const [name, setName] = useState('')
  const [siteName, setSiteName] = useState('')
  const [newKey, setNewKey] = useState<{ name: string; key: string } | null>(null)
  const [newEnrollKey, setNewEnrollKey] = useState<{ name: string; key: string } | null>(null)
  const [selected, setSelected] = useState<string | null>(null) // agent id whose detail modal is open
  const [err, setErr] = useState('')
  // The control plane's own build version (the up-to-date reference for agents)
  // and the current replicated-config version (rules-sync reference).
  const [cpVer, setCpVer] = useState<{ version: string; config_version: string } | null>(null)

  const load = () =>
    Promise.all([api.clusterNodes(), api.clusterSites(), api.enrollKeys(), api.listRevoked(), api.serverVersion()])
      .then(([n, s, k, rv, v]) => {
        setNodes(n)
        setSites(s)
        setEnrollKeys(k)
        setRevoked(rv)
        setCpVer(v)
        setErr('')
      })
      .catch((e) => setErr(e.message))

  useEffect(() => {
    load()
    return pollWhileVisible(load, 10000)
  }, [])

  const add = async (e: FormEvent) => {
    e.preventDefault()
    if (!name.trim()) return
    try {
      const r = await api.addNode(name.trim())
      setNewKey(r)
      setName('')
      setErr('')
      load()
    } catch (e: any) {
      setErr(e.message)
    }
  }

  const del = async (n: Node, revoke: boolean) => {
    const msg = revoke
      ? `Remove and revoke agent “${n.name}”? Its identity is tombstoned so the running agent cannot rejoin the cluster — it keeps serving DNS standalone until you stop it or un-revoke.`
      : `Remove agent “${n.name}” only? A still-running agent may re-enroll as a NEW node. Use this for intentional replacement.`
    if (!window.confirm(msg)) return
    try {
      await api.deleteNode(n.id, revoke)
      if (newKey?.name === n.name) setNewKey(null)
      if (selected === n.id) setSelected(null)
      load()
    } catch (e: any) {
      setErr(e.message)
    }
  }

  const unrevoke = async (r: RevokedNode) => {
    if (!window.confirm(`Un-revoke “${r.name || r.id}”? Its agent can rejoin (as a new node) on its next attempt.`)) return
    try {
      await api.unrevokeNode(r.id)
      load()
    } catch (e: any) {
      setErr(e.message)
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
      load()
    } catch (e: any) {
      setErr(e.message)
    }
  }

  const renew = async (n: Node) => {
    if (!window.confirm(`Rotate the key for “${n.name}”? The old key stops working immediately.`)) return
    try {
      const r = await api.renewNodeKey(n.id)
      setNewKey({ name: n.name, key: r.key })
      setErr('')
      load()
    } catch (e: any) {
      setErr(e.message)
    }
  }

  const rename = async (n: Node) => {
    const next = window.prompt(`Rename agent “${n.name}” (display label only — its identity and history are unchanged):`, n.name)
    if (next == null) return
    const name = next.trim()
    if (!name || name === n.name) return
    try {
      await api.renameNode(n.id, name)
      setErr('')
      load()
    } catch (e: any) {
      setErr(e.message)
    }
  }

  const approve = async (n: Node) => {
    try {
      await api.approveNode(n.id, !n.approved)
      setErr('')
      load()
    } catch (e: any) {
      setErr(e.message)
    }
  }

  const toggleMaintenance = async (n: Node) => {
    const on = !n.maintenance
    if (on && !window.confirm(`Put “${n.name}” into maintenance? It stops serving DNS (SERVFAIL) so clients fail over to another agent.`)) return
    try {
      await api.setNodeMaintenance(n.id, on)
      setErr('')
      load()
    } catch (e: any) {
      setErr(e.message)
    }
  }

  const assignSite = async (n: Node, site: string, role: string) => {
    try {
      await api.setNodeSite(n.id, site, role)
      setErr('')
      load()
    } catch (e: any) {
      setErr(e.message)
    }
  }

  const addSite = async (e: FormEvent) => {
    e.preventDefault()
    if (!siteName.trim()) return
    try {
      await api.createSite(siteName.trim())
      setSiteName('')
      setErr('')
      load()
    } catch (e: any) {
      setErr(e.message)
    }
  }
  const delSite = async (n: string) => {
    if (!window.confirm(`Delete site “${n}”? Its agents are unassigned (they keep serving DNS).`)) return
    try {
      await api.deleteSite(n)
      load()
    } catch (e: any) {
      setErr(e.message)
    }
  }

  const createEnrollKey = async (name: string, ttlHours: number, maxUses: number) => {
    try {
      const r = await api.createEnrollKey(name, ttlHours, maxUses)
      setNewEnrollKey({ name: r.name || r.key_prefix, key: r.key })
      setErr('')
      load()
    } catch (e: any) {
      setErr(e.message)
    }
  }
  const revokeEnrollKey = async (k: EnrollKey) => {
    if (!window.confirm(`Revoke enrollment key “${k.name || k.key_prefix}”? Agents can no longer join with it.`)) return
    try {
      await api.revokeEnrollKey(k.id)
      load()
    } catch (e: any) {
      setErr(e.message)
    }
  }

  // ---- derived ----
  const online = nodes.filter(ONLINE).length
  const serving = nodes.filter(SERVING).length
  const pending = nodes.filter((n) => !n.approved).length
  const totalQ = nodes.reduce((sum, n) => sum + n.total, 0)
  const totalB = nodes.reduce((sum, n) => sum + n.blocked, 0)
  const sitesInUse = Array.from(new Set([...sites.map((s) => s.name), ...nodes.map((n) => n.site).filter(Boolean)])).sort()
  const membersOf = (site: string) =>
    nodes.filter((n) => n.site === site).sort((a, b) => roleRank(a.role) - roleRank(b.role) || a.name.localeCompare(b.name))
  const selectedNode = selected ? nodes.find((n) => n.id === selected) || null : null
  const agentsTable = useTable(nodes, AGENT_COLS, 'name')

  const cpHost = window.location.hostname || '<control-plane-host>'
  const cpURL = `${window.location.protocol}//${cpHost}${window.location.port ? ':' + window.location.port : ''}`

  // Prefer showing a freshly-created enrollment key inline; otherwise a placeholder.
  const enrollSecret = newEnrollKey?.key || '<enrollment-key>'
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
  const manualRun = newKey
    ? `docker run -d --name mazedns-${newKey.name} --restart unless-stopped \\
  --network host \\
  -e MAZEDNS_CP_URL=${cpURL} \\
  -e MAZEDNS_CP_IP=${cpIP} \\
  -e MAZEDNS_NODE_KEY=${newKey.key} \\
  -e MAZEDNS_NODE_NAME=${newKey.name} \\
  -e MAZEDNS_DB_PATH=/data/mazedns.db \\
  -e MAZEDNS_API_ADDRESS=0.0.0.0 \\
  -e MAZEDNS_API_PORT=9090 \\
  -v mazedns-${newKey.name}-data:/data \\
  ${IMAGE}
${bridgeAlt}`
    : ''

  return (
    <div>
      <h2>Cluster management</h2>
      {err && <div className="error">{err}</div>}
      <p className="muted" style={{ textAlign: 'left', marginTop: 0 }}>
        This is the <strong>control plane</strong> — it holds the config and dashboard and <strong>does not answer
        DNS</strong>. All resolving is done by the <strong>DNS agents</strong> below; point your clients at their
        addresses.
        {cpVer && (
          <>
            {' '}Control plane version <code>{cpVer.version}</code>.
          </>
        )}
      </p>

      <div className="cards">
        <Card label="Agents" value={nodes.length} />
        <Card label="Online" value={online} />
        <Card label="Serving DNS" value={serving} accent={serving === 0 ? 'danger' : undefined} />
        <Card label="Pending" value={pending} accent={pending > 0 ? 'danger' : undefined} />
        <Card label="Cluster queries" value={totalQ} />
        <Card label="Cluster blocked" value={totalB} accent="danger" />
      </div>

      {/* ── Sites ─────────────────────────────────────────────────────────── */}
      <div className="section-head">
        <h2>Sites</h2>
        <form className="row" onSubmit={addSite}>
          <input placeholder="new site (e.g. office-london)" value={siteName} onChange={(e) => setSiteName(e.target.value)} />
          <button type="submit" className="btn">
            Create site
          </button>
        </form>
      </div>
      <p className="muted">
        Group agents into sites and label each <strong>Primary</strong>, <strong>Secondary</strong>, or{' '}
        <strong>Backup</strong>. Roles are advisory — every agent serves DNS; clients fail over via the order in their{' '}
        <code>resolv.conf</code> / DHCP.
      </p>

      {sitesInUse.length > 0 ? (
        <div className="site-grid">
          {sitesInUse.map((site) => {
            const members = membersOf(site)
            const desc = sites.find((s) => s.name === site)?.description
            const onlineN = members.filter(ONLINE).length
            return (
              <div className="settings-card site-card" key={site}>
                <div className="site-head">
                  <h3>{site}</h3>
                  <span className="muted">
                    {onlineN}/{members.length} online
                  </span>
                  <button className="del" onClick={() => delSite(site)} title="Delete site">
                    ✕
                  </button>
                </div>
                {desc && <p className="muted" style={{ textAlign: 'left', margin: '0 0 8px' }}>{desc}</p>}
                <ul className="site-members">
                  {members.map((n) => {
                    const st = statusOf(n)
                    return (
                      <li key={n.id} className="site-member" onClick={() => setSelected(n.id)} title="Open agent details">
                        <span className={`node-dot ${st.dot}`} title={st.label} />
                        <span className={`badge ${roleBadge(n.role)}`}>{roleLabel(n.role)}</span>
                        <strong>{n.name}</strong>
                        <span className="muted" style={{ marginLeft: 'auto' }}>{nodeIP(n) || 'no address'}</span>
                      </li>
                    )
                  })}
                  {members.length === 0 && <li className="muted">No agents assigned yet</li>}
                </ul>
              </div>
            )
          })}
        </div>
      ) : (
        <p className="muted">No sites yet — create one above, then assign agents in the table below.</p>
      )}

      {/* ── Agents ────────────────────────────────────────────────────────── */}
      <h2>Agents</h2>
      <p className="muted" style={{ textAlign: 'left', marginTop: 0 }}>
        Click an agent to see its metrics and management actions.
      </p>
      {(() => {
        const stale = nodes.filter((n) => outdated(n, cpVer?.version))
        if (stale.length === 0) return null
        return (
          <div className="error" style={{ marginBottom: 12 }}>
            ⚠ {stale.length} agent{stale.length === 1 ? ' is' : 's are'} not running the control-plane version (
            <code>{cpVer!.version}</code>) — update {stale.length === 1 ? 'its' : 'their'} container image
            {stale.length === 1 ? '' : 's'}: {stale.map((n) => n.name).join(', ')}
          </div>
        )
      })()}
      <div className="table-scroll">
        <table className="agents-table">
          <thead>
            <tr>
              <Th table={agentsTable} col="status">Status</Th>
              <Th table={agentsTable} col="name">Agent</Th>
              <Th table={agentsTable} col="address">Address</Th>
              <Th table={agentsTable} col="site">Site</Th>
              <Th table={agentsTable} col="role">Role</Th>
              <Th table={agentsTable} col="total" className="num">Queries</Th>
              <Th table={agentsTable} col="blocked" className="num">Blocked</Th>
              <Th table={agentsTable} col="version">Version</Th>
              <Th table={agentsTable} col="last_seen">Last seen</Th>
            </tr>
          </thead>
          <tbody>
            {agentsTable.rows.map((n) => {
              const st = statusOf(n)
              return (
                <tr key={n.id} className="agent-row" onClick={() => setSelected(n.id)}>
                  <td>
                    <span className="node-status">
                      <span className={`node-dot ${st.dot}`} title={st.label} />
                      <span className="node-status-label">{st.label}</span>
                    </span>
                  </td>
                  <td>
                    <strong>{n.name}</strong>
                    {!n.approved && (
                      <span className="badge info" title="Pending approval" style={{ marginLeft: 6 }}>
                        pending
                      </span>
                    )}
                  </td>
                  <td>{nodeIP(n) || '—'}</td>
                  <td onClick={(e) => e.stopPropagation()}>
                    <SiteSelect value={n.site} sites={sitesInUse} onChange={(site) => assignSite(n, site, site ? n.role || 'backup' : '')} />
                  </td>
                  <td onClick={(e) => e.stopPropagation()}>
                    {n.site ? (
                      <RoleSelect value={n.role} onChange={(role) => assignSite(n, n.site, role)} />
                    ) : (
                      <span className="muted">—</span>
                    )}
                  </td>
                  <td className="num">{n.total.toLocaleString()}</td>
                  <td className="num">{n.blocked.toLocaleString()}</td>
                  <td>
                    <AppVersion v={n.app_version} cp={cpVer?.version} />
                    {n.version && n.expected_version && n.version !== n.expected_version && (
                      <span className="muted" title={`config syncing: node has ${n.version}, expects ${n.expected_version}`}> ⟳</span>
                    )}
                  </td>
                  <td>{ago(n.last_seen)}</td>
                </tr>
              )
            })}
            {agentsTable.rows.length === 0 && (
              <tr>
                <td colSpan={9} className="muted">
                  No agents enrolled — add one from “Deploy a DNS agent” below.
                </td>
              </tr>
            )}
          </tbody>
        </table>
      </div>
      <Pager table={agentsTable} unit="agents" />

      {/* ── Revoked agents ────────────────────────────────────────────────── */}
      {revoked.length > 0 && (
        <details className="settings-card">
          <summary>
            Revoked agents <span className="badge blocked">{revoked.length}</span>
          </summary>
          <p className="muted" style={{ textAlign: 'left' }}>
            These node identities are tombstoned — their agents are refused at re-enrollment (no enrollment-key use is
            spent). <strong>Un-revoke</strong> lets an agent rejoin as a new node on its next attempt;{' '}
            <strong>Delete forever</strong> permanently removes the record.
          </p>
          <div className="table-scroll">
            <table className="agents-table">
              <thead>
                <tr>
                  <th>Name</th>
                  <th>ID</th>
                  <th>Revoked</th>
                  <th>By</th>
                  <th></th>
                </tr>
              </thead>
              <tbody>
                {revoked.map((r) => (
                  <tr key={r.id}>
                    <td>{r.name || <span className="muted">—</span>}</td>
                    <td>
                      <code>{r.id}</code>
                    </td>
                    <td>{r.revoked_at ? new Date(r.revoked_at * 1000).toLocaleString() : '—'}</td>
                    <td>{r.revoked_by || <span className="muted">—</span>}</td>
                    <td>
                      <div className="agent-remove-btns">
                        <button className="btn ghost" onClick={() => unrevoke(r)}>
                          Un-revoke
                        </button>
                        <button className="del" onClick={() => purgeRevoked(r)}>
                          Delete forever
                        </button>
                      </div>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </details>
      )}

      {/* ── Enrollment keys ───────────────────────────────────────────────── */}
      <EnrollKeys
        keys={enrollKeys}
        created={newEnrollKey}
        onCreate={createEnrollKey}
        onRevoke={revokeEnrollKey}
        onDismiss={() => setNewEnrollKey(null)}
      />

      {/* ── Deployment docs (collapsed: this is reference, not the main view) ─ */}
      <details className="settings-card deploy-docs">
        <summary>Deploy a DNS agent</summary>
        <p className="muted" style={{ textAlign: 'left' }}>
          Agents self-enroll with an <strong>enrollment key</strong> you create above and pass as{' '}
          <code>MAZEDNS_JOIN_TOKEN</code>. Run the agent image below and it appears in the table above automatically —
          no per-node key to copy. Set <code>MAZEDNS_REQUIRE_APPROVAL=true</code> to hold new agents until you approve
          them. After joining, each node authenticates with a per-node key the control plane rotates automatically.
        </p>
        <p className="muted" style={{ textAlign: 'left' }}>
          <strong>Keep the <code>/data</code> volume</strong> — it stores the node’s identity (its UUID + rotating key)
          so a recreated container rejoins instantly as the same node. If the volume is lost anyway, a stable{' '}
          <code>MAZEDNS_NODE_NAME</code> is the safety net: once the old container stops polling (~2 min) the new one{' '}
          <em>reclaims</em> the same node — its history, site, and role — instead of appearing as a duplicate.
        </p>
        <CodeBlock label="Zero-touch join — docker run" text={joinRun} />
        <CodeBlock label="Zero-touch join — docker compose" text={joinCompose} />

        <details style={{ marginTop: 12 }}>
          <summary>Prefer a fixed per-agent key? Issue one manually</summary>
          <form className="row" onSubmit={add} style={{ marginTop: 12 }}>
            <input placeholder="new agent name (e.g. site-b)" value={name} onChange={(e) => setName(e.target.value)} />
            <button type="submit" className="btn primary">
              Issue key
            </button>
          </form>
          {newKey && (
            <div className="enroll">
              <div className="ok-msg">
                <strong>Key for agent “{newKey.name}” — shown once</strong> (stored hashed). Set it as{' '}
                <code>MAZEDNS_NODE_KEY</code> on the agent.
              </div>
              <CodeBlock label="docker run" text={manualRun} />
            </div>
          )}
        </details>
      </details>

      {selectedNode && (
        <AgentModal
          node={selectedNode}
          cpVer={cpVer}
          sites={sitesInUse}
          newKey={newKey?.name === selectedNode.name ? newKey : null}
          onClose={() => setSelected(null)}
          onApprove={() => approve(selectedNode)}
          onMaintenance={() => toggleMaintenance(selectedNode)}
          onRenew={() => renew(selectedNode)}
          onRename={() => rename(selectedNode)}
          onDelete={(revoke) => del(selectedNode, revoke)}
          onAssign={(site, role) => assignSite(selectedNode, site, role)}
        />
      )}
    </div>
  )
}

function AgentModal({
  node,
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
  cpVer: { version: string; config_version: string } | null
  sites: string[]
  newKey: { name: string; key: string } | null
  onClose: () => void
  onApprove: () => void
  onMaintenance: () => void
  onRenew: () => void
  onRename: () => void
  onDelete: (revoke: boolean) => void
  onAssign: (site: string, role: string) => void
}) {
  const st = statusOf(node)
  const pct = node.total > 0 ? `${Math.round((node.blocked / node.total) * 100)}% of queries` : undefined
  const tiles: { label: string; value: string; sub?: string; tone?: string }[] = [
    { label: 'Queries', value: node.total.toLocaleString() },
    { label: 'Blocked', value: node.blocked.toLocaleString(), sub: pct, tone: 'blocked' },
    { label: 'Cached', value: node.cached.toLocaleString() },
    { label: 'Forwarded', value: node.forwarded.toLocaleString() },
    { label: 'Rewritten', value: node.rewritten.toLocaleString() },
    { label: 'Errors', value: node.errors.toLocaleString(), tone: node.errors > 0 ? 'blocked' : '' },
  ]
  return (
    <Modal title={node.name} onClose={onClose} size="wide">
      <div className="agent-modal-status">
        <span className={`node-dot ${st.dot}`} />
        <span className="node-status-label">{st.label}</span>
      </div>

      <div className="usage-tiles">
        {tiles.map((t) => (
          <div key={t.label} className="usage-tile">
            <span className={`num${t.tone ? ` ${t.tone}` : ''}`}>{t.value}</span>
            <span className="muted">{t.label}</span>
            {t.sub && <span className="tile-sub muted">{t.sub}</span>}
          </div>
        ))}
      </div>

      <dl className="kv-grid">
        <div><dt>Address</dt><dd>{nodeIP(node) || '—'}</dd></div>
        <div><dt>App version</dt><dd><AppVersion v={node.app_version} cp={cpVer?.version} /></dd></div>
        <div>
          <dt>Config sync</dt>
          <dd title="Whether this agent has applied the control plane's current rules/rewrites for this node (per-node replicated-config hash — scoped entries make it differ between nodes).">
            {!node.version ? (
              '—'
            ) : node.version === (node.expected_version ?? cpVer?.config_version) ? (
              <span className="badge allow">in sync</span>
            ) : (
              <span className="badge info">syncing…</span>
            )}{' '}
            <code className="muted">{node.version.slice(0, 12)}</code>
          </dd>
        </div>
        <div><dt>Last seen</dt><dd>{ago(node.last_seen)}</dd></div>
        <div><dt>Enrolled</dt><dd>{dateStr(node.created_at)}</dd></div>
        <div><dt>Key prefix</dt><dd><code>{node.key_prefix || '—'}</code></dd></div>
        <div><dt>Key rotated</dt><dd>{node.key_issued_at ? ago(node.key_issued_at) : '—'}</dd></div>
        <div><dt>Node ID</dt><dd><code className="muted">{node.id}</code></dd></div>
      </dl>

      <div className="agent-assign">
        <label>
          Site
          <SiteSelect value={node.site} sites={sites} onChange={(site) => onAssign(site, site ? node.role || 'backup' : '')} />
        </label>
        {node.site && (
          <label>
            Role
            <RoleSelect value={node.role} onChange={(role) => onAssign(node.site, role)} />
          </label>
        )}
      </div>

      {newKey && (
        <div className="enroll" style={{ marginTop: 12 }}>
          <div className="ok-msg">
            <strong>New key — shown once</strong> (stored hashed). Set it as <code>MAZEDNS_NODE_KEY</code> on the agent,
            then restart it.
          </div>
          <pre className="keybox">{newKey.key}</pre>
        </div>
      )}

      <h4 className="agent-actions-head">Actions</h4>
      <div className="agent-actions">
        <div className="agent-action">
          <button className={`btn ${node.approved ? '' : 'primary'}`} onClick={onApprove}>
            {node.approved ? 'Hold' : 'Approve'}
          </button>
          <span className="muted">
            {node.approved
              ? 'Revoke admission — the agent stops pulling config and serving until re-approved.'
              : 'Admit this agent to the cluster so it can pull config and serve DNS.'}
          </span>
        </div>
        <div className="agent-action">
          <button className={`btn ${node.maintenance ? 'primary' : ''}`} onClick={onMaintenance}>
            {node.maintenance ? 'Resume' : 'Maintenance'}
          </button>
          <span className="muted">
            {node.maintenance
              ? 'Resume serving DNS.'
              : 'Drain: answer SERVFAIL so clients fail over to another agent (for reboots/upgrades).'}
          </span>
        </div>
        <div className="agent-action">
          <button className="btn" onClick={onRename}>
            Rename
          </button>
          <span className="muted">Change the display label. The agent’s identity and history are unchanged.</span>
        </div>
        <div className="agent-action">
          <button className="btn" onClick={onRenew}>
            Rotate key
          </button>
          <span className="muted">
            Issue a new per-node key. A running agent adopts it automatically on its next poll (the old key stays valid
            for a short grace window — no downtime). The key shown is for the manual <code>MAZEDNS_NODE_KEY</code> path.
          </span>
        </div>
        <div className="agent-action">
          <div className="agent-remove-btns">
            <button className="del" onClick={() => onDelete(true)}>
              Remove &amp; revoke
            </button>
            <button className="btn ghost" onClick={() => onDelete(false)}>
              Remove only
            </button>
          </div>
          <span className="muted">
            <strong>Remove &amp; revoke</strong> tombstones this node’s identity so the running agent can’t rejoin — use
            it for a decommissioned or compromised agent. <strong>Remove only</strong> deletes the row so the agent may
            re-enroll as a new node (intentional replacement).
            <br />
            Note: an agent whose <code>/data</code> was wiped enrolls with no identity and can’t be matched to the
            tombstone — but with the same name it can <em>reclaim</em> this node once it goes offline. To keep it out,
            also revoke the enrollment key it holds and/or turn on <em>require approval</em>.
          </span>
        </div>
      </div>
    </Modal>
  )
}

function Card({ label, value, accent }: { label: string; value: number; accent?: string }) {
  return (
    <div className={`card ${accent || ''}`}>
      <div className="card-value">{value.toLocaleString()}</div>
      <div className="card-label">{label}</div>
    </div>
  )
}

// TTL_OPTIONS maps a friendly label to a number of hours (0 = never expires).
const TTL_OPTIONS: { label: string; hours: number }[] = [
  { label: 'Never', hours: 0 },
  { label: '1 hour', hours: 1 },
  { label: '24 hours', hours: 24 },
  { label: '7 days', hours: 24 * 7 },
  { label: '30 days', hours: 24 * 30 },
]

function EnrollKeys({
  keys,
  created,
  onCreate,
  onRevoke,
  onDismiss,
}: {
  keys: EnrollKey[]
  created: { name: string; key: string } | null
  onCreate: (name: string, ttlHours: number, maxUses: number) => void
  onRevoke: (k: EnrollKey) => void
  onDismiss: () => void
}) {
  const [name, setName] = useState('')
  const [ttl, setTtl] = useState(0)
  const [maxUses, setMaxUses] = useState(0)
  const table = useTable(keys, ENROLL_COLS, 'created', true)

  const submit = (e: FormEvent) => {
    e.preventDefault()
    onCreate(name.trim(), ttl, maxUses)
    setName('')
    setMaxUses(0)
  }

  return (
    <>
      <div className="section-head">
        <h2>Enrollment keys</h2>
        <form className="row" onSubmit={submit}>
          <input placeholder="description (e.g. site-a rollout)" value={name} onChange={(e) => setName(e.target.value)} />
          <select value={ttl} onChange={(e) => setTtl(Number(e.target.value))} title="Expiry">
            {TTL_OPTIONS.map((o) => (
              <option key={o.hours} value={o.hours}>
                {o.label}
              </option>
            ))}
          </select>
          <input
            type="number"
            min={0}
            placeholder="max uses (0 = ∞)"
            value={maxUses || ''}
            onChange={(e) => setMaxUses(Math.max(0, Number(e.target.value)))}
            style={{ width: 130 }}
            title="Max uses (0 = unlimited)"
          />
          <button type="submit" className="btn primary">
            Create key
          </button>
        </form>
      </div>
      <p className="muted" style={{ textAlign: 'left', marginTop: 0 }}>
        Agents join by presenting an enrollment key (as <code>MAZEDNS_JOIN_TOKEN</code>). Each key only works for
        enrollment — never for serving DNS or shipping logs — and can be limited by expiry and a maximum number of uses.
        The full secret is shown once, here, then stored hashed.
      </p>

      {created && (
        <div className="enroll">
          <div className="ok-msg">
            <strong>Enrollment key “{created.name}” — shown once</strong> (stored hashed). Use it as{' '}
            <code>MAZEDNS_JOIN_TOKEN</code> on new agents.{' '}
            <button className="btn ghost" onClick={onDismiss}>
              Dismiss
            </button>
          </div>
          <pre className="keybox">{created.key}</pre>
        </div>
      )}

      <div className="table-scroll">
        <table className="agents-table">
          <thead>
            <tr>
              <th>Key</th>
              <Th table={table} col="name">Description</Th>
              <Th table={table} col="status">Status</Th>
              <Th table={table} col="expires">Expires</Th>
              <Th table={table} col="uses" className="num">Uses</Th>
              <Th table={table} col="created">Created</Th>
              <th></th>
            </tr>
          </thead>
          <tbody>
            {table.rows.map((k) => (
              <tr key={k.id}>
                <td>
                  <code>{k.key_prefix}…</code>
                </td>
                <td>{k.name || <span className="muted">—</span>}</td>
                <td>
                  <span className={`badge ${k.status === 'active' ? 'allow' : 'info'}`}>{k.status}</span>
                </td>
                <td>{k.expires_at ? dateStr(k.expires_at) : <span className="muted">never</span>}</td>
                <td className="num">
                  {k.use_count}
                  {k.max_uses ? ` / ${k.max_uses}` : ''}
                </td>
                <td>
                  {dateStr(k.created_at)}
                  {k.created_by ? ` · ${k.created_by}` : ''}
                </td>
                <td>
                  {!k.revoked && (
                    <button className="del" onClick={() => onRevoke(k)} title="Revoke key">
                      Revoke
                    </button>
                  )}
                </td>
              </tr>
            ))}
            {table.rows.length === 0 && (
              <tr>
                <td colSpan={7} className="muted">
                  No enrollment keys yet — create one above to let agents join.
                </td>
              </tr>
            )}
          </tbody>
        </table>
      </div>
      <Pager table={table} unit="keys" />
    </>
  )
}
