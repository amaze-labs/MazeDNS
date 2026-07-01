import { useEffect, useState, type FormEvent } from 'react'
import { api, type Node, type Site } from '../api'
import { pollWhileVisible } from '../poll'

const ONLINE_WINDOW = 120 // seconds
const IMAGE = 'ghcr.io/ipmaze/mazedns-dns-agent:latest'

function ago(unixSec: number): string {
  if (!unixSec) return 'never'
  const s = Math.max(0, Math.floor(Date.now() / 1000 - unixSec))
  if (s < 60) return `${s}s ago`
  if (s < 3600) return `${Math.floor(s / 60)}m ago`
  return `${Math.floor(s / 3600)}h ago`
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

export default function Cluster() {
  const [nodes, setNodes] = useState<Node[]>([])
  const [sites, setSites] = useState<Site[]>([])
  const [name, setName] = useState('')
  const [siteName, setSiteName] = useState('')
  const [newKey, setNewKey] = useState<{ name: string; key: string } | null>(null)
  const [err, setErr] = useState('')

  const load = () =>
    Promise.all([api.clusterNodes(), api.clusterSites()])
      .then(([n, s]) => {
        setNodes(n)
        setSites(s)
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

  const del = async (n: string) => {
    if (!window.confirm(`Remove agent “${n}”? Its key is revoked.`)) return
    await api.deleteNode(n)
    if (newKey?.name === n) setNewKey(null)
    load()
  }

  const renew = async (n: string) => {
    if (!window.confirm(`Rotate the key for “${n}”? The old key stops working immediately.`)) return
    try {
      const r = await api.renewNodeKey(n)
      setNewKey(r)
      setErr('')
      load()
    } catch (e: any) {
      setErr(e.message)
    }
  }

  const approve = async (n: Node) => {
    try {
      await api.approveNode(n.name, !n.approved)
      setErr('')
      load()
    } catch (e: any) {
      setErr(e.message)
    }
  }

  const toggleMaintenance = async (n: Node) => {
    const on = !n.maintenance
    if (on && !window.confirm(`Put “${n.name}” into maintenance? It will stop serving DNS (answers SERVFAIL) so clients fail over to another agent.`)) return
    try {
      await api.setNodeMaintenance(n.name, on)
      setErr('')
      load()
    } catch (e: any) {
      setErr(e.message)
    }
  }

  const now = Date.now() / 1000
  const isOnline = (n: Node) => !!n.last_seen && now - n.last_seen < ONLINE_WINDOW
  // An agent serves DNS when it's online, approved, and not draining.
  const isServing = (n: Node) => isOnline(n) && n.approved && !n.maintenance
  // statusOf summarises an agent's DNS state for the status column / dot colour.
  const statusOf = (n: Node): { dot: 'on' | 'off' | 'warn'; label: string } => {
    if (!n.approved) return { dot: 'warn', label: 'Pending approval' }
    if (!isOnline(n)) return { dot: 'off', label: 'Offline' }
    if (n.maintenance) return { dot: 'warn', label: 'Draining' }
    return { dot: 'on', label: 'Serving DNS' }
  }

  const online = nodes.filter(isOnline).length
  const serving = nodes.filter(isServing).length
  const pending = nodes.filter((n) => !n.approved).length
  const totalQ = nodes.reduce((sum, n) => sum + n.total, 0)
  const totalB = nodes.reduce((sum, n) => sum + n.blocked, 0)

  const cpHost = window.location.hostname || '<control-plane-host>'
  const cpURL = `${window.location.protocol}//${cpHost}${window.location.port ? ':' + window.location.port : ''}`

  // ---- Sites: create / delete / assign nodes ----
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
  const assignSite = async (n: Node, site: string, role: string) => {
    try {
      await api.setNodeSite(n.name, site, role)
      setErr('')
      load()
    } catch (e: any) {
      setErr(e.message)
    }
  }

  // Role helpers: primary leads, then backups, then unlabelled.
  const roleRank = (r: string) => (r === 'primary' ? 0 : r === 'backup' ? 1 : 2)
  const roleLabel = (r: string) => (r === 'primary' ? 'Primary' : r === 'backup' ? 'Backup' : '—')
  const nodeIP = (n: Node) => (n.address || '').replace(/:\d+$/, '')
  const membersOf = (site: string) =>
    nodes.filter((n) => n.site === site).sort((a, b) => roleRank(a.role) - roleRank(b.role) || a.name.localeCompare(b.name))
  const sitesInUse = Array.from(new Set([...sites.map((s) => s.name), ...nodes.map((n) => n.site).filter(Boolean)])).sort()

  // Zero-touch join: agents self-enroll with the shared join token you set on the
  // control plane (MAZEDNS_JOIN_TOKEN). The token is never shown here.
  const joinRun = `docker run -d --name mazedns-agent --restart unless-stopped \\
  -e MAZEDNS_CP_URL=${cpURL} \\
  -e MAZEDNS_JOIN_TOKEN=<your-cluster-join-token> \\
  -e MAZEDNS_NODE_NAME=site-a-1 \\
  -p 53:5300/udp -p 53:5300/tcp \\
  ${IMAGE}`
  const joinCompose = `services:
  dns-agent:
    image: ${IMAGE}
    restart: unless-stopped
    environment:
      MAZEDNS_CP_URL: "${cpURL}"
      MAZEDNS_JOIN_TOKEN: "\${MAZEDNS_JOIN_TOKEN:?set the cluster join token}"
      MAZEDNS_NODE_NAME: "site-a-1"
    ports:
      - "53:5300/udp"
      - "53:5300/tcp"`

  // Legacy per-node key flow (no join token configured).
  const dockerRun = newKey
    ? `docker run -d --name mazedns-${newKey.name} --restart unless-stopped \\
  -e MAZEDNS_CP_URL=${cpURL} \\
  -e MAZEDNS_NODE_KEY=${newKey.key} \\
  -e MAZEDNS_NODE_NAME=${newKey.name} \\
  -p 53:5300/udp -p 53:5300/tcp \\
  ${IMAGE}`
    : ''

  return (
    <div>
      <h2>Cluster management</h2>
      {err && <div className="error">{err}</div>}

      <div className="cards">
        <Card label="Agents" value={nodes.length} />
        <Card label="Online" value={online} />
        <Card label="Serving DNS" value={serving} accent={serving === 0 ? 'danger' : undefined} />
        <Card label="Pending" value={pending} accent={pending > 0 ? 'danger' : undefined} />
        <Card label="Cluster queries" value={totalQ} />
        <Card label="Cluster blocked" value={totalB} accent="danger" />
      </div>

      <div className="settings-card role-card">
        <h3>How MazeDNS is deployed</h3>
        <p className="muted" style={{ textAlign: 'left', marginTop: 0 }}>
          This is the <strong>control plane</strong>: it holds the config, dashboard, and cluster coordination and{' '}
          <strong>does not answer DNS</strong>. All resolving is done by the <strong>DNS agents</strong> below. Point your
          clients at the agents’ addresses.
        </p>
      </div>

      <h2>Add a DNS agent</h2>
      <p className="muted">
        Agents self-enroll with the shared <strong>join token</strong> you set on the control plane
        (<code>MAZEDNS_JOIN_TOKEN</code>). Run the agent image below and it appears here automatically — no key to copy.
      </p>
      <CodeBlock label="Zero-touch join — docker run" text={joinRun} />
      <CodeBlock label="Zero-touch join — docker compose" text={joinCompose} />

      <details className="settings-card" style={{ marginTop: 12 }}>
        <summary>No join token? Issue a per-agent key manually</summary>
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
            <CodeBlock label="docker run" text={dockerRun} />
          </div>
        )}
      </details>

      <h2>Sites</h2>
      <p className="muted">
        Group agents into sites and label each <strong>Primary</strong> or <strong>Backup</strong>. Roles are advisory —
        every agent serves DNS; clients fail over via the order in their <code>resolv.conf</code> / DHCP.
      </p>
      <form className="row" onSubmit={addSite}>
        <input placeholder="new site name (e.g. office-london)" value={siteName} onChange={(e) => setSiteName(e.target.value)} />
        <button type="submit" className="btn">
          Create site
        </button>
      </form>

      {sitesInUse.length > 0 ? (
        <div className="site-grid">
          {sitesInUse.map((site) => {
            const members = membersOf(site)
            const desc = sites.find((s) => s.name === site)?.description
            const onlineN = members.filter(isOnline).length
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
                      <li key={n.name}>
                        <span className={`node-dot ${st.dot}`} title={st.label} />
                        <span className={`badge ${n.role === 'primary' ? 'allow' : ''}`}>{roleLabel(n.role)}</span>
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

      <h2>Agents</h2>
      <div className="table-scroll">
      <table>
        <thead>
          <tr>
            <th>Status</th>
            <th>Agent</th>
            <th>Address</th>
            <th>Queries</th>
            <th>Blocked</th>
            <th>Version</th>
            <th>Last seen</th>
            <th>Site / role</th>
            <th></th>
          </tr>
        </thead>
        <tbody>
          {nodes.map((n) => {
            const st = statusOf(n)
            return (
            <tr key={n.name} className={!n.approved ? 'master-row' : ''}>
              <td>
                <span className="node-status">
                  <span className={`node-dot ${st.dot}`} title={st.label} />
                  <span className="node-status-label">{st.label}</span>
                </span>
              </td>
              <td>
                {n.name}
                {!n.approved && (
                  <span className="badge info" title="Pending approval" style={{ marginLeft: 6 }}>
                    pending
                  </span>
                )}
              </td>
              <td>{n.address || '—'}</td>
              <td>{n.total.toLocaleString()}</td>
              <td>{n.blocked.toLocaleString()}</td>
              <td>{n.version ? <code>{n.version}</code> : <span className="muted">pending</span>}</td>
              <td>{ago(n.last_seen)}</td>
              <td>
                <div className="ql-filters">
                  <select value={n.site} onChange={(e) => assignSite(n, e.target.value, e.target.value ? n.role || 'backup' : '')}>
                    <option value="">— none —</option>
                    {sitesInUse.map((s) => (
                      <option key={s} value={s}>
                        {s}
                      </option>
                    ))}
                  </select>
                  {n.site && (
                    <select value={n.role || 'backup'} onChange={(e) => assignSite(n, n.site, e.target.value)}>
                      <option value="primary">Primary</option>
                      <option value="backup">Backup</option>
                    </select>
                  )}
                </div>
              </td>
              <td>
                <div className="ql-filters">
                  <button
                    className={`btn ${n.approved ? '' : 'primary'}`}
                    onClick={() => approve(n)}
                    title={n.approved ? 'Revoke admission (hold this agent)' : 'Admit this agent to the cluster'}
                  >
                    {n.approved ? 'Hold' : 'Approve'}
                  </button>
                  <button
                    className={`btn ${n.maintenance ? 'primary' : ''}`}
                    onClick={() => toggleMaintenance(n)}
                    title={n.maintenance ? 'Resume serving DNS' : 'Drain: stop serving DNS so clients fail over'}
                  >
                    {n.maintenance ? 'Resume' : 'Maintenance'}
                  </button>
                  <button className="btn" onClick={() => renew(n.name)} title="Rotate this agent's key">
                    Renew key
                  </button>
                  <button className="del" onClick={() => del(n.name)}>
                    ✕
                  </button>
                </div>
              </td>
            </tr>
            )
          })}
          {nodes.length === 0 && (
            <tr>
              <td colSpan={9} className="muted">
                No agents enrolled — run one with the join command above
              </td>
            </tr>
          )}
        </tbody>
      </table>
      </div>
    </div>
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
