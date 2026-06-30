import { useEffect, useState, type FormEvent } from 'react'
import { api, type Node, type Site } from '../api'
import { pollWhileVisible } from '../poll'

const ONLINE_WINDOW = 120 // seconds
const IMAGE = 'ghcr.io/ipmaze/mazedns:latest'

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
    if (!window.confirm(`Remove node “${n}”? Its key is revoked.`)) return
    await api.deleteNode(n)
    if (newKey?.name === n) setNewKey(null)
    load()
  }

  const renew = async (n: string) => {
    if (!window.confirm(`Rotate the key for “${n}”? The old key stops working immediately — update the worker's MAZEDNS_NODE_KEY.`)) return
    try {
      const r = await api.renewNodeKey(n)
      setNewKey(r)
      setErr('')
      load()
    } catch (e: any) {
      setErr(e.message)
    }
  }

  const toggleMaintenance = async (n: Node) => {
    const on = !n.maintenance
    if (on && !window.confirm(`Put “${n.name}” into maintenance? It will stop serving DNS (answers SERVFAIL) so clients fail over to another node.`)) return
    try {
      await api.setNodeMaintenance(n.name, on)
      setErr('')
      load()
    } catch (e: any) {
      setErr(e.message)
    }
  }

  const now = Date.now() / 1000
  const isOnline = (n: Node) => n.is_master || (!!n.last_seen && now - n.last_seen < ONLINE_WINDOW)
  // A node serves DNS when it's online, not draining, and not a control-plane-only master.
  const isServing = (n: Node) => isOnline(n) && !n.maintenance && !(n.is_master && n.control_plane_only)
  // statusOf summarises a node's DNS state for the status column / dot colour.
  const statusOf = (n: Node): { dot: 'on' | 'off' | 'warn'; label: string } => {
    if (!isOnline(n)) return { dot: 'off', label: 'Offline' }
    if (n.is_master && n.control_plane_only) return { dot: 'warn', label: 'Control plane only' }
    if (n.maintenance) return { dot: 'warn', label: 'Draining' }
    return { dot: 'on', label: 'Serving DNS' }
  }

  const master = nodes.find((n) => n.is_master)
  const online = nodes.filter(isOnline).length
  const serving = nodes.filter(isServing).length
  const totalQ = nodes.reduce((sum, n) => sum + n.total, 0)
  const totalB = nodes.reduce((sum, n) => sum + n.blocked, 0)

  const setControlPlane = async (on: boolean) => {
    if (on) {
      const otherServing = nodes.filter((n) => !n.is_master && isServing(n)).length
      if (
        otherServing === 0 &&
        !window.confirm(
          'No worker node is currently serving DNS. Turning this on means the cluster answers no DNS queries until a worker comes online. Continue?',
        )
      )
        return
    }
    try {
      await api.setMasterControlPlaneOnly(on)
      setErr('')
      load()
    } catch (e: any) {
      setErr(e.message)
    }
  }

  const masterHost = window.location.hostname || '<master-host>'
  const masterURL = `http://${masterHost}:8080`

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
    if (!window.confirm(`Delete site “${n}”? Its nodes are unassigned (they keep serving DNS).`)) return
    try {
      await api.deleteSite(n)
      load()
    } catch (e: any) {
      setErr(e.message)
    }
  }
  const assignSite = async (n: Node, site: string, role: string) => {
    try {
      await api.setNodeSite(n.is_master ? 'master' : n.name, site, role)
      setErr('')
      load()
    } catch (e: any) {
      setErr(e.message)
    }
  }

  // Role helpers: primary leads, then backups, then unlabelled.
  const roleRank = (r: string) => (r === 'primary' ? 0 : r === 'backup' ? 1 : 2)
  const roleLabel = (r: string) => (r === 'primary' ? 'Primary' : r === 'backup' ? 'Backup' : '—')
  // A node's DNS address for generated client config (master uses the dashboard host).
  const nodeIP = (n: Node) => (n.is_master ? masterHost : (n.address || '').replace(/:\d+$/, ''))
  // Group nodes by site, members ordered primary-first.
  const membersOf = (site: string) =>
    nodes.filter((n) => n.site === site).sort((a, b) => roleRank(a.role) - roleRank(b.role) || a.name.localeCompare(b.name))
  const sitesInUse = Array.from(new Set([...sites.map((s) => s.name), ...nodes.map((n) => n.site).filter(Boolean)])).sort()
  const dockerRun = newKey
    ? `docker run -d --name mazedns-${newKey.name} --restart unless-stopped \\
  -e MAZEDNS_MODE=worker \\
  -e MAZEDNS_MASTER_URL=${masterURL} \\
  -e MAZEDNS_NODE_KEY=${newKey.key} \\
  -p 53:5300/udp -p 53:5300/tcp \\
  ${IMAGE}`
    : ''
  const dockerCompose = newKey
    ? `services:
  mazedns-${newKey.name}:
    image: ${IMAGE}
    restart: unless-stopped
    environment:
      MAZEDNS_MODE: worker
      MAZEDNS_MASTER_URL: "${masterURL}"
      MAZEDNS_NODE_KEY: "${newKey.key}"
    ports:
      - "53:5300/udp"
      - "53:5300/tcp"`
    : ''

  return (
    <div>
      <h2>Cluster management</h2>
      {err && <div className="error">{err}</div>}

      <div className="cards">
        <Card label="Nodes" value={nodes.length} />
        <Card label="Online" value={online} />
        <Card label="Serving DNS" value={serving} accent={serving === 0 ? 'danger' : undefined} />
        <Card label="Cluster queries" value={totalQ} />
        <Card label="Cluster blocked" value={totalB} accent="danger" />
      </div>

      {/* Master role: control plane + DNS, or control plane only (no DNS). */}
      <div className="settings-card role-card">
        <h3>Master role</h3>
        <p className="muted" style={{ textAlign: 'left', marginTop: 0 }}>
          Choose whether this master also answers DNS, or runs purely as the cluster <strong>control plane</strong>
          (config, dashboard, node enrollment, log aggregation) while the worker nodes serve DNS. Applies live — no
          restart.
        </p>
        <label className="toggle">
          <input
            type="checkbox"
            checked={!!master?.control_plane_only}
            onChange={(e) => setControlPlane(e.target.checked)}
          />
          <span className="track">
            <span className="thumb" />
          </span>
          <span className="toggle-label">Control plane only — the master serves no DNS (answers REFUSED)</span>
        </label>
        <p className="muted" style={{ textAlign: 'left', marginBottom: 0 }}>
          Currently:{' '}
          <strong>{master?.control_plane_only ? 'Control plane only — no DNS' : 'Control plane + DNS'}</strong>.
          {master?.control_plane_only
            ? ' Point your clients at the worker nodes below.'
            : ' The master both coordinates the cluster and resolves DNS.'}
        </p>
      </div>

      <h2>Sites</h2>
      <p className="muted">
        Group nodes into sites and label each <strong>Primary</strong> or <strong>Backup</strong>. Roles are advisory —
        every node serves DNS; clients fail over via the order in their <code>resolv.conf</code> / DHCP. Assign nodes in
        the table below.
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
            const ips = members.map(nodeIP)
            const list = (a: string[]) => a.map((ip) => ip || '<set node address>')
            const cfg =
              `# /etc/resolv.conf — site ${site} (primary first)\n` +
              list(ips).map((ip) => `nameserver ${ip}`).join('\n') +
              `\n\n# DHCP (ISC dhcpd) option 6\noption domain-name-servers ${list(ips).join(', ')};`
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
                        {n.is_master && <span className="badge">master</span>}
                        <span className="muted" style={{ marginLeft: 'auto' }}>{nodeIP(n) || 'no address'}</span>
                      </li>
                    )
                  })}
                  {members.length === 0 && <li className="muted">No nodes assigned yet</li>}
                </ul>
                {members.length > 0 && <CodeBlock label="Client config" text={cfg} />}
              </div>
            )
          })}
        </div>
      ) : (
        <p className="muted">No sites yet — create one above, then assign nodes in the table below.</p>
      )}

      <h2>Add a worker node</h2>
      <p className="muted">
        Enroll a node to get a one-time key, then run the worker from the prebuilt image <code>{IMAGE}</code>.
      </p>
      <form className="row" onSubmit={add}>
        <input placeholder="new node name (e.g. site-b)" value={name} onChange={(e) => setName(e.target.value)} />
        <button type="submit" className="btn primary">
          Add node
        </button>
      </form>

      {newKey && (
        <div className="enroll">
          <div className="ok-msg">
            <strong>Key for node “{newKey.name}” — shown once</strong> (stored hashed). Run the worker with it, or update
            its <code>MAZEDNS_NODE_KEY</code> if you rotated. Adjust <code>{masterURL}</code> if the worker reaches the
            master at a different address.
          </div>
          <CodeBlock label="Option A — docker run" text={dockerRun} />
          <CodeBlock label="Option B — docker compose (add to your compose file)" text={dockerCompose} />
        </div>
      )}

      <h2>Nodes</h2>
      <div className="table-scroll">
      <table>
        <thead>
          <tr>
            <th>Status</th>
            <th>Node</th>
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
            <tr key={n.name}>
              <td>
                <span className="node-status">
                  <span className={`node-dot ${st.dot}`} title={st.label} />
                  <span className="node-status-label">{st.label}</span>
                </span>
              </td>
              <td>
                {n.name} {n.is_master && <span className="badge">master</span>}
                {n.is_master && n.control_plane_only && (
                  <span className="badge info" title="Control plane only — serves no DNS">control plane</span>
                )}
              </td>
              <td>{n.address || '—'}</td>
              <td>{n.total.toLocaleString()}</td>
              <td>{n.blocked.toLocaleString()}</td>
              <td>{n.version ? <code>{n.version}</code> : <span className="muted">pending</span>}</td>
              <td>{n.is_master ? 'now' : ago(n.last_seen)}</td>
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
                  {/* Maintenance is moot for a control-plane-only master (already no DNS). */}
                  {!(n.is_master && n.control_plane_only) && (
                    <button
                      className={`btn ${n.maintenance ? 'primary' : ''}`}
                      onClick={() => toggleMaintenance(n)}
                      title={n.maintenance ? 'Resume serving DNS' : 'Drain: stop serving DNS so clients fail over'}
                    >
                      {n.maintenance ? 'Resume' : 'Maintenance'}
                    </button>
                  )}
                  {!n.is_master && (
                    <>
                      <button className="btn" onClick={() => renew(n.name)} title="Rotate this node's key">
                        Renew key
                      </button>
                      <button className="del" onClick={() => del(n.name)}>
                        ✕
                      </button>
                    </>
                  )}
                </div>
              </td>
            </tr>
            )
          })}
          {nodes.length === 0 && (
            <tr>
              <td colSpan={9} className="muted">
                No nodes enrolled — add one above
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
