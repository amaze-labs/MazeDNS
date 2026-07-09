import { useEffect, useState, type FormEvent } from 'react'
import { api, type Node, type Site } from '../api'
import { pollWhileVisible } from '../poll'
import Modal from './Modal'

const ONLINE_WINDOW = 120 // seconds
const IMAGE = 'ghcr.io/ipmaze/mazedns-dns-agent:latest'

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

const roleRank = (r: string) => (r === 'primary' ? 0 : r === 'backup' ? 1 : 2)
const roleLabel = (r: string) => (r === 'primary' ? 'Primary' : r === 'backup' ? 'Backup' : '—')
const nodeIP = (n: Node) => (n.address || '').replace(/:\d+$/, '')

export default function Cluster() {
  const [nodes, setNodes] = useState<Node[]>([])
  const [sites, setSites] = useState<Site[]>([])
  const [name, setName] = useState('')
  const [siteName, setSiteName] = useState('')
  const [newKey, setNewKey] = useState<{ name: string; key: string } | null>(null)
  const [selected, setSelected] = useState<string | null>(null) // agent name whose detail modal is open
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
    if (!window.confirm(`Remove agent “${n}”? Its key is revoked and it disappears from the cluster.`)) return
    try {
      await api.deleteNode(n)
      if (newKey?.name === n) setNewKey(null)
      if (selected === n) setSelected(null)
      load()
    } catch (e: any) {
      setErr(e.message)
    }
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
    if (on && !window.confirm(`Put “${n.name}” into maintenance? It stops serving DNS (SERVFAIL) so clients fail over to another agent.`)) return
    try {
      await api.setNodeMaintenance(n.name, on)
      setErr('')
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

  // ---- derived ----
  const online = nodes.filter(ONLINE).length
  const serving = nodes.filter(SERVING).length
  const pending = nodes.filter((n) => !n.approved).length
  const totalQ = nodes.reduce((sum, n) => sum + n.total, 0)
  const totalB = nodes.reduce((sum, n) => sum + n.blocked, 0)
  const sitesInUse = Array.from(new Set([...sites.map((s) => s.name), ...nodes.map((n) => n.site).filter(Boolean)])).sort()
  const membersOf = (site: string) =>
    nodes.filter((n) => n.site === site).sort((a, b) => roleRank(a.role) - roleRank(b.role) || a.name.localeCompare(b.name))
  const selectedNode = selected ? nodes.find((n) => n.name === selected) || null : null

  const cpHost = window.location.hostname || '<control-plane-host>'
  const cpURL = `${window.location.protocol}//${cpHost}${window.location.port ? ':' + window.location.port : ''}`

  const joinRun = `docker run -d --name mazedns-agent --restart unless-stopped \\
  -e MAZEDNS_API_ADDRESS=0.0.0.0 \\
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
      MAZEDNS_API_ADDRESS: "0.0.0.0"
      MAZEDNS_CP_URL: "${cpURL}"
      MAZEDNS_JOIN_TOKEN: "\${MAZEDNS_JOIN_TOKEN:?set the cluster join token}"
      MAZEDNS_NODE_NAME: "site-a-1"
    ports:
      - "53:5300/udp"
      - "53:5300/tcp"`
  const manualRun = newKey
    ? `docker run -d --name mazedns-${newKey.name} --restart unless-stopped \\
  -e MAZEDNS_API_ADDRESS=0.0.0.0 \\
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
      <p className="muted" style={{ textAlign: 'left', marginTop: 0 }}>
        This is the <strong>control plane</strong> — it holds the config and dashboard and <strong>does not answer
        DNS</strong>. All resolving is done by the <strong>DNS agents</strong> below; point your clients at their
        addresses.
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
        Group agents into sites and label each <strong>Primary</strong> or <strong>Backup</strong>. Roles are advisory —
        every agent serves DNS; clients fail over via the order in their <code>resolv.conf</code> / DHCP.
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
                      <li key={n.name} className="site-member" onClick={() => setSelected(n.name)} title="Open agent details">
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

      {/* ── Agents ────────────────────────────────────────────────────────── */}
      <h2>Agents</h2>
      <p className="muted">Click an agent to see its metrics and management actions.</p>
      <div className="table-scroll">
        <table className="agents-table">
          <thead>
            <tr>
              <th>Status</th>
              <th>Agent</th>
              <th>Address</th>
              <th>Site</th>
              <th>Role</th>
              <th className="num">Queries</th>
              <th className="num">Blocked</th>
              <th>Version</th>
              <th>Last seen</th>
            </tr>
          </thead>
          <tbody>
            {nodes.map((n) => {
              const st = statusOf(n)
              return (
                <tr key={n.name} className="agent-row" onClick={() => setSelected(n.name)}>
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
                    <select
                      value={n.site}
                      onChange={(e) => assignSite(n, e.target.value, e.target.value ? n.role || 'backup' : '')}
                    >
                      <option value="">— none —</option>
                      {sitesInUse.map((s) => (
                        <option key={s} value={s}>
                          {s}
                        </option>
                      ))}
                    </select>
                  </td>
                  <td onClick={(e) => e.stopPropagation()}>
                    {n.site ? (
                      <select value={n.role || 'backup'} onChange={(e) => assignSite(n, n.site, e.target.value)}>
                        <option value="primary">Primary</option>
                        <option value="backup">Backup</option>
                      </select>
                    ) : (
                      <span className="muted">—</span>
                    )}
                  </td>
                  <td className="num">{n.total.toLocaleString()}</td>
                  <td className="num">{n.blocked.toLocaleString()}</td>
                  <td>
                    {n.version ? (
                      n.expected_version && n.version !== n.expected_version ? (
                        <code title={`syncing: node has ${n.version}, expects ${n.expected_version}`}>{n.version} ⟳</code>
                      ) : (
                        <code>{n.version}</code>
                      )
                    ) : (
                      <span className="muted">pending</span>
                    )}
                  </td>
                  <td>{ago(n.last_seen)}</td>
                </tr>
              )
            })}
            {nodes.length === 0 && (
              <tr>
                <td colSpan={9} className="muted">
                  No agents enrolled — add one from “Deploy a DNS agent” below.
                </td>
              </tr>
            )}
          </tbody>
        </table>
      </div>

      {/* ── Deployment docs (collapsed: this is reference, not the main view) ─ */}
      <details className="settings-card deploy-docs">
        <summary>Deploy a DNS agent</summary>
        <p className="muted" style={{ textAlign: 'left' }}>
          Agents self-enroll with the shared <strong>join token</strong> you set on the control plane
          (<code>MAZEDNS_JOIN_TOKEN</code>). Run the agent image below and it appears in the table above automatically —
          no key to copy. Set <code>MAZEDNS_REQUIRE_APPROVAL=true</code> to hold new agents until you approve them.
        </p>
        <CodeBlock label="Zero-touch join — docker run" text={joinRun} />
        <CodeBlock label="Zero-touch join — docker compose" text={joinCompose} />

        <details style={{ marginTop: 12 }}>
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
              <CodeBlock label="docker run" text={manualRun} />
            </div>
          )}
        </details>
      </details>

      {selectedNode && (
        <AgentModal
          node={selectedNode}
          sites={sitesInUse}
          newKey={newKey?.name === selectedNode.name ? newKey : null}
          onClose={() => setSelected(null)}
          onApprove={() => approve(selectedNode)}
          onMaintenance={() => toggleMaintenance(selectedNode)}
          onRenew={() => renew(selectedNode.name)}
          onDelete={() => del(selectedNode.name)}
          onAssign={(site, role) => assignSite(selectedNode, site, role)}
        />
      )}
    </div>
  )
}

function AgentModal({
  node,
  sites,
  newKey,
  onClose,
  onApprove,
  onMaintenance,
  onRenew,
  onDelete,
  onAssign,
}: {
  node: Node
  sites: string[]
  newKey: { name: string; key: string } | null
  onClose: () => void
  onApprove: () => void
  onMaintenance: () => void
  onRenew: () => void
  onDelete: () => void
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
        <div><dt>Version</dt><dd>{node.version ? <code>{node.version}</code> : '—'}{node.expected_version && node.version && node.version !== node.expected_version ? <span className="muted"> (expects <code>{node.expected_version}</code>)</span> : null}</dd></div>
        <div><dt>Last seen</dt><dd>{ago(node.last_seen)}</dd></div>
        <div><dt>Enrolled</dt><dd>{dateStr(node.created_at)}</dd></div>
        <div><dt>Key prefix</dt><dd><code>{node.key_prefix || '—'}</code></dd></div>
      </dl>

      <div className="agent-assign">
        <label>
          Site
          <select value={node.site} onChange={(e) => onAssign(e.target.value, e.target.value ? node.role || 'backup' : '')}>
            <option value="">— none —</option>
            {sites.map((s) => (
              <option key={s} value={s}>{s}</option>
            ))}
          </select>
        </label>
        {node.site && (
          <label>
            Role
            <select value={node.role || 'backup'} onChange={(e) => onAssign(node.site, e.target.value)}>
              <option value="primary">Primary</option>
              <option value="backup">Backup</option>
            </select>
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
          <button className="btn" onClick={onRenew}>
            Renew key
          </button>
          <span className="muted">Rotate this agent’s API key. The old key stops working immediately.</span>
        </div>
        <div className="agent-action">
          <button className="del" onClick={onDelete}>
            Remove
          </button>
          <span className="muted">Revoke the key and remove the agent from the cluster.</span>
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
