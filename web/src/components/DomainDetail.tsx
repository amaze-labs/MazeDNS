import { useEffect, useState } from 'react'
import { api, type Classification, type DomainClient, type WhoisInfo } from '../api'
import Modal from './Modal'
import Spinner from './Spinner'

const BLOCK_CATS = ['ads', 'trackers', 'malware', 'phishing']
const catClass = (c: string) => (BLOCK_CATS.includes(c) ? 'blocked' : c === 'other' ? 'allow' : 'info')
const fmtDate = (s: string) => (s ? new Date(s).toLocaleDateString() : '—')
const fmtTime = (ms: number) => (ms ? new Date(ms).toLocaleString() : '—')

// scoreClass colours the legitimacy number: high = safe (green), low = risky (red).
const scoreClass = (n: number) => (n >= 70 ? 'allow' : n >= 50 ? 'info' : 'blocked')
// Clearer intent: approved = blacklisted, rejected = whitelisted.
const statusText = (s: string) =>
  s === 'auto' || s === 'approved' ? 'blacklisted' : s === 'rejected' ? 'whitelisted' : s

// DomainDetail shows everything known about one classified domain: the legitimacy
// scorecard (start 100, deduct per risk factor), live WHOIS/RDAP data, the clients
// that queried it, and the review actions.
export default function DomainDetail({
  c,
  onClose,
  onAction,
}: {
  c: Classification
  onClose: () => void
  onAction: (domain: string, decision: 'approve' | 'reject' | 'dismiss') => void
}) {
  const [whois, setWhois] = useState<WhoisInfo | null>(null)
  const [whoisErr, setWhoisErr] = useState('')
  const [loading, setLoading] = useState(true)
  const [clients, setClients] = useState<DomainClient[] | null>(null)

  useEffect(() => {
    setLoading(true)
    api
      .whois(c.domain)
      .then((r) => (r.ok && r.whois ? setWhois(r.whois) : setWhoisErr(r.error || 'unavailable')))
      .catch((e) => setWhoisErr(e.message))
      .finally(() => setLoading(false))
    api
      .domainClients(c.domain)
      .then((r) => setClients(r.clients))
      .catch(() => setClients([]))
  }, [c.domain])

  const blocked = c.status === 'auto' || c.status === 'approved'
  const act = (d: 'approve' | 'reject' | 'dismiss') => {
    onAction(c.domain, d)
    onClose()
  }

  // The legitimacy score and its factor breakdown come from the backend; fall
  // back gracefully for old verdicts that predate scoring.
  const score = typeof c.score === 'number' ? c.score : 100
  const factors = c.factors || []

  return (
    <Modal title={c.domain} onClose={onClose}>
      <div className="dd-grid">
        <span className="muted">Category</span>
        <span>
          <span className={`badge ${catClass(c.category)}`}>{c.category}</span>
          {c.threat && <span className="badge blocked" style={{ marginLeft: 6 }}>🛡 threat</span>}
          {c.trusted && <span className="badge allow" style={{ marginLeft: 6 }}>✓ trusted</span>}
        </span>
        <span className="muted">Legitimacy</span>
        <span>
          <span className={`badge ${scoreClass(score)}`}>{score}% legitimate</span>
          <span className="muted" style={{ marginLeft: 8 }}>
            {statusText(c.status)}
          </span>
        </span>
        <span className="muted">Model</span>
        <span>{c.model || '—'}</span>
        <span className="muted">Summary</span>
        <span>{c.reason || '—'}</span>
      </div>

      <h4>Legitimacy scorecard</h4>
      <p className="muted" style={{ textAlign: 'left' }}>
        Every domain starts <strong>100% legitimate</strong>. Each risk factor below — weighed the way a SOC analyst
        would — deducts from the score. The model's own read is just one (bounded) factor, so it can't single-handedly
        sink a legitimate domain. Below {/* blockThreshold */}50% it becomes a block candidate.
      </p>
      <div className="scorecard">
        <div className="score-row base">
          <span className="score-label">Starting score</span>
          <span className="score-detail">every domain is presumed legitimate</span>
          <span className="score-delta">100</span>
        </div>
        {factors.map((f, i) => (
          <div key={i} className={`score-row ${f.delta < 0 ? 'risk' : f.delta > 0 ? 'up' : 'neutral'}`}>
            <span className="score-label">{f.label}</span>
            <span className="score-detail">{f.detail}</span>
            <span className="score-delta">{f.delta === 0 ? '—' : f.delta > 0 ? `+${f.delta}` : f.delta}</span>
          </div>
        ))}
        <div className={`score-row total ${scoreClass(score)}`}>
          <span className="score-label">Final legitimacy</span>
          <span className="score-detail">{score < 50 ? 'block candidate' : 'allowed'}</span>
          <span className="score-delta">{score}</span>
        </div>
      </div>

      <h4>Clients querying this domain</h4>
      {clients === null ? (
        <Spinner label="Loading…" />
      ) : clients.length === 0 ? (
        <p className="muted" style={{ textAlign: 'left' }}>No queries for this domain in the retained logs.</p>
      ) : (
        <table className="table compact">
          <thead>
            <tr>
              <th>Client</th>
              <th>Queries</th>
              <th>Blocked</th>
              <th>Last seen</th>
            </tr>
          </thead>
          <tbody>
            {clients.map((cl) => (
              <tr key={cl.client}>
                <td>
                  {cl.name ? (
                    <>
                      <strong>{cl.name}</strong>{' '}
                      <span className="muted">
                        {cl.client}
                        {cl.source && ` · ${cl.source}`}
                      </span>
                    </>
                  ) : (
                    cl.client
                  )}
                </td>
                <td>{cl.count.toLocaleString()}</td>
                <td>{cl.blocked > 0 ? <span className="badge blocked">{cl.blocked}</span> : '—'}</td>
                <td className="muted">{fmtTime(cl.last_seen)}</td>
              </tr>
            ))}
          </tbody>
        </table>
      )}

      <h4>Registration (WHOIS / RDAP)</h4>
      {loading ? (
        <Spinner label="Looking up…" />
      ) : whoisErr ? (
        <p className="muted" style={{ textAlign: 'left' }}>WHOIS unavailable: {whoisErr}</p>
      ) : whois ? (
        <div className="dd-grid">
          {whois.registrant && (
            <>
              <span className="muted">Registrant</span>
              <span>{whois.registrant}</span>
            </>
          )}
          <span className="muted">Registrar</span>
          <span>{whois.registrar || '—'}</span>
          <span className="muted">Registered</span>
          <span>
            {fmtDate(whois.created)}
            {whois.age_days > 0 && (
              <span className={whois.age_days < 90 ? 'badge blocked' : 'muted'} style={{ marginLeft: 8 }}>
                {whois.age_days < 90 ? `⚠ ${whois.age_days} days old` : `${whois.age_days} days old`}
              </span>
            )}
          </span>
          <span className="muted">Expires</span>
          <span>{fmtDate(whois.expires)}</span>
          <span className="muted">Updated</span>
          <span>{fmtDate(whois.updated)}</span>
          {whois.nameservers?.length > 0 && (
            <>
              <span className="muted">Nameservers</span>
              <span>{whois.nameservers.join(', ')}</span>
            </>
          )}
          {whois.status?.length > 0 && (
            <>
              <span className="muted">Status</span>
              <span>{whois.status.join(', ')}</span>
            </>
          )}
        </div>
      ) : null}

      <div className="settings-actions" style={{ marginTop: 18 }}>
        {!blocked && (
          <button className="btn primary" onClick={() => act('approve')}>
            Block
          </button>
        )}
        {c.status !== 'rejected' && (
          <button className="btn" onClick={() => act('reject')}>
            Allow
          </button>
        )}
        {c.status === 'suggested' && (
          <button className="btn ghost" onClick={() => act('dismiss')}>
            Dismiss
          </button>
        )}
      </div>
    </Modal>
  )
}
