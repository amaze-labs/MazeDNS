import { useEffect, useState } from 'react'
import { api, type Classification, type WhoisInfo } from '../api'
import Modal from './Modal'
import Spinner from './Spinner'

const BLOCK_CATS = ['ads', 'trackers', 'malware', 'phishing']
const catClass = (c: string) => (BLOCK_CATS.includes(c) ? 'blocked' : c === 'other' ? 'allow' : 'info')
const fmtDate = (s: string) => (s ? new Date(s).toLocaleDateString() : '—')

// DomainDetail shows everything known about one classified domain: the model's
// verdict plus live WHOIS/RDAP registration data, with the review actions.
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

  useEffect(() => {
    setLoading(true)
    api
      .whois(c.domain)
      .then((r) => (r.ok && r.whois ? setWhois(r.whois) : setWhoisErr(r.error || 'unavailable')))
      .catch((e) => setWhoisErr(e.message))
      .finally(() => setLoading(false))
  }, [c.domain])

  const blocked = c.status === 'auto' || c.status === 'approved'
  const act = (d: 'approve' | 'reject' | 'dismiss') => {
    onAction(c.domain, d)
    onClose()
  }

  return (
    <Modal title={c.domain} onClose={onClose}>
      <div className="dd-grid">
        <span className="muted">Category</span>
        <span>
          <span className={`badge ${catClass(c.category)}`}>{c.category}</span>
          {c.threat && <span className="badge blocked" style={{ marginLeft: 6 }}>🛡 threat</span>}
          {c.trusted && <span className="badge allow" style={{ marginLeft: 6 }}>✓ trusted</span>}
        </span>
        <span className="muted">Confidence</span>
        <span>{Math.round((c.confidence || 0) * 100)}%</span>
        <span className="muted">Status</span>
        <span>{blocked ? 'blocked' : c.status === 'rejected' ? 'allowed' : c.status}</span>
        <span className="muted">Model</span>
        <span>{c.model || '—'}</span>
        <span className="muted">Reason</span>
        <span>{c.reason || '—'}</span>
      </div>

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
