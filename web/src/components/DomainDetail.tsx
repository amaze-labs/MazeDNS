import { useEffect, useRef, useState } from 'react'
import { api, type Classification, type DomainClient, type WhoisInfo } from '../api'
import Modal from './Modal'
import Spinner from './Spinner'
import { DecisionActions, DecisionFields, useDecision, type Decision } from './DecisionModal'

// Shared with the review table (Classifier).
const BLOCK_CATS = ['ads', 'trackers', 'malware', 'phishing']
// Security categories read as blocks (coral); content categories are neutral.
export const catTag = (c: string) => (BLOCK_CATS.includes(c) ? 'block' : '')
// Legitimacy bands: < 50 block candidate, 50–69 watch, 70+ safe.
export const scoreTone = (n: number) => (n < 50 ? 'block' : n < 70 ? 'warn' : 'ok')
// Plain names for the stored statuses: approved = blocked by you, rejected =
// allowed by you.
const STATUS_LABELS: Record<string, string> = {
  suggested: 'To check',
  auto: 'Auto-blocked',
  approved: 'Blocked by you',
  rejected: 'Allowed by you',
  clean: 'Clean',
}
export const statusLabel = (s: string) => STATUS_LABELS[s] ?? s

const fmtDate = (s: string) => (s ? new Date(s).toLocaleDateString(undefined, { day: 'numeric', month: 'short', year: 'numeric' }) : '—')
const fmtTime = (ms: number) => (ms ? new Date(ms).toLocaleString() : '—')
const cap = (s: string) => s.charAt(0).toUpperCase() + s.slice(1)

function ago(ms: number): string {
  if (!ms) return ''
  const s = Math.max(0, Math.floor((Date.now() - ms) / 1000))
  if (s < 60) return 'just now'
  if (s < 3600) return `${Math.floor(s / 60)} min ago`
  if (s < 86400) return `${Math.floor(s / 3600)} h ago`
  return `${Math.floor(s / 86400)} d ago`
}

// ScoreRing draws the legitimacy score as a ring coloured by its band.
function ScoreRing({ score }: { score: number }) {
  const r = 15.5
  const c = 2 * Math.PI * r
  const k = `var(--${scoreTone(score)})`
  return (
    <svg className="ring" viewBox="0 0 36 36" role="img" aria-label={`Legitimacy ${score} of 100`}>
      <circle cx="18" cy="18" r={r} fill="none" stroke="var(--soft)" strokeWidth="4" />
      <circle
        cx="18"
        cy="18"
        r={r}
        fill="none"
        stroke={k}
        strokeWidth="4"
        strokeLinecap="round"
        strokeDasharray={`${(c * Math.max(0, Math.min(100, score))) / 100} ${c}`}
        transform="rotate(-90 18 18)"
      />
      <text x="18" y="22" textAnchor="middle" className="ring-num">
        {score}
      </text>
    </svg>
  )
}

// DomainDetail is the review drawer for one classified domain: the legitimacy
// score and what moved it, the model's opinion when one was asked, the clients
// that queried it, WHOIS/RDAP data, and the decision actions in the footer.
// Block/Allow open the category + note form inside the drawer; a failed save
// keeps the drawer open with the error and the typed note.
export default function DomainDetail({
  c,
  onClose,
  canEdit,
  onDecide,
  onDismiss,
}: {
  c: Classification
  onClose: () => void // must be stable (Modal re-focuses when it changes)
  canEdit: boolean
  onDecide: (c: Classification, decision: Decision, category: string, note: string) => Promise<void>
  onDismiss: (c: Classification) => Promise<void>
}) {
  const [whois, setWhois] = useState<WhoisInfo | null>(null)
  const [whoisErr, setWhoisErr] = useState('')
  const [loading, setLoading] = useState(true)
  const [clients, setClients] = useState<DomainClient[] | null>(null)
  const [clientsErr, setClientsErr] = useState('')
  const [mode, setMode] = useState<Decision | null>(null)
  const [actErr, setActErr] = useState('')
  const [dismissing, setDismissing] = useState(false)
  const formRef = useRef<HTMLDivElement>(null)

  useEffect(() => {
    let alive = true
    setLoading(true)
    setWhois(null)
    setWhoisErr('')
    setClients(null)
    setClientsErr('')
    api
      .whois(c.domain)
      .then((r) => alive && (r.ok && r.whois ? setWhois(r.whois) : setWhoisErr(r.error || 'unavailable')))
      .catch((e) => alive && setWhoisErr(e.message))
      .finally(() => alive && setLoading(false))
    api
      .domainClients(c.domain)
      .then((r) => alive && setClients(r.clients))
      .catch((e) => alive && setClientsErr(e.message))
    return () => {
      alive = false
    }
  }, [c.domain])

  const d = useDecision(mode ?? 'approve', c.category, c.note, async (category, note) => {
    await onDecide(c, mode ?? 'approve', category, note)
    onClose()
  })
  const decide = (m: Decision) => {
    setActErr('')
    setMode(m)
    requestAnimationFrame(() => formRef.current?.scrollIntoView({ block: 'nearest' }))
  }
  const dismiss = async () => {
    setDismissing(true)
    setActErr('')
    try {
      await onDismiss(c)
      onClose()
    } catch (e: any) {
      setActErr(e.message)
      setDismissing(false)
    }
  }

  const blocked = c.status === 'auto' || c.status === 'approved'
  const decided = blocked || c.status === 'rejected'
  const score = typeof c.score === 'number' ? c.score : 100
  const factors = c.factors || []
  const lowered = factors.filter((f) => f.delta < 0)
  const other = factors.filter((f) => f.delta >= 0)
  // A static-only verdict has no LLM behind it (model is "static analysis" / empty).
  const aiVerdict = !!c.model && c.model !== 'static analysis'
  const headline = c.trusted
    ? 'Trusted domain'
    : score < 50
      ? c.threat
        ? 'Likely malicious'
        : 'Block candidate'
      : score < 70
        ? 'Worth watching'
        : 'Looks legitimate'

  const footer = !canEdit ? undefined : mode ? (
    <DecisionActions d={d} onCancel={() => setMode(null)} cancelLabel="Back" />
  ) : (
    <>
      {!blocked && (
        <button className="btn danger solid" onClick={() => decide('approve')}>
          Block domain
        </button>
      )}
      {c.status !== 'rejected' && (
        <button className="btn" onClick={() => decide('reject')}>
          Allow
        </button>
      )}
      {decided && (
        <button className="btn" onClick={() => decide(blocked ? 'approve' : 'reject')} title="Change the category or note of this decision">
          Edit review
        </button>
      )}
      {c.status === 'suggested' && (
        <button className="btn quiet" onClick={dismiss} disabled={dismissing} title="Hide it for now; it may come back if it is re-scored">
          {dismissing ? 'Dismissing…' : 'Dismiss'}
        </button>
      )}
    </>
  )

  return (
    <Modal
      title={<span className="mono">{c.domain}</span>}
      eyebrow={
        <>
          {statusLabel(c.status)}
          {c.updated_at ? ` · scored ${ago(c.updated_at)}` : ''}
          {clients && clients.length > 0 ? ` · ${clients.length} client${clients.length === 1 ? '' : 's'}` : ''}
        </>
      }
      onClose={onClose}
      footer={footer}
    >
      {actErr && (
        <div className="error" role="alert">
          {actErr}
        </div>
      )}
      {mode && (
        <div ref={formRef} className="decision-pane">
          <h3>{mode === 'approve' ? (decided ? 'Edit the block decision' : 'Block this domain') : decided ? 'Edit the allow decision' : 'Allow this domain'}</h3>
          <DecisionFields d={d} />
        </div>
      )}

      <div className="big-score">
        <ScoreRing score={score} />
        <div>
          <b>{headline}</b>
          <div className="muted">
            Legitimacy {score} of 100{score < 50 ? ' — below 50 makes it a block candidate.' : '.'}
          </div>
          <div className="tags">
            <span className={`tag ${catTag(c.category)}`}>{cap(c.category)}</span>
            {c.threat && <span className="tag block">On a threat feed</span>}
            {c.trusted && <span className="tag ok">Trusted</span>}
          </div>
        </div>
      </div>

      <div>
        <h3>What lowered the score</h3>
        {lowered.length === 0 ? (
          <p className="muted nomargin">Nothing — no risk factor fired. Every domain starts at 100.</p>
        ) : (
          <ul className="factors">
            {lowered.map((f, i) => (
              <li key={i}>
                <span>{f.label}</span>
                <span className="pts down">{f.delta.toString().replace('-', '−')}</span>
                {f.detail && <small>{f.detail}</small>}
              </li>
            ))}
          </ul>
        )}
        {other.length > 0 && (
          <>
            <h3 className="sub-h">Other signals</h3>
            <ul className="factors">
              {other.map((f, i) => (
                <li key={i}>
                  <span>{f.label}</span>
                  <span className={`pts${f.delta > 0 ? ' up' : ' none'}`}>{f.delta > 0 ? `+${f.delta}` : '—'}</span>
                  {f.detail && <small>{f.detail}</small>}
                </li>
              ))}
            </ul>
          </>
        )}
      </div>

      <div className="verdict">
        {aiVerdict ? (
          <>
            <b>Model opinion:</b> {cap(c.category)}
            {c.reason && <small>“{c.reason}” — {c.model}</small>}
          </>
        ) : (
          <>
            <b>Summary:</b> {c.reason || 'No summary recorded.'}
            <small>Static analysis only, no language model was asked.</small>
          </>
        )}
      </div>

      {c.note && (
        <div>
          <h3>Review note</h3>
          <p className="nomargin wrap">{c.note}</p>
        </div>
      )}

      <div>
        <h3>Clients asking for it</h3>
        {clientsErr ? (
          <p className="muted nomargin">Clients unavailable: {clientsErr}</p>
        ) : clients === null ? (
          <Spinner label="Loading…" />
        ) : clients.length === 0 ? (
          <p className="muted nomargin">No queries for this domain in the retained logs.</p>
        ) : (
          <div className="table-scroll">
            <table className="compact">
              <thead>
                <tr>
                  <th>Client</th>
                  <th className="num">Queries</th>
                  <th className="num">Blocked</th>
                  <th className="hide-sm">Last seen</th>
                </tr>
              </thead>
              <tbody>
                {clients.map((cl) => (
                  <tr key={cl.client}>
                    <td>
                      {cl.name ? (
                        <>
                          {cl.name}
                          <div className="mono faint">
                            {cl.client}
                            {cl.source && ` · ${cl.source}`}
                          </div>
                        </>
                      ) : (
                        <span className="mono">{cl.client}</span>
                      )}
                    </td>
                    <td className="num">{cl.count.toLocaleString()}</td>
                    <td className="num">{cl.blocked > 0 ? <span className="bad-text">{cl.blocked.toLocaleString()}</span> : <span className="faint">—</span>}</td>
                    <td className="muted hide-sm nowrap">{fmtTime(cl.last_seen)}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </div>

      <div>
        <h3>Registration (WHOIS)</h3>
        {loading ? (
          <Spinner label="Looking up…" />
        ) : whoisErr ? (
          <p className="muted nomargin">WHOIS unavailable: {whoisErr}</p>
        ) : whois ? (
          <dl className="kv">
            {whois.registrant && (
              <>
                <dt>Registrant</dt>
                <dd>{whois.registrant}</dd>
              </>
            )}
            <dt>Registrar</dt>
            <dd>{whois.registrar || '—'}</dd>
            <dt>Registered</dt>
            <dd>
              {fmtDate(whois.created)}
              {whois.age_days > 0 && (
                <span className={`tag ${whois.age_days < 90 ? 'block' : ''} age`}>
                  {whois.age_days.toLocaleString()} days old
                </span>
              )}
            </dd>
            <dt>Expires</dt>
            <dd>{fmtDate(whois.expires)}</dd>
            <dt>Updated</dt>
            <dd>{fmtDate(whois.updated)}</dd>
            {whois.nameservers?.length > 0 && (
              <>
                <dt>Nameservers</dt>
                <dd className="mono">{whois.nameservers.join(', ')}</dd>
              </>
            )}
            {whois.status?.length > 0 && (
              <>
                <dt>Status</dt>
                <dd className="small">{whois.status.join(', ')}</dd>
              </>
            )}
          </dl>
        ) : null}
      </div>
    </Modal>
  )
}
