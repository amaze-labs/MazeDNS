import Modal from './Modal'

// A single step box in the scoring flow.
function Step({ tone = '', children }: { tone?: string; children: React.ReactNode }) {
  return <div className={`flow-box ${tone}`}>{children}</div>
}
// A branch annotation hanging off the main path (the "yes/no leads here" outcome).
function Branch({ tone = '', label, children }: { tone?: string; label: string; children: React.ReactNode }) {
  return (
    <div className={`flow-branch ${tone}`}>
      <span className="flow-branch-label">{label}</span>
      <span>{children}</span>
    </div>
  )
}
const Arrow = () => <div className="flow-arrow">↓</div>

export default function ClassifierHelp({ onClose }: { onClose: () => void }) {
  return (
    <Modal title="How AI classification &amp; scoring works" onClose={onClose}>
      <p className="muted" style={{ textAlign: 'left' }}>
        A small local model looks at every <em>new registered domain</em> your network queries and predicts what it is.
        Two public lists then corroborate or override that prediction, and your enforcement mode decides what actually
        happens. Nothing runs on the DNS hot path — classification is asynchronous, so resolution stays fast.
      </p>

      <h4>The scoring flow</h4>
      <div className="flow">
        <Step>A new registered domain is seen in a query</Step>
        <Arrow />
        <Step tone="info">
          The local model predicts a <strong>category</strong> + a <strong>confidence</strong> (0–100%)
        </Step>
        <Arrow />
        <Step tone="threat">On a threat-intel list? (abuse.ch URLhaus, by default)</Step>
        <Branch tone="block" label="yes">
          Force <strong>malicious</strong> and boost the score to <strong>≥97%</strong> — flagged even if the model
          missed it.
        </Branch>
        <Arrow />
        <Step tone="trusted">On the trusted list? (Majestic top domains, by default)</Step>
        <Branch tone="allow" label="yes">
          <strong>Never blocked</strong> — treated as a likely false positive (not even suggested).
        </Branch>
        <Arrow />
        <Step>Is the category a security one? (ads / trackers / malware / phishing)</Step>
        <Branch tone="info" label="no">
          Recorded as <strong>content</strong> (social, streaming, …) for visibility — never blocked.
        </Branch>
        <Arrow />
        <Step tone="mode">Your enforcement mode decides the outcome</Step>
        <div className="flow-outcomes">
          <div className="flow-box block">
            <strong>Auto-block</strong> → blocked immediately
          </div>
          <div className="flow-box suggest">
            <strong>Suggest</strong> → waits in “suggested” for your approval
          </div>
        </div>
      </div>

      <h4>What the numbers &amp; signals mean</h4>
      <ul className="help-list">
        <li>
          <strong>Confidence</strong> — how sure the model is. A threat-list match overrides it upward (≥97%); the
          trusted list overrides the decision regardless of confidence.
        </li>
        <li>
          <strong>🛡 threat</strong> — the domain is on a known-malware feed. Strong signal: it corroborates a malicious
          verdict and catches domains the model alone would have missed.
        </li>
        <li>
          <strong>✓ trusted</strong> — the domain is a well-known legitimate site. It is never blocked, which is how
          false positives are kept down. If a domain is on <em>both</em> lists, the threat list wins.
        </li>
        <li>
          <strong>Category</strong> — security categories (red) are block candidates; content categories (blue) are
          labels only; <code>other</code> is legitimate-but-unclassified.
        </li>
      </ul>

      <h4>Enforcement modes</h4>
      <ul className="help-list">
        <li>
          <strong>Off</strong> — stop classifying.
        </li>
        <li>
          <strong>Suggest &amp; approve</strong> — record verdicts; nothing blocks until you approve it.
        </li>
        <li>
          <strong>Auto-block</strong> — security verdicts block immediately (trusted domains are still spared).
        </li>
      </ul>

      <h4>Reviewing a suggestion</h4>
      <ul className="help-list">
        <li>
          <strong>Block</strong> — enforce it (also propagates to worker nodes).
        </li>
        <li>
          <strong>Allow</strong> — never block this domain (hide it from suggestions for good).
        </li>
        <li>
          <strong>Dismiss</strong> — hide it just once; it may be re-evaluated and resurface later.
        </li>
      </ul>
    </Modal>
  )
}
