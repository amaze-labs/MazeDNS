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
        For every <em>new registered domain</em> your network queries, two public lists are looked up first and fed
        into the model, so its category and reasoning are informed by them. The model then decides, a couple of safety
        rails act as a backstop, and your enforcement mode decides what actually happens. Nothing runs on the DNS hot
        path — classification is asynchronous, so resolution stays fast.
      </p>

      <h4>The scoring flow</h4>
      <div className="flow">
        <Step>A new registered domain is seen in a query</Step>
        <Arrow />
        <Step tone="info">
          Look up deterministic <strong>signals</strong> — is it on the <strong>trusted</strong> list (popular domains)
          and/or the <strong>threat-intel</strong> list (abuse.ch)?
        </Step>
        <Arrow />
        <Step tone="mode">
          The local model classifies it <strong>with those signals in hand</strong> → category + confidence
        </Step>
        <Arrow />
        <Step>Safety rails (backstop — a small model can still err, even with the hints)</Step>
        <Branch tone="block" label="threat">
          On a threat feed → force <strong>malicious</strong>, score <strong>≥97%</strong> — even if the model disagreed.
        </Branch>
        <Branch tone="allow" label="trusted">
          On the trusted list, <strong>or nameservers on a trusted domain</strong> (e.g. <code>apple.com</code>) →{' '}
          <strong>never blocked</strong>. Nameservers can't be faked, so this is the strongest false-positive guard.
        </Branch>
        <Branch tone="allow" label="established">
          Old/established domain (&gt;2 years) → <strong>not auto-blocked</strong> on a model-only verdict (sent to
          review) — phishing/malware is overwhelmingly young.
        </Branch>
        <Arrow />
        <Step>Is it a blocking verdict? (a security category, and not trusted)</Step>
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
          <strong>Confidence</strong> — how sure the model is (it already sees the threat/trusted signals). The safety
          rails still apply: a threat match floors it at ≥97%, and a trusted domain is never blocked regardless.
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
