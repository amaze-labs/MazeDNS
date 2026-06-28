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
        Every <em>new registered domain</em> your network queries is scored like a SOC analyst would: it{' '}
        <strong>starts at 100% legitimate</strong>, and each risk factor deducts from that score. The local model's read
        is just <em>one</em> of those factors (and a bounded one), so a confidently-wrong model can no longer
        single-handedly block a legitimate site. Nothing runs on the DNS hot path — scoring is asynchronous, so
        resolution stays fast.
      </p>

      <h4>How the score is built</h4>
      <div className="flow">
        <Step tone="info">
          Start at <strong>100% legitimate</strong> — every domain is presumed innocent
        </Step>
        <Arrow />
        <Step>Gather signals: trusted &amp; threat lists, WHOIS (age, ownership, nameservers), TLD &amp; name shape</Step>
        <Arrow />
        <Step tone="allow">
          <strong>Trusted shortcut</strong> — on the popular-domains list, <em>or</em> served by a trusted entity's own
          nameservers (e.g. <code>apple.com</code>) → score stays <strong>100</strong>. Nameservers can't be faked, so
          this is the strongest false-positive guard, and it overrides everything below.
        </Step>
        <Arrow />
        <Step>Otherwise, deduct for each risk factor:</Step>
        <Branch tone="block" label="−70">
          on a <strong>threat-intel</strong> feed (strong, but weighed with the rest — not an automatic block)
        </Branch>
        <Branch tone="block" label="−45…−6">
          <strong>young domain</strong> (newer = bigger hit — phishing/malware is overwhelmingly young)
        </Branch>
        <Branch tone="block" label="−15">
          <strong>risky TLD</strong> (TLDs with disproportionate abuse)
        </Branch>
        <Branch tone="block" label="−8…−20">
          <strong>look-alike name shape</strong> (punycode/homograph, random/DGA, digit- or hyphen-heavy)
        </Branch>
        <Branch tone="block" label="−0…−50">
          <strong>model assessment</strong> — scaled by its confidence, but capped so it can't sink a domain alone
        </Branch>
        <Arrow />
        <Step tone="allow">
          <strong>Established floor</strong> — a &gt;2-year-old domain that isn't on a threat feed can't be pushed into
          block range by soft signals alone
        </Step>
        <Arrow />
        <Step tone="mode">
          Block candidate when legitimacy <strong>&lt; 50%</strong> AND there's a real threat indicator (model security
          category or a threat-feed hit) — so a merely <em>young</em> legit site is never blocked on structure alone
        </Step>
        <div className="flow-outcomes">
          <div className="flow-box block">
            <strong>&lt; 35%</strong> + auto-block mode → blocked immediately
          </div>
          <div className="flow-box suggest">
            <strong>&lt; 50%</strong> → waits in “suggested” for your approval
          </div>
        </div>
      </div>

      <h4>What the numbers &amp; signals mean</h4>
      <ul className="help-list">
        <li>
          <strong>Legitimacy</strong> — the 0–100% score. 100 = presumed-innocent; the breakdown in each domain's detail
          view shows exactly which factors dropped it. Below 50% (with a threat indicator) it's a block candidate.
        </li>
        <li>
          <strong>🛡 threat</strong> — on a known-malware/phishing feed. A heavy deduction that also catches domains the
          model alone would have missed — but it's weighed against age and trust, not taken as an absolute rule.
        </li>
        <li>
          <strong>✓ trusted</strong> — a well-known legitimate site (or on trusted infrastructure). Scores 100 and is
          never blocked — this is the main false-positive guard, and it wins over a threat-list hit.
        </li>
        <li>
          <strong>Category</strong> — security categories (red) can drive a block; content categories (blue) are labels
          only; <code>other</code> is legitimate-but-unclassified.
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
