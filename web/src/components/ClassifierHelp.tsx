import Modal from './Modal'

// A single step box in the scoring flow.
function Step({ tone = '', children }: { tone?: string; children: React.ReactNode }) {
  return <div className={`flow-box ${tone}`}>{children}</div>
}
// A deduction hanging off the main path.
function Deduct({ pts, children }: { pts: string; children: React.ReactNode }) {
  return (
    <li>
      <span>{children}</span>
      <span className="pts down">{pts}</span>
    </li>
  )
}
const Arrow = () => (
  <div className="flow-arrow" aria-hidden="true">
    ↓
  </div>
)

// ClassifierHelp explains how a domain's legitimacy score is built and what the
// review actions do. Opened from "How scoring works" on the Review tab.
export default function ClassifierHelp({ onClose }: { onClose: () => void }) {
  return (
    <Modal title="How scoring works" eyebrow="Domain classification" onClose={onClose} size="wide">
      <p className="muted nomargin">
        Every <em>newly seen registered domain</em> is scored the way a security analyst would: it <b>starts at 100</b> (presumed
        legitimate) and each risk factor deducts from that. Most of the work is <b>static analysis</b> — threat feeds, reputation
        services, WHOIS age, risky TLDs and look-alike names — with no AI involved. A language model (local, or a hosted provider
        such as Anthropic) is an <b>optional</b> extra signal that mainly cuts false positives. It is one bounded factor, so a
        confidently wrong model can never block a legitimate site on its own. Scoring runs in the background, never on the DNS
        path, so resolution stays fast.
      </p>

      <div>
        <h3>How the score is built</h3>
        <div className="flow">
          <Step tone="info">
            Start at <b>100</b> — every domain is presumed legitimate.
          </Step>
          <Arrow />
          <Step>Gather signals: trusted and threat lists, WHOIS (age, owner, nameservers), TLD and the shape of the name.</Step>
          <Arrow />
          <Step tone="ok">
            <b>Trusted shortcut</b> — on the popular-domains list, <em>or</em> served by a trusted company’s own nameservers (e.g.{' '}
            <code>apple.com</code>): the score stays at <b>100</b>. Nameservers can’t be faked, so this is the strongest guard against
            false positives and it overrides everything below.
          </Step>
          <Arrow />
          <Step>
            Otherwise, deduct for each risk factor:
            <ul className="factors flow-factors">
              <Deduct pts="−70">
                On a <b>threat feed</b> — strong, but weighed with the rest, not an automatic block
              </Deduct>
              <Deduct pts="−6 to −45">
                <b>Young domain</b> — newer means a bigger hit; phishing and malware are overwhelmingly young
              </Deduct>
              <Deduct pts="−15">
                <b>Risky TLD</b> — top-level domains with disproportionate abuse
              </Deduct>
              <Deduct pts="−8 to −28">
                <b>Look-alike name</b> — brand impersonation, punycode homographs, random (DGA) or digit/hyphen-heavy names
              </Deduct>
              <Deduct pts="0 to −60">
                <b>Reputation</b> — VirusTotal / AbuseIPDB flags (a clean report <em>raises</em> the floor instead)
              </Deduct>
              <Deduct pts="0 to −50">
                <b>Language model</b> (optional) — scaled by its confidence, capped so it can’t sink a domain alone
              </Deduct>
            </ul>
          </Step>
          <Arrow />
          <Step tone="ok">
            <b>Established floor</b> — a domain older than two years that isn’t on a threat feed can’t be pushed into block range by soft
            signals alone.
          </Step>
          <Arrow />
          <Step tone="warn">
            A <b>block candidate</b> needs a score <b>below 50</b> <em>and</em> a real threat signal (threat feed, reputation flag or the
            model’s security category), so a merely young, legitimate site is never blocked on its shape alone.
          </Step>
          <div className="flow-outcomes">
            <div className="flow-box block">
              <b>Below 35</b> in auto-block mode: blocked right away.
            </div>
            <div className="flow-box warn">
              <b>Below 50</b>: waits in “To check” for your decision.
            </div>
          </div>
        </div>
      </div>

      <div>
        <h3>What the numbers and tags mean</h3>
        <dl className="kv help-kv">
          <dt>Legitimacy</dt>
          <dd>
            The 0–100 score. Each domain’s drawer shows exactly which factors lowered it. Below 50, with a threat signal, it is a block
            candidate.
          </dd>
          <dt>
            <span className="tag block">Threat feed</span>
          </dt>
          <dd>
            On a known malware or phishing feed. A heavy deduction that also catches domains a model would miss, weighed against age and
            trust. Feeds refresh in the background; a domain already marked clean is flagged again if it later lands on a feed.
          </dd>
          <dt>
            <span className="tag ok">Trusted</span>
          </dt>
          <dd>A well-known legitimate site or trusted infrastructure. Scores 100 and is never blocked, even if a threat list names it.</dd>
          <dt>Category</dt>
          <dd>
            Security categories (ads, trackers, malware, phishing) can drive a block. Content categories such as social or streaming need
            the language model and are labels only; <code>other</code> means legitimate but unclassified.
          </dd>
        </dl>
      </div>

      <div>
        <h3>Enforcement modes</h3>
        <dl className="kv help-kv">
          <dt>Off</dt>
          <dd>Stop scoring new domains.</dd>
          <dt>Suggest</dt>
          <dd>Record verdicts; nothing is blocked until you approve it.</dd>
          <dt>Auto-block</dt>
          <dd>Security verdicts block right away (trusted domains are still spared).</dd>
        </dl>
      </div>

      <div>
        <h3>Deciding on a domain</h3>
        <dl className="kv help-kv">
          <dt>Block</dt>
          <dd>Enforce it. The block reaches every agent.</dd>
          <dt>Allow</dt>
          <dd>Never block this domain and stop suggesting it.</dd>
          <dt>Dismiss</dt>
          <dd>Hide it this once; it may be scored again and come back.</dd>
        </dl>
      </div>
    </Modal>
  )
}
