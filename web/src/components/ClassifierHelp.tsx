import Modal from './Modal'

// A single step box in the scoring flow.
function Step({ tone = '', children }: { tone?: string; children: React.ReactNode }) {
  return <div className={`flow-box ${tone}`}>{children}</div>
}
// A factor hanging off the main path: a deduction, or (up) trust evidence.
function Deduct({ pts, up = false, children }: { pts: string; up?: boolean; children: React.ReactNode }) {
  return (
    <li>
      <span>{children}</span>
      <span className={`pts ${up ? 'up' : 'down'}`}>{pts}</span>
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
        Every <em>newly seen registered domain</em> is scored the way a security analyst would: it <b>starts at 85</b> (probably fine,
        but nothing vouches for it yet), risk factors deduct and trust evidence adds. Most of the work is <b>static analysis</b> — threat feeds, reputation
        services, WHOIS age, risky TLDs and look-alike names — with no AI involved. A language model (local, or a hosted provider
        such as Anthropic) is an <b>optional</b> extra signal that mainly cuts false positives. It is one bounded factor, so a
        confidently wrong model can never block a legitimate site on its own. Scoring runs in the background, never on the DNS
        path, so resolution stays fast.
      </p>

      <div>
        <h3>How the score is built</h3>
        <div className="flow">
          <Step tone="info">
            Start at <b>85</b> — an unknown domain is probably fine, but nothing vouches for it yet.
          </Step>
          <Arrow />
          <Step>Gather signals: trusted and threat lists, WHOIS (age, owner, nameservers), TLD and the shape of the name.</Step>
          <Arrow />
          <Step tone="ok">
            <b>Trusted shortcut</b> — on the popular-domains list, or CDN infrastructure itself: the score stays at <b>100</b>. This is the
            strongest guard against false positives and it overrides everything below. A customer site on a hosting platform
            (<code>something.web.app</code>) is scored like any other domain.
          </Step>
          <Arrow />
          <Step>
            Otherwise, weigh the evidence both ways. Deduct for each risk factor:
            <ul className="factors flow-factors">
              <Deduct pts="−45 to −90">
                On a <b>threat feed</b> — one feed may be a misreport; two or more is corroborated
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
              <Deduct pts="−10">
                <b>Hosting platform</b> — a customer site on workers.dev, github.io, netlify.app… anyone can publish there
              </Deduct>
              <Deduct pts="−20">
                <b>Suspended</b> — the registration is on hold or being deleted, typical after a takedown
              </Deduct>
              <Deduct pts="0 to −60">
                <b>Reputation</b> — VirusTotal / AbuseIPDB / Kaspersky flags
              </Deduct>
              <Deduct pts="0 to −50">
                <b>Language model</b> (optional) — scaled by its confidence, capped so it can’t sink a domain alone
              </Deduct>
            </ul>
            Add for trust evidence (at most <b>+40</b> in total, <b>+10</b> against a corroborated threat):
            <ul className="factors flow-factors">
              <Deduct up pts="+8 to +20">
                <b>Old registration</b> — 2, 5 or 10+ years
              </Deduct>
              <Deduct up pts="+15">
                <b>Own nameservers</b> — served only by a trusted company’s nameservers (e.g. <code>aaplimg.com</code> on Apple’s),
                checked over encrypted DNS; shared DNS hosts such as Cloudflare or GoDaddy serve anyone’s domain, so they don’t count
              </Deduct>
              <Deduct up pts="+4 to +8">
                <b>How it’s held</b> — registry locks, a named owner, paid years ahead, DNSSEC
              </Deduct>
              <Deduct up pts="+3 to +10">
                <b>Clean reputation</b> — VirusTotal clean, Kaspersky green, no abuse on its IP
              </Deduct>
            </ul>
            The language model can lower the score but never raise it: it reads the domain name, which an attacker chooses. WHOIS data
            from plain-text (port-43) servers can likewise only lower it, since it could be forged in transit.
          </Step>
          <Arrow />
          <Step tone="ok">
            <b>Safety floors</b> — a domain older than two years, or reported clean by VirusTotal, can’t be pushed into block range by
            soft signals alone (a single feed, the model, the shape of the name).
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
            The 0–100 score. Each domain’s drawer shows exactly which factors lowered and raised it. Below 50, with a threat signal, it is a block
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
