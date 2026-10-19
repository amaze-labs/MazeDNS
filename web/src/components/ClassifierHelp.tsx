import type { ReactNode } from 'react'
import Modal from './Modal'
import '../styles/classifier-help.css'

// A single step box in a flow.
function Step({ tone = '', n, children }: { tone?: string; n?: number; children: ReactNode }) {
  return (
    <div className={`flow-box ${tone}`}>
      {n !== undefined && <span className="step-n">{n}</span>}
      {children}
    </div>
  )
}
// A factor hanging off the main path: a deduction, or (up) trust evidence.
function Deduct({ pts, up = false, children }: { pts: string; up?: boolean; children: ReactNode }) {
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

// ClassifierHelp explains domain classification end to end: what happens to
// a query, which names are never looked at, who sees what, how the score is
// built and what the review actions do. Opened from Filtering → Review and
// Settings → Classification.
export default function ClassifierHelp({ onClose }: { onClose: () => void }) {
  return (
    <Modal title="How classification works" eyebrow="Domain classification" onClose={onClose} size="wide">
      <div className="cls-help">
        <p className="muted nomargin">
          Classification scores every <em>newly seen registered domain</em> for risk, the way a security analyst would, so you
          don’t have to keep blocklists by hand. It runs on the control plane in the background, <b>never on the DNS path</b>: a
          query is answered at once, and its domain is looked at afterwards. Most of the work is <b>static analysis</b>. A language
          model is an optional extra signal that mainly cuts false positives, and it can never block a site on its own.
        </p>

        <div>
          <h3>From a query to a verdict</h3>
          <div className="flow">
            <Step n={1}>
              A client asks an agent for a name. The agent <b>answers right away</b> from its rules, cache or upstream: classification
              never delays a query.
            </Step>
            <Arrow />
            <Step n={2}>
              The agent ships the query to the control plane with its query log. Its <b>category</b> (social, streaming, …) is
              labelled there from local data; see “Categories” below.
            </Step>
            <Arrow />
            <Step n={3} tone="info">
              <b>Names that are never classified</b> stop here, so they never reach any outside service:
              <ul className="factors">
                <li>names answered by your <b>local records</b> (Local DNS);</li>
                <li>names under a <b>conditional forwarder’s</b> domain;</li>
                <li>
                  domains on your <b>Never classify</b> list (Settings → Classification), with their subdomains;
                </li>
                <li>
                  private-use names: <code>.lan</code>, <code>.local</code>, <code>.home.arpa</code>, <code>.internal</code>, reverse
                  lookups, single-label names.
                </li>
              </ul>
            </Step>
            <Arrow />
            <Step n={4}>
              The rest is reduced to its <b>registered domain</b> (<code>mail.example.co.uk</code> → <code>example.co.uk</code>) and
              queued. Each domain is <b>scored once</b>: its verdict sticks until you decide on it, start over, or a threat feed lists it
              later.
            </Step>
            <Arrow />
            <Step n={5}>
              If <b>classification is on</b>, the signals <b>you turned on</b> are gathered: the trusted list, threat feeds, WHOIS, the
              nameserver check, reputation services, the AI model. Off, nothing is gathered, downloaded or sent.
            </Step>
            <Arrow />
            <Step n={6}>
              The domain gets a <b>legitimacy score</b> from 0 to 100 (below), and a verdict: clean, or a block candidate.
            </Step>
            <Arrow />
            <Step n={7} tone="warn">
              The <b>enforcement mode</b> decides what a block candidate does: wait in Filtering → Review for you (Suggest), or block at
              once on every agent (Auto-block).
            </Step>
          </div>
        </div>

        <div>
          <h3>Who sees what</h3>
          <p className="muted small">
            Each service is used only when its switch is on in Settings → Classification, and only while classification is on.
          </p>
          <table className="who-sees">
            <thead>
              <tr>
                <th>Service</th>
                <th>What it receives</th>
                <th>Switch</th>
              </tr>
            </thead>
            <tbody>
              <tr>
                <td>majestic.com</td>
                <td>Nothing: the trusted list is downloaded.</td>
                <td>Trusted list</td>
              </tr>
              <tr>
                <td>Threat-feed publishers</td>
                <td>Nothing: each feed is downloaded (abuse.ch, GitHub…).</td>
                <td>Threat-intelligence feeds</td>
              </tr>
              <tr>
                <td>rdap.org, registries</td>
                <td>Every new domain.</td>
                <td>WHOIS</td>
              </tr>
              <tr>
                <td>Cloudflare, Quad9 (DoH)</td>
                <td>Domains served by a trusted company’s own nameservers.</td>
                <td>Nameserver check</td>
              </tr>
              <tr>
                <td>virustotal.com</td>
                <td>Every new domain.</td>
                <td>VirusTotal</td>
              </tr>
              <tr>
                <td>abuseipdb.com</td>
                <td>The address each new domain resolves to.</td>
                <td>AbuseIPDB</td>
              </tr>
              <tr>
                <td>opentip.kaspersky.com</td>
                <td>Every new domain.</td>
                <td>Kaspersky OpenTIP</td>
              </tr>
              <tr>
                <td>Your AI model</td>
                <td>Every new domain (your own endpoint, or the hosted provider’s API).</td>
                <td>Use an AI model</td>
              </tr>
            </tbody>
          </table>
        </div>

        <div>
          <h3>How the score is built</h3>
          <div className="flow">
            <Step tone="info">
              Start at <b>85</b>: an unknown domain is probably fine, but nothing vouches for it yet.
            </Step>
            <Arrow />
            <Step tone="ok">
              <b>Trusted shortcut</b>: on the trusted list, or CDN infrastructure itself, the score stays at <b>100</b>. This is the
              strongest guard against false positives and it overrides everything below. A customer site on a hosting platform
              (<code>something.web.app</code>) is scored like any other domain.
            </Step>
            <Arrow />
            <Step>
              Otherwise, weigh the evidence both ways. Deduct for each risk factor:
              <ul className="factors">
                <Deduct pts="−45 to −90">
                  On a <b>threat feed</b>: one feed may be a misreport; two or more is corroborated
                </Deduct>
                <Deduct pts="−6 to −45">
                  <b>Young domain</b> (WHOIS): newer means a bigger hit; phishing and malware are overwhelmingly young
                </Deduct>
                <Deduct pts="−15">
                  <b>Risky TLD</b>: top-level domains with disproportionate abuse
                </Deduct>
                <Deduct pts="−8 to −28">
                  <b>Look-alike name</b>: brand impersonation, punycode homographs, random (DGA) or digit/hyphen-heavy names
                </Deduct>
                <Deduct pts="−10">
                  <b>Hosting platform</b>: a customer site on workers.dev, github.io, netlify.app… anyone can publish there
                </Deduct>
                <Deduct pts="−20">
                  <b>Suspended</b>: the registration is on hold or being deleted, typical after a takedown
                </Deduct>
                <Deduct pts="0 to −60">
                  <b>Reputation</b>: VirusTotal, AbuseIPDB or Kaspersky flags
                </Deduct>
                <Deduct pts="0 to −50">
                  <b>Language model</b> (optional): scaled by its confidence, capped so it can’t sink a domain alone
                </Deduct>
              </ul>
              Add for trust evidence (at most <b>+40</b> in total, <b>+10</b> against a corroborated threat):
              <ul className="factors">
                <Deduct up pts="+8 to +20">
                  <b>Old registration</b>: 2, 5 or 10+ years
                </Deduct>
                <Deduct up pts="+15">
                  <b>Own nameservers</b>: served only by a trusted company’s nameservers (e.g. <code>aaplimg.com</code> on Apple’s),
                  confirmed by the nameserver check; shared DNS hosts such as Cloudflare or GoDaddy serve anyone’s domain, so they
                  don’t count
                </Deduct>
                <Deduct up pts="+4 to +8">
                  <b>How it’s held</b>: registry locks, a named owner, paid years ahead, DNSSEC
                </Deduct>
                <Deduct up pts="+3 to +10">
                  <b>Clean reputation</b>: VirusTotal clean, Kaspersky green, no abuse on its IP
                </Deduct>
              </ul>
              The language model can lower the score but never raise it: it reads the domain name, which an attacker chooses. WHOIS
              data from plain-text (port-43) servers can likewise only lower it, since it could be forged in transit. Only the
              signals you turned on count; the rest simply don’t apply.
            </Step>
            <Arrow />
            <Step tone="ok">
              <b>Safety floors</b>: a domain older than two years, or reported clean by VirusTotal, can’t be pushed into block range by
              soft signals alone (a single feed, the model, the shape of the name).
            </Step>
            <Arrow />
            <Step tone="warn">
              A <b>block candidate</b> needs a score <b>below 50</b> <em>and</em> a real threat signal (threat feed, reputation flag or
              the model’s security category), so a merely young, legitimate site is never blocked on its shape alone.
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
          <h3>Categories</h3>
          <p className="muted nomargin">
            Separate from the risk score, every query is labelled with what its domain is (social, streaming, shopping, …) from the
            first source that knows it: your override; <b>Local network</b> for names your records answer and private-use names; a
            security verdict the classifier enforces; the category database (UT1, downloaded); a built-in list of common platforms;
            and, when a model is on, the model’s answer. All of these are looked up on the control plane, so labelling sends nothing
            out. Filtering → Categories blocks whole categories on every agent.
          </p>
        </div>

        <div>
          <h3>What the numbers and tags mean</h3>
          <dl className="kv help-kv">
            <dt>Legitimacy</dt>
            <dd>
              The 0–100 score. Each domain’s drawer shows exactly which factors lowered and raised it. Below 50, with a threat
              signal, it is a block candidate.
            </dd>
            <dt>
              <span className="tag block">Threat feed</span>
            </dt>
            <dd>
              On a known malware or phishing feed. A heavy deduction that also catches domains a model would miss, weighed against
              age and trust. Feeds refresh in the background; a domain already marked clean is flagged again if it later lands on a
              feed.
            </dd>
            <dt>
              <span className="tag ok">Trusted</span>
            </dt>
            <dd>A well-known legitimate site or trusted infrastructure. Scores 100 and is never blocked, even if a threat list names it.</dd>
            <dt>Category</dt>
            <dd>
              What the domain is (see Categories above). A security reason (ads, trackers, malware, phishing) is shown next to it when
              the classifier blocks the domain for it.
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
      </div>
    </Modal>
  )
}
