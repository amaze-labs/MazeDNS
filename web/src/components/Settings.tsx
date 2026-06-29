import { useEffect, useRef, useState } from 'react'
import {
  api,
  type Settings as S,
  type ForwardGroup,
  type ClassifierSettings,
  type ClassifierStatus,
  type NetbirdSettings,
  type VMExportSettings,
} from '../api'
import Spinner from './Spinner'

const linesToList = (s: string) =>
  s.split(/[\n,]+/).map((x) => x.trim()).filter(Boolean)

// onClassifierChange lets the app refresh its nav (the AI tab appears/disappears
// with the classifier's enabled state).
export default function Settings({ onClassifierChange }: { onClassifierChange?: () => void }) {
  const [s, setS] = useState<S | null>(null)
  const [upstreams, setUpstreams] = useState('')
  const [forwarders, setForwarders] = useState<ForwardGroup[]>([])
  const [err, setErr] = useState('')
  const [ok, setOk] = useState(false)
  const [saving, setSaving] = useState(false)
  const [importMode, setImportMode] = useState<'merge' | 'replace'>('merge')
  const [importMsg, setImportMsg] = useState('')
  const fileRef = useRef<HTMLInputElement>(null)

  // Classifier settings (separate endpoint; null until loaded / if unavailable).
  const [cls, setCls] = useState<ClassifierSettings | null>(null)
  const [clsInfo, setClsInfo] = useState<ClassifierStatus | null>(null)
  const [testing, setTesting] = useState(false)
  const [testMsg, setTestMsg] = useState<{ ok: boolean; text: string } | null>(null)

  // NetBird client-identity integration (separate endpoint).
  const [nb, setNb] = useState<NetbirdSettings | null>(null)
  const [nbInfo, setNbInfo] = useState<{ has_token: boolean; peer_count: number } | null>(null)
  const [nbTesting, setNbTesting] = useState(false)
  const [nbMsg, setNbMsg] = useState<{ ok: boolean; text: string } | null>(null)

  // VictoriaMetrics metrics export.
  const [vm, setVm] = useState<VMExportSettings | null>(null)
  const [vmHasPassword, setVmHasPassword] = useState(false)

  const load = async () => {
    try {
      const cur = await api.settings()
      setS(cur)
      setUpstreams((cur.upstreams || []).join('\n'))
      setForwarders(cur.forwarders || [])
    } catch (e: any) {
      setErr(e.message)
    }
    api
      .classifier()
      .then((st) => {
        setCls(st.settings)
        setClsInfo(st)
      })
      .catch(() => setCls(null))
    api
      .netbird()
      .then((r) => {
        setNb(r.settings)
        setNbInfo({ has_token: r.has_token, peer_count: r.peer_count })
      })
      .catch(() => setNb(null))
    api
      .metricsExport()
      .then((r) => {
        setVm(r.settings)
        setVmHasPassword(r.has_password)
      })
      .catch(() => setVm(null))
  }
  useEffect(() => {
    load()
  }, [])

  const testClassifier = async () => {
    if (!cls) return
    setTesting(true)
    setTestMsg(null)
    try {
      const r = await api.testClassifier(cls)
      setTestMsg(
        r.ok
          ? { ok: true, text: `Connected — classified ${r.domain} as “${r.category}” (${Math.round((r.confidence || 0) * 100)}%).` }
          : { ok: false, text: r.error || 'Test failed.' },
      )
    } catch (e: any) {
      setTestMsg({ ok: false, text: e.message })
    } finally {
      setTesting(false)
    }
  }

  const testNetbird = async () => {
    if (!nb) return
    setNbTesting(true)
    setNbMsg(null)
    try {
      const r = await api.testNetbird(nb)
      setNbMsg(r.ok ? { ok: true, text: `Connected — ${r.peer_count} peers found.` } : { ok: false, text: r.error || 'Test failed.' })
    } catch (e: any) {
      setNbMsg({ ok: false, text: e.message })
    } finally {
      setNbTesting(false)
    }
  }

  if (!s) {
    return (
      <div>
        <h2>Settings</h2>
        {err ? <div className="error">{err}</div> : <Spinner label="Loading…" />}
      </div>
    )
  }

  const patch = (p: Partial<S>) => setS({ ...s, ...p })
  const patchCache = (p: Partial<S['cache']>) => setS({ ...s, cache: { ...s.cache, ...p } })

  const setFwd = (i: number, f: Partial<ForwardGroup>) =>
    setForwarders(forwarders.map((g, j) => (j === i ? { ...g, ...f } : g)))
  const addFwd = () => setForwarders([...forwarders, { suffix: '', upstreams: [] }])
  const delFwd = (i: number) => setForwarders(forwarders.filter((_, j) => j !== i))

  const doExport = async () => {
    setErr('')
    try {
      const blob = await api.exportConfig()
      const url = URL.createObjectURL(blob)
      const a = document.createElement('a')
      a.href = url
      a.download = `mazedns-config-${new Date().toISOString().slice(0, 10)}.json`
      a.click()
      URL.revokeObjectURL(url)
    } catch (e: any) {
      setErr(e.message)
    }
  }

  const doImport = async (file: File) => {
    setErr('')
    setImportMsg('')
    if (
      importMode === 'replace' &&
      !window.confirm('Replace mode clears all existing rules and rewrites before importing. Continue?')
    ) {
      if (fileRef.current) fileRef.current.value = ''
      return
    }
    try {
      const bundle = JSON.parse(await file.text())
      const res = await api.importConfig(bundle, importMode)
      setImportMsg(
        `Imported ${res.rules} rules, ${res.rewrites} rewrites${res.settings ? ', settings applied' : ''} (${res.mode}).`,
      )
      await load()
    } catch (e: any) {
      setErr(e.message)
    } finally {
      if (fileRef.current) fileRef.current.value = ''
    }
  }

  // saveAll persists every settings section with a single button: operational
  // settings, then the AI classifier, NetBird, and metrics export (each only if
  // present). Stops at the first failure and reports one result.
  const saveAll = async () => {
    setSaving(true)
    setErr('')
    setOk(false)
    try {
      const body: S = {
        ...s,
        upstreams: linesToList(upstreams),
        forwarders: forwarders
          .map((g) => ({ suffix: g.suffix.trim(), upstreams: g.upstreams }))
          .filter((g) => g.suffix && g.upstreams.length > 0),
      }
      const saved = await api.saveSettings(body)
      setS(saved)
      setUpstreams((saved.upstreams || []).join('\n'))
      setForwarders(saved.forwarders || [])

      if (cls) {
        setCls(await api.saveClassifierSettings(cls))
        onClassifierChange?.()
      }
      if (nb) setNb(await api.saveNetbird(nb))
      if (vm) {
        const v = await api.saveMetricsExport(vm)
        setVm(v)
        setVmHasPassword(v.password !== '' || vmHasPassword)
      }
      setOk(true)
    } catch (e: any) {
      setErr(e.message)
    } finally {
      setSaving(false)
    }
  }

  return (
    <div className="settings">
      <h2>Settings</h2>
      <p className="muted">
        Operational settings are stored in the database and applied live — no restart needed.
        Bootstrap options (listen addresses, TLS, admin credentials, SSO) stay in the config file / env.
      </p>
      {err && <div className="error">{err}</div>}

      <details className="settings-card" open>
        <summary>Upstream resolvers</summary>
        <label className="muted">
          One per line, tried in order. Plain DNS <code>host:port</code> (e.g. <code>1.1.1.1:53</code>), or encrypted:
          DNS-over-TLS <code>tls://1.1.1.1:853#cloudflare-dns.com</code> or DNS-over-HTTPS{' '}
          <code>https://dns.quad9.net/dns-query</code>. <strong>DoT/DoH is recommended</strong> — connections are pooled,
          so large/DNSSEC-validated answers avoid UDP fragmentation and per-query handshakes (lower latency).
        </label>
        <div className="row" style={{ flexWrap: 'wrap', gap: 6, margin: '6px 0' }}>
          <span className="muted" style={{ alignSelf: 'center' }}>Quick fill (DoT):</span>
          <button type="button" className="btn ghost" onClick={() => setUpstreams('tls://1.1.1.1:853#cloudflare-dns.com\ntls://1.0.0.1:853#cloudflare-dns.com')}>
            Cloudflare
          </button>
          <button type="button" className="btn ghost" onClick={() => setUpstreams('tls://9.9.9.9:853#dns.quad9.net\ntls://149.112.112.112:853#dns.quad9.net')}>
            Quad9
          </button>
          <button type="button" className="btn ghost" onClick={() => setUpstreams('tls://8.8.8.8:853#dns.google\ntls://8.8.4.4:853#dns.google')}>
            Google
          </button>
        </div>
        <textarea
          rows={4}
          value={upstreams}
          onChange={(e) => setUpstreams(e.target.value)}
          placeholder="tls://1.1.1.1:853#cloudflare-dns.com&#10;tls://9.9.9.9:853#dns.quad9.net"
        />
        <p className="hint" style={{ textAlign: 'left' }}>
          A quick-fill replaces the box; click <strong>Save changes</strong> below to apply.
        </p>
      </details>

      <details className="settings-card" open>
        <summary>Conditional forwarders</summary>
        <label className="muted">Route queries for a domain suffix to specific upstreams.</label>
        {forwarders.map((g, i) => (
          <div className="row" key={i}>
            <input
              placeholder="suffix (e.g. lan)"
              value={g.suffix}
              onChange={(e) => setFwd(i, { suffix: e.target.value })}
            />
            <input
              placeholder="upstreams, comma-separated"
              value={g.upstreams.join(', ')}
              onChange={(e) => setFwd(i, { upstreams: linesToList(e.target.value) })}
            />
            <button className="del" onClick={() => delFwd(i)}>
              ✕
            </button>
          </div>
        ))}
        <button className="btn ghost" onClick={addFwd}>
          + Add forwarder
        </button>
      </details>

      <details className="settings-card" open>
        <summary>Filtering &amp; protocol</summary>
        <div className="field">
          <label>Block response</label>
          <select value={s.block_response} onChange={(e) => patch({ block_response: e.target.value })}>
            <option value="nxdomain">NXDOMAIN</option>
            <option value="zeroip">Zero IP (0.0.0.0 / ::)</option>
          </select>
        </div>
        <div className="field">
          <label>Rate limit (queries/min per client, 0 = off)</label>
          <input
            type="number"
            min={0}
            value={s.rate_limit_qpm}
            onChange={(e) => patch({ rate_limit_qpm: Number(e.target.value) })}
          />
        </div>
      </details>

      <details className="settings-card" open>
        <summary>DNSSEC</summary>
        <label className="muted">
          DNSSEC lets a resolver cryptographically verify that DNS answers are authentic and untampered. When enabled,
          MazeDNS sets the DNSSEC-OK (DO) bit on upstream queries and surfaces the Authenticated Data (AD) flag in
          responses, so signed zones are validated by your upstream resolver and the result is passed through. Use an
          upstream that performs validation (e.g. 1.1.1.1, 9.9.9.9, 8.8.8.8).
        </label>
        <div className="field">
          <label className="toggle">
            <input type="checkbox" checked={s.dnssec} onChange={(e) => patch({ dnssec: e.target.checked })} />
            <span className="track">
              <span className="thumb" />
            </span>
            <span className="toggle-label">
              Enable DNSSEC — set the DO bit upstream and surface the AD flag
            </span>
          </label>
        </div>
        <p className="muted" style={{ textAlign: 'left', marginTop: 4 }}>
          Currently <strong>{s.dnssec ? 'enabled' : 'disabled'}</strong>. Changes apply live — no restart.
        </p>
      </details>

      <details className="settings-card" open>
        <summary>Cache</summary>
        <div className="field">
          <label className="toggle">
            <input
              type="checkbox"
              checked={s.cache.enabled}
              onChange={(e) => patchCache({ enabled: e.target.checked })}
            />
            <span className="track">
              <span className="thumb" />
            </span>
            <span className="toggle-label">Enable response cache</span>
          </label>
        </div>
        <div className="field">
          <label>Max entries</label>
          <input
            type="number"
            min={0}
            value={s.cache.max_entries}
            onChange={(e) => patchCache({ max_entries: Number(e.target.value) })}
          />
        </div>
        <div className="field">
          <label>Min TTL (sec)</label>
          <input
            type="number"
            min={0}
            value={s.cache.min_ttl_sec}
            onChange={(e) => patchCache({ min_ttl_sec: Number(e.target.value) })}
          />
        </div>
        <div className="field">
          <label>Max TTL (sec)</label>
          <input
            type="number"
            min={0}
            value={s.cache.max_ttl_sec}
            onChange={(e) => patchCache({ max_ttl_sec: Number(e.target.value) })}
          />
        </div>
      </details>

      {cls && (
        <details className="settings-card" open>
          <summary>AI classification (local LLM)</summary>
          <label className="muted">
            Classify newly-seen domains with a local OpenAI-compatible model (Ollama, llama.cpp, LM Studio) instead of
            maintaining blocklists. Runs on the master; auto-blocks also propagate to workers.
          </label>
          <div className="field">
            <label className="toggle">
              <input type="checkbox" checked={cls.enabled} onChange={(e) => setCls({ ...cls, enabled: e.target.checked })} />
              <span className="track">
                <span className="thumb" />
              </span>
              <span className="toggle-label">Enable classification</span>
            </label>
          </div>
          <div className="field">
            <label>Enforcement mode</label>
            <select value={cls.mode} onChange={(e) => setCls({ ...cls, mode: e.target.value })}>
              <option value="off">Off</option>
              <option value="suggest">Suggest &amp; approve</option>
              <option value="auto">Auto-block</option>
            </select>
          </div>
          <div className="field">
            <label>Model endpoint (OpenAI-compatible base URL)</label>
            <input
              value={cls.endpoint}
              onChange={(e) => setCls({ ...cls, endpoint: e.target.value })}
              placeholder="http://localhost:11434/v1"
            />
          </div>
          <div className="field">
            <label>Model</label>
            <input value={cls.model} onChange={(e) => setCls({ ...cls, model: e.target.value })} placeholder="llama3.2" />
          </div>
          <div className="field">
            <label>
              API key (optional; usually empty for local models){' '}
              {clsInfo?.has_api_key && <span className="badge allow">key set</span>}
            </label>
            <input
              type="password"
              value={cls.api_key}
              onChange={(e) => setCls({ ...cls, api_key: e.target.value })}
              placeholder={clsInfo?.has_api_key ? '•••••••••••••• (saved — leave blank to keep)' : 'usually empty for local models'}
            />
          </div>
          <div className="field">
            <label>Min gap between model calls (ms)</label>
            <input
              type="number"
              min={0}
              value={cls.min_gap_ms}
              onChange={(e) => setCls({ ...cls, min_gap_ms: Number(e.target.value) })}
            />
          </div>
          <div className="field">
            <label>Request timeout (seconds) — raise it if a local model is slow to warm up</label>
            <input
              type="number"
              min={1}
              value={cls.timeout_sec}
              onChange={(e) => setCls({ ...cls, timeout_sec: Number(e.target.value) })}
            />
          </div>
          <h4 style={{ margin: '14px 0 4px' }}>Trusted list (reduce false positives)</h4>
          <p className="muted" style={{ textAlign: 'left' }}>
            Domains on the trusted list are never blocked, even if the model flags them.
          </p>
          <div className="field">
            <label className="toggle">
              <input
                type="checkbox"
                checked={!cls.trusted_disable_default}
                onChange={(e) => setCls({ ...cls, trusted_disable_default: !e.target.checked })}
              />
              <span className="track">
                <span className="thumb" />
              </span>
              <span className="toggle-label">Use built-in public list (Majestic Million top domains)</span>
            </label>
          </div>
          <div className="field">
            <label>Additional custom trusted list (optional) — your own URL / file path (plain / hosts / ranked-CSV)</label>
            <input
              value={cls.trusted_list_url}
              onChange={(e) => setCls({ ...cls, trusted_list_url: e.target.value })}
              placeholder="https://… or /path/to/allowlist.txt"
            />
          </div>
          <div className="field">
            <label>Built-in list cap (0 = default 100k) — load only the top N most popular</label>
            <input
              type="number"
              min={0}
              value={cls.trusted_top_n}
              onChange={(e) => setCls({ ...cls, trusted_top_n: Number(e.target.value) })}
            />
          </div>

          <h4 style={{ margin: '14px 0 4px' }}>Threat-intelligence feeds (catch malicious domains)</h4>
          <p className="muted" style={{ textAlign: 'left' }}>
            Domains on any enabled feed corroborate a malicious verdict (and are flagged even if the model missed them).
            Enable as many as you like — they’re merged. More feeds = broader coverage (and bigger downloads on the
            master).
          </p>
          {(clsInfo?.threat_feed_catalog ?? []).map((f) => (
            <div className="field" key={f.key}>
              <label className="toggle">
                <input
                  type="checkbox"
                  checked={(cls.threat_feeds ?? []).includes(f.key)}
                  onChange={(e) => {
                    const cur = cls.threat_feeds ?? []
                    setCls({
                      ...cls,
                      threat_feeds: e.target.checked ? [...cur, f.key] : cur.filter((k) => k !== f.key),
                    })
                  }}
                />
                <span className="track">
                  <span className="thumb" />
                </span>
                <span className="toggle-label">
                  {f.name} — {f.desc}
                </span>
              </label>
            </div>
          ))}
          <div className="field">
            <label>Additional custom threat lists (optional) — one URL / file path per line</label>
            <textarea
              rows={2}
              value={cls.threat_list_url}
              onChange={(e) => setCls({ ...cls, threat_list_url: e.target.value })}
              placeholder="https://example.com/malware-domains.txt&#10;/path/to/threatlist.txt"
            />
          </div>
          <div className="field">
            <label className="toggle">
              <input
                type="checkbox"
                checked={cls.whois_enabled}
                onChange={(e) => setCls({ ...cls, whois_enabled: e.target.checked })}
              />
              <span className="track">
                <span className="thumb" />
              </span>
              <span className="toggle-label">
                Enrich with WHOIS (domain age, registrar) via RDAP — a strong signal for the model
              </span>
            </label>
          </div>

          <h4 style={{ textAlign: 'left', marginBottom: 4 }}>Reputation services (corroboration)</h4>
          <label className="muted" style={{ marginTop: 0 }}>
            Optional third-party lookups per new domain. A clean report raises the legitimacy score (fewer false
            positives); a malicious one lowers it. Keys are stored server-side and never shown back.
          </label>
          <div className="field">
            <label className="toggle">
              <input type="checkbox" checked={cls.vt_enabled} onChange={(e) => setCls({ ...cls, vt_enabled: e.target.checked })} />
              <span className="track">
                <span className="thumb" />
              </span>
              <span className="toggle-label">VirusTotal — check the domain's reputation</span>
            </label>
          </div>
          {cls.vt_enabled && (
            <div className="field">
              <label>VirusTotal API key {clsInfo?.has_vt_key && <span className="badge allow">key set</span>}</label>
              <input
                type="password"
                value={cls.vt_api_key}
                onChange={(e) => setCls({ ...cls, vt_api_key: e.target.value })}
                placeholder={clsInfo?.has_vt_key ? '•••••••••••••• (saved — leave blank to keep)' : 'paste your VirusTotal API key'}
              />
            </div>
          )}
          <div className="field">
            <label className="toggle">
              <input
                type="checkbox"
                checked={cls.abuseipdb_enabled}
                onChange={(e) => setCls({ ...cls, abuseipdb_enabled: e.target.checked })}
              />
              <span className="track">
                <span className="thumb" />
              </span>
              <span className="toggle-label">AbuseIPDB — check the domain's resolved IP</span>
            </label>
          </div>
          {cls.abuseipdb_enabled && (
            <div className="field">
              <label>AbuseIPDB API key {clsInfo?.has_abuseipdb_key && <span className="badge allow">key set</span>}</label>
              <input
                type="password"
                value={cls.abuseipdb_api_key}
                onChange={(e) => setCls({ ...cls, abuseipdb_api_key: e.target.value })}
                placeholder={clsInfo?.has_abuseipdb_key ? '•••••••••••••• (saved — leave blank to keep)' : 'paste your AbuseIPDB API key'}
              />
            </div>
          )}

          <div className="settings-actions">
            <button className="btn" onClick={testClassifier} disabled={testing}>
              {testing ? <Spinner label="Testing…" /> : 'Test connection'}
            </button>
            <span className="hint">Review verdicts in the AI tab.</span>
          </div>
          {testMsg && <div className={testMsg.ok ? 'ok-msg' : 'error'}>{testMsg.text}</div>}
        </details>
      )}

      {nb && (
        <details className="settings-card" open>
          <summary>NetBird client identity</summary>
          <label className="muted">
            Resolve client IPs to friendly names in the dashboard and the per-domain client list. When enabled, IPs are
            matched to their NetBird peer (name + hostname) via the NetBird API; otherwise a reverse-DNS (PTR) lookup is
            used as a fallback.
            {nbInfo ? ` Currently mapping ${nbInfo.peer_count} peer(s).` : ''}
          </label>
          <div className="field">
            <label className="toggle">
              <input type="checkbox" checked={nb.enabled} onChange={(e) => setNb({ ...nb, enabled: e.target.checked })} />
              <span className="track">
                <span className="thumb" />
              </span>
              <span className="toggle-label">Enable NetBird peer lookup</span>
            </label>
          </div>
          <div className="field">
            <label>NetBird API URL</label>
            <input
              value={nb.api_url}
              onChange={(e) => setNb({ ...nb, api_url: e.target.value })}
              placeholder="https://api.netbird.io"
            />
          </div>
          <div className="field">
            <label>API token (Personal Access Token)</label>
            <input
              type="password"
              value={nb.token}
              onChange={(e) => setNb({ ...nb, token: e.target.value })}
              placeholder={nbInfo?.has_token ? '•••••••• (unchanged)' : 'nbp_…'}
            />
          </div>
          <div className="settings-actions">
            <button className="btn" onClick={testNetbird} disabled={nbTesting}>
              {nbTesting ? <Spinner label="Testing…" /> : 'Test connection'}
            </button>
          </div>
          {nbMsg && <div className={nbMsg.ok ? 'ok-msg' : 'error'}>{nbMsg.text}</div>}
        </details>
      )}

      {vm && (
        <details className="settings-card" open>
          <summary>Metrics export — VictoriaMetrics</summary>
          <label className="muted">
            Push this node's Prometheus metrics to a VictoriaMetrics instance on an interval (its
            <code> /api/v1/import/prometheus </code> endpoint). Each node pushes its own metrics, labelled with the
            instance below, so a cluster aggregates in VM without VM having to scrape every node. Changes apply on the
            next push cycle.
          </label>
          <div className="field">
            <label className="toggle">
              <input type="checkbox" checked={vm.enabled} onChange={(e) => setVm({ ...vm, enabled: e.target.checked })} />
              <span className="track">
                <span className="thumb" />
              </span>
              <span className="toggle-label">Enable VictoriaMetrics export</span>
            </label>
          </div>
          <div className="field">
            <label>VictoriaMetrics URL</label>
            <input
              value={vm.url}
              onChange={(e) => setVm({ ...vm, url: e.target.value })}
              placeholder="http://victoriametrics:8428"
            />
          </div>
          <div className="field">
            <label>Push interval (seconds)</label>
            <input
              type="number"
              min={1}
              value={vm.interval_sec}
              onChange={(e) => setVm({ ...vm, interval_sec: Number(e.target.value) })}
            />
          </div>
          <div className="field">
            <label>Job label</label>
            <input value={vm.job} onChange={(e) => setVm({ ...vm, job: e.target.value })} placeholder="mazedns" />
          </div>
          <div className="field">
            <label>Instance label</label>
            <input
              value={vm.instance}
              onChange={(e) => setVm({ ...vm, instance: e.target.value })}
              placeholder="(blank = hostname)"
            />
          </div>
          <div className="field">
            <label>Username (optional)</label>
            <input value={vm.username} onChange={(e) => setVm({ ...vm, username: e.target.value })} />
          </div>
          <div className="field">
            <label>Password (optional)</label>
            <input
              type="password"
              value={vm.password}
              onChange={(e) => setVm({ ...vm, password: e.target.value })}
              placeholder={vmHasPassword ? '•••••••• (unchanged)' : ''}
            />
          </div>
        </details>
      )}

      <details className="settings-card danger-zone">
        <summary>⚠ Danger zone — backup &amp; restore</summary>
        <label className="muted">
          Export downloads settings, rules, and rewrites as one JSON file. Import restores it —
          <em> merge</em> upserts on top of what's here; <em> replace</em> wipes all rules and rewrites first
          (irreversible).
        </label>
        {importMsg && <div className="ok-msg">{importMsg}</div>}
        <div className="row">
          <button className="btn" onClick={doExport}>
            ⬇ Export config
          </button>
          <span className="import-group">
            <select value={importMode} onChange={(e) => setImportMode(e.target.value as 'merge' | 'replace')}>
              <option value="merge">Merge</option>
              <option value="replace">Replace</option>
            </select>
            <button className="btn" onClick={() => fileRef.current?.click()}>
              ⬆ Import file…
            </button>
          </span>
          <input
            ref={fileRef}
            type="file"
            accept="application/json,.json"
            hidden
            onChange={(e) => e.target.files?.[0] && doImport(e.target.files[0])}
          />
        </div>
      </details>

      {/* One global save for every section above. */}
      <div className="settings-savebar">
        {ok && <span className="ok-inline">Saved &amp; applied.</span>}
        <button className="btn ghost-danger" onClick={load} disabled={saving}>
          Reset
        </button>
        <button className="btn primary" onClick={saveAll} disabled={saving}>
          {saving ? 'Saving…' : 'Save changes'}
        </button>
      </div>
    </div>
  )
}
