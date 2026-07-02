import { useEffect, useRef, useState } from 'react'
import {
  api,
  type Settings as S,
  type ForwardGroup,
  type ClassifierSettings,
  type ClassifierStatus,
  type NetbirdSettings,
  type VMExportSettings,
  type VLExportSettings,
  type CPSettings,
} from '../api'
import Spinner from './Spinner'

const linesToList = (s: string) =>
  s.split(/[\n,]+/).map((x) => x.trim()).filter(Boolean)

// --- Upstream resolver editing ------------------------------------------------
// The textarea spec format (see resolver.ParseUpstream) is hard to get right by
// hand, so we edit each upstream as a structured row and serialize back to the
// canonical spec string the backend expects.
type UpProto = 'plain' | 'tls' | 'https'
type UpRow = { proto: UpProto; host: string; port: string; name: string; url: string }

const emptyRow = (): UpRow => ({ proto: 'plain', host: '', port: '', name: '', url: '' })

// splitHostPort separates host and port, leaving bracketed/bare IPv6 intact and
// falling back to def when no port is given.
const splitHostPort = (s: string, def: string): { host: string; port: string } => {
  if (s.startsWith('[')) {
    const end = s.indexOf(']')
    const host = s.slice(0, end + 1)
    const rest = s.slice(end + 1)
    return { host, port: rest.startsWith(':') ? rest.slice(1) : def }
  }
  if ((s.match(/:/g) || []).length === 1) {
    const [host, port] = s.split(':')
    return { host, port: port || def }
  }
  return { host: s, port: def } // no port, or bare IPv6
}

const parseUpstream = (raw: string): UpRow => {
  const spec = raw.trim()
  if (spec.startsWith('https://')) return { ...emptyRow(), proto: 'https', url: spec }
  if (spec.startsWith('tls://')) {
    let rest = spec.slice('tls://'.length)
    let name = ''
    const h = rest.indexOf('#')
    if (h >= 0) {
      name = rest.slice(h + 1)
      rest = rest.slice(0, h)
    }
    const { host, port } = splitHostPort(rest, '853')
    return { proto: 'tls', host, port, name, url: '' }
  }
  let rest = spec
  if (rest.startsWith('udp://')) rest = rest.slice('udp://'.length)
  else if (rest.startsWith('tcp://')) rest = rest.slice('tcp://'.length)
  const { host, port } = splitHostPort(rest, '53')
  return { proto: 'plain', host, port, name: '', url: '' }
}

const upstreamToSpec = (r: UpRow): string => {
  if (r.proto === 'https') return r.url.trim()
  const host = r.host.trim()
  if (!host) return ''
  const port = r.port.trim()
  if (r.proto === 'tls') {
    const hp = port ? `${host}:${port}` : host
    return r.name.trim() ? `tls://${hp}#${r.name.trim()}` : `tls://${hp}`
  }
  // Plain DNS: drop the redundant default :53 to keep the spec clean.
  return port && port !== '53' ? `${host}:${port}` : host
}

const rowsToText = (rows: UpRow[]) => rows.map(upstreamToSpec).filter(Boolean).join('\n')
const textToRows = (t: string): UpRow[] => {
  const rows = linesToList(t).map(parseUpstream)
  return rows.length ? rows : [emptyRow()]
}

// Well-known resolvers for the quick-fill buttons, with a variant per protocol.
const PROVIDERS = [
  { key: 'cloudflare', label: 'Cloudflare', ips: ['1.1.1.1', '1.0.0.1'], name: 'cloudflare-dns.com', doh: 'https://cloudflare-dns.com/dns-query' },
  { key: 'quad9', label: 'Quad9', ips: ['9.9.9.9', '149.112.112.112'], name: 'dns.quad9.net', doh: 'https://dns.quad9.net/dns-query' },
  { key: 'google', label: 'Google', ips: ['8.8.8.8', '8.8.4.4'], name: 'dns.google', doh: 'https://dns.google/dns-query' },
] as const

// onClassifierChange lets the app refresh its nav (the AI tab appears/disappears
// with the classifier's enabled state).
export default function Settings({ onClassifierChange }: { onClassifierChange?: () => void }) {
  const [s, setS] = useState<S | null>(null)
  const [upstreams, setUpstreams] = useState('')
  const [upRows, setUpRows] = useState<UpRow[]>([emptyRow()])
  const [rawUpstreams, setRawUpstreams] = useState(false)
  const [qfProto, setQfProto] = useState<UpProto>('tls')
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

  // VictoriaLogs query-log export.
  const [vl, setVl] = useState<VLExportSettings | null>(null)
  const [vlHasPassword, setVlHasPassword] = useState(false)

  // Control-plane runtime settings (SSO / session / cluster policy). Own endpoint.
  const [cp, setCp] = useState<CPSettings | null>(null)
  const [oidcHasSecret, setOidcHasSecret] = useState(false)
  const [hasMetricsToken, setHasMetricsToken] = useState(false)
  const [newScrapeToken, setNewScrapeToken] = useState('')
  const [cpSaving, setCpSaving] = useState(false)
  const [cpMsg, setCpMsg] = useState<{ ok: boolean; text: string } | null>(null)

  // Which settings view is shown. The page is split into tabs so each concern
  // has its own focused page; one Save button below still persists them all.
  const [view, setView] = useState<'resolver' | 'access' | 'classification' | 'integrations' | 'backup'>('resolver')

  const saveCP = async () => {
    if (!cp) return
    setCpSaving(true)
    setCpMsg(null)
    try {
      const r = await api.saveCPSettings(cp)
      setCp(r.settings)
      setOidcHasSecret(r.oidc_has_client_secret)
      setHasMetricsToken(r.has_metrics_scrape_token)
      setCpMsg({ ok: true, text: 'Access settings saved and applied.' })
    } catch (e: any) {
      setCpMsg({ ok: false, text: e.message })
    } finally {
      setCpSaving(false)
    }
  }

  const genMetricsToken = async () => {
    try {
      const r = await api.generateMetricsToken()
      setNewScrapeToken(r.token)
      setHasMetricsToken(true)
    } catch (e: any) {
      setCpMsg({ ok: false, text: e.message })
    }
  }

  const clearMetricsToken = async () => {
    try {
      await api.clearMetricsToken()
      setNewScrapeToken('')
      setHasMetricsToken(false)
    } catch (e: any) {
      setCpMsg({ ok: false, text: e.message })
    }
  }

  const load = async () => {
    try {
      const cur = await api.settings()
      setS(cur)
      const text = (cur.upstreams || []).join('\n')
      setUpstreams(text)
      setUpRows(textToRows(text))
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
      .cpSettings()
      .then((r) => {
        setCp(r.settings)
        setOidcHasSecret(r.oidc_has_client_secret)
        setHasMetricsToken(r.has_metrics_scrape_token)
      })
      .catch(() => setCp(null))
    api
      .metricsExport()
      .then((r) => {
        setVm(r.settings)
        setVmHasPassword(r.has_password)
      })
      .catch(() => setVm(null))
    api
      .logsExport()
      .then((r) => {
        setVl(r.settings)
        setVlHasPassword(r.has_password)
      })
      .catch(() => setVl(null))
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

  // Structured upstream editing keeps the canonical `upstreams` text in sync so
  // saveAll/raw mode stay source-of-truth agnostic.
  const setRows = (rows: UpRow[]) => {
    setUpRows(rows)
    setUpstreams(rowsToText(rows))
  }
  const setRow = (i: number, p: Partial<UpRow>) => setRows(upRows.map((r, j) => (j === i ? { ...r, ...p } : r)))
  const addRow = () => setRows([...upRows, emptyRow()])
  const delRow = (i: number) => setRows(upRows.filter((_, j) => j !== i))
  const quickFill = (p: (typeof PROVIDERS)[number]) => {
    if (qfProto === 'https') setRows([{ ...emptyRow(), proto: 'https', url: p.doh }])
    else if (qfProto === 'tls') setRows(p.ips.map((ip) => ({ proto: 'tls', host: ip, port: '853', name: p.name, url: '' })))
    else setRows(p.ips.map((ip) => ({ ...emptyRow(), host: ip, port: '53' })))
  }
  // Toggling out of raw text mode re-parses whatever the user typed into rows.
  const toggleRaw = () => {
    if (rawUpstreams) setUpRows(textToRows(upstreams))
    setRawUpstreams(!rawUpstreams)
  }

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
      const text = (saved.upstreams || []).join('\n')
      setUpstreams(text)
      setUpRows(textToRows(text))
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
      if (vl) {
        const v = await api.saveLogsExport(vl)
        setVl(v)
        setVlHasPassword(v.password !== '' || vlHasPassword)
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
        Settings are stored in the database and applied live — no restart needed. Only bootstrap options (database,
        API listen address/port, log level) stay in the config file / env.
      </p>
      {err && <div className="error">{err}</div>}

      <div className="settings-subnav" role="tablist">
        {([
          { id: 'resolver', label: 'Resolver' },
          { id: 'access', label: 'Access & SSO' },
          ...(cls ? [{ id: 'classification', label: 'Classification' }] : []),
          { id: 'integrations', label: 'Integrations' },
          { id: 'backup', label: 'Backup & restore' },
        ] as { id: typeof view; label: string }[]).map((t) => (
          <button
            key={t.id}
            role="tab"
            aria-selected={view === t.id}
            className={`subnav-tab${view === t.id ? ' active' : ''}`}
            onClick={() => setView(t.id)}
          >
            {t.label}
          </button>
        ))}
      </div>

      {view === 'integrations' && (
        <p className="muted" style={{ textAlign: 'left' }}>
          Connect MazeDNS to external services: NetBird for client identity, and VictoriaMetrics / VictoriaLogs for
          long-term metrics and query-log retention.
        </p>
      )}

      {view === 'access' && cp && (
        <>
          {cpMsg && <div className={cpMsg.ok ? 'ok-msg' : 'error'}>{cpMsg.text}</div>}
          <details className="settings-card" open>
            <summary>Single sign-on (OIDC / SSO)</summary>
            <label className="setup-check">
              <input
                type="checkbox"
                checked={cp.oidc.enabled}
                onChange={(e) => setCp({ ...cp, oidc: { ...cp.oidc, enabled: e.target.checked } })}
              />
              Enable SSO login via an OpenID Connect provider
            </label>
            {cp.oidc.enabled && (
              <div className="form-grid">
                <label>
                  Issuer URL
                  <input value={cp.oidc.issuer} onChange={(e) => setCp({ ...cp, oidc: { ...cp.oidc, issuer: e.target.value } })} />
                </label>
                <label>
                  Client ID
                  <input value={cp.oidc.client_id} onChange={(e) => setCp({ ...cp, oidc: { ...cp.oidc, client_id: e.target.value } })} />
                </label>
                <label>
                  Client secret
                  <input
                    type="password"
                    placeholder={oidcHasSecret ? '•••••••• (unchanged)' : ''}
                    value={cp.oidc.client_secret}
                    onChange={(e) => setCp({ ...cp, oidc: { ...cp.oidc, client_secret: e.target.value } })}
                  />
                </label>
                <label>
                  Redirect URL
                  <input value={cp.oidc.redirect_url} onChange={(e) => setCp({ ...cp, oidc: { ...cp.oidc, redirect_url: e.target.value } })} />
                </label>
                <label>
                  Groups claim
                  <input value={cp.oidc.groups_claim} onChange={(e) => setCp({ ...cp, oidc: { ...cp.oidc, groups_claim: e.target.value } })} />
                </label>
                <label>
                  Admin group
                  <input value={cp.oidc.admin_group} onChange={(e) => setCp({ ...cp, oidc: { ...cp.oidc, admin_group: e.target.value } })} />
                </label>
                <label>
                  Admin email
                  <input
                    value={cp.oidc.admin_email}
                    onChange={(e) => setCp({ ...cp, oidc: { ...cp.oidc, admin_email: e.target.value } })}
                    placeholder="you@example.com — always granted admin on login"
                  />
                </label>
                <label className="setup-check">
                  <input
                    type="checkbox"
                    checked={cp.oidc.disable_password_login}
                    onChange={(e) => setCp({ ...cp, oidc: { ...cp.oidc, disable_password_login: e.target.checked } })}
                  />
                  Disable local password login (SSO only)
                </label>
                <label className="setup-check">
                  <input
                    type="checkbox"
                    checked={cp.oidc.auto_login}
                    onChange={(e) => setCp({ ...cp, oidc: { ...cp.oidc, auto_login: e.target.checked } })}
                  />
                  Redirect straight to the SSO provider
                </label>
              </div>
            )}
          </details>

          <details className="settings-card" open>
            <summary>Sessions &amp; login</summary>
            <label>
              Session lifetime (hours)
              <input
                type="number"
                min={1}
                value={Math.round(cp.session_ttl_sec / 3600)}
                onChange={(e) => setCp({ ...cp, session_ttl_sec: Math.max(1, Number(e.target.value)) * 3600 })}
              />
            </label>
            <div className="form-grid">
              <label>
                Login attempts per window (0 = no limit)
                <input
                  type="number"
                  min={0}
                  value={cp.login_rate_attempts}
                  onChange={(e) => setCp({ ...cp, login_rate_attempts: Math.max(0, Number(e.target.value)) })}
                />
              </label>
              <label>
                Login window (seconds)
                <input
                  type="number"
                  min={1}
                  value={cp.login_rate_window_sec}
                  onChange={(e) => setCp({ ...cp, login_rate_window_sec: Math.max(1, Number(e.target.value)) })}
                />
              </label>
            </div>
            <p className="muted small">
              Failed and successful login attempts are throttled per source IP and per username. Applied live.
            </p>
          </details>

          <details className="settings-card" open>
            <summary>Cluster policy</summary>
            <label className="setup-check">
              <input
                type="checkbox"
                checked={cp.require_approval}
                onChange={(e) => setCp({ ...cp, require_approval: e.target.checked })}
              />
              Require admin approval before a new agent serves DNS
            </label>
            <div className="form-grid">
              <label>
                Node key max age (days, 0 = 30d default)
                <input
                  type="number"
                  min={0}
                  value={Math.round(cp.key_max_age_sec / 86400)}
                  onChange={(e) => setCp({ ...cp, key_max_age_sec: Math.max(0, Number(e.target.value)) * 86400 })}
                />
              </label>
              <label>
                Key rotation grace (minutes)
                <input
                  type="number"
                  min={0}
                  value={Math.round(cp.key_grace_sec / 60)}
                  onChange={(e) => setCp({ ...cp, key_grace_sec: Math.max(0, Number(e.target.value)) * 60 })}
                />
              </label>
              <label>
                Advertise address (optional)
                <input value={cp.advertise_addr} onChange={(e) => setCp({ ...cp, advertise_addr: e.target.value })} />
              </label>
            </div>
          </details>

          <div className="settings-actions">
            <button className="btn primary" onClick={saveCP} disabled={cpSaving}>
              {cpSaving ? 'Saving…' : 'Save access settings'}
            </button>
          </div>
        </>
      )}

      {view === 'resolver' && (
        <>
      <details className="settings-card" open>
        <summary>Upstream resolvers</summary>
        <label className="muted">
          Tried in order. <strong>DoT/DoH is recommended</strong> — connections are pooled, so large/DNSSEC-validated
          answers avoid UDP fragmentation and per-query handshakes (lower latency). Plain DNS is faster to set up but
          unencrypted.
        </label>

        <div className="quick-fill">
          <span className="muted">Quick fill:</span>
          <select value={qfProto} onChange={(e) => setQfProto(e.target.value as UpProto)} aria-label="Quick-fill protocol">
            <option value="tls">DNS-over-TLS</option>
            <option value="https">DNS-over-HTTPS</option>
            <option value="plain">Plain DNS</option>
          </select>
          {PROVIDERS.map((p) => (
            <button type="button" key={p.key} className="btn ghost" onClick={() => quickFill(p)}>
              {p.label}
            </button>
          ))}
        </div>

        {rawUpstreams ? (
          <textarea
            rows={Math.max(4, upRows.length + 1)}
            value={upstreams}
            onChange={(e) => setUpstreams(e.target.value)}
            placeholder="tls://1.1.1.1:853#cloudflare-dns.com&#10;https://dns.quad9.net/dns-query&#10;1.1.1.1:53"
          />
        ) : (
          <div className="upstream-list">
            {upRows.map((r, i) => (
              <div className="upstream-row" key={i}>
                <select value={r.proto} onChange={(e) => setRow(i, { proto: e.target.value as UpProto })} aria-label="Protocol">
                  <option value="plain">Plain DNS</option>
                  <option value="tls">DoT</option>
                  <option value="https">DoH</option>
                </select>
                {r.proto === 'https' ? (
                  <input
                    className="grow"
                    placeholder="https://dns.example.net/dns-query"
                    value={r.url}
                    onChange={(e) => setRow(i, { url: e.target.value })}
                  />
                ) : (
                  <>
                    <input
                      className="grow"
                      placeholder="host / IP (e.g. 1.1.1.1)"
                      value={r.host}
                      onChange={(e) => setRow(i, { host: e.target.value })}
                    />
                    <input
                      className="port"
                      placeholder={r.proto === 'tls' ? '853' : '53'}
                      value={r.port}
                      onChange={(e) => setRow(i, { port: e.target.value })}
                      aria-label="Port"
                    />
                    {r.proto === 'tls' && (
                      <input
                        className="grow"
                        placeholder="TLS server name (e.g. cloudflare-dns.com)"
                        value={r.name}
                        onChange={(e) => setRow(i, { name: e.target.value })}
                      />
                    )}
                  </>
                )}
                <button type="button" className="del" onClick={() => delRow(i)} aria-label="Remove resolver">
                  ✕
                </button>
              </div>
            ))}
            <button type="button" className="btn ghost" onClick={addRow}>
              + Add resolver
            </button>
          </div>
        )}

        <p className="hint" style={{ textAlign: 'left' }}>
          <button type="button" className="linklike" onClick={toggleRaw}>
            {rawUpstreams ? '← Back to editor' : 'Edit as text'}
          </button>{' '}
          · Click <strong>Save changes</strong> below to apply.
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
        </>
      )}

      {view === 'classification' && cls && (
        <details className="settings-card" open>
          <summary>Domain classification</summary>
          <label className="muted">
            Score newly-seen domains for risk instead of maintaining blocklists by hand. Every domain starts fully
            legitimate and each <strong>static signal</strong> — threat-intel feeds, the trusted/popular list, reputation
            services, WHOIS age, risky TLDs and look-alike/DGA name patterns — adjusts the score. An AI model (local or hosted) is an{' '}
            <strong>optional</strong> extra signal (configured below) that mainly reduces false positives; leave it blank
            and classification runs on the static signals alone. Runs on the master; auto-blocks also propagate to workers.
          </label>
          <div className="field">
            <label className="toggle">
              <input type="checkbox" checked={cls.enabled} onChange={(e) => setCls({ ...cls, enabled: e.target.checked })} />
              <span className="track">
                <span className="thumb" />
              </span>
              <span className="toggle-label">Enable domain classification</span>
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

          <h4 style={{ margin: '14px 0 4px' }}>Optional AI layer</h4>
          <p className="muted" style={{ textAlign: 'left' }}>
            Fold an LLM's read in as one more bounded signal — it also adds content categories (social, streaming, …).
            Use a local/OpenAI-compatible endpoint or a hosted provider. Turn this off to run on the static signals only.
          </p>
          <div className="field">
            <label className="toggle">
              <input type="checkbox" checked={!!cls.ai_enabled} onChange={(e) => setCls({ ...cls, ai_enabled: e.target.checked })} />
              <span className="track">
                <span className="thumb" />
              </span>
              <span className="toggle-label">Use an AI model</span>
            </label>
          </div>
          {cls.ai_enabled && (
            <>
              <div className="field">
                <label>Provider</label>
                <select value={cls.provider || 'openai'} onChange={(e) => setCls({ ...cls, provider: e.target.value })}>
                  <option value="openai">OpenAI-compatible (Ollama, OpenAI, LM Studio, vLLM, …)</option>
                  <option value="anthropic">Anthropic (Claude)</option>
                </select>
              </div>
              {cls.provider !== 'anthropic' && (
                <div className="field">
                  <label>Model endpoint (OpenAI-compatible base URL)</label>
                  <input
                    value={cls.endpoint}
                    onChange={(e) => setCls({ ...cls, endpoint: e.target.value })}
                    placeholder="http://localhost:11434/v1"
                  />
                </div>
              )}
              <div className="field">
                <label>Model</label>
                <input
                  value={cls.model}
                  onChange={(e) => setCls({ ...cls, model: e.target.value })}
                  placeholder={cls.provider === 'anthropic' ? 'claude-haiku-4-5' : 'llama3.2'}
                />
              </div>
              <div className="field">
                <label>
                  API key{' '}
                  {cls.provider === 'anthropic' ? '(required)' : '(optional; usually empty for local models)'}{' '}
                  {clsInfo?.has_api_key && <span className="badge allow">key set</span>}
                </label>
                <input
                  type="password"
                  value={cls.api_key}
                  onChange={(e) => setCls({ ...cls, api_key: e.target.value })}
                  placeholder={
                    clsInfo?.has_api_key
                      ? '•••••••••••••• (saved — leave blank to keep)'
                      : cls.provider === 'anthropic'
                      ? 'sk-ant-…'
                      : 'usually empty for local models'
                  }
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
            </>
          )}
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

      {view === 'integrations' && (
        <>
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

      {cp && (
        <details className="settings-card" open>
          <summary>Metrics scrape token (/metrics)</summary>
          <p className="muted">
            When set, the control plane's <code>/metrics</code> endpoint requires{' '}
            <code>Authorization: Bearer &lt;token&gt;</code>. When unset, <code>/metrics</code> is open. The token is shown
            once on generation and stored hashed.
          </p>
          {newScrapeToken ? (
            <div className="ok-msg">
              <strong>New scrape token — copy it now, it won't be shown again:</strong>
              <pre className="keybox">{newScrapeToken}</pre>
              <p className="muted small">
                Prometheus: <code>authorization: {'{'} type: Bearer, credentials: &lt;token&gt; {'}'}</code> under the
                scrape job.
              </p>
            </div>
          ) : (
            <p className="muted small">
              Status: {hasMetricsToken ? `set (prefix ${cp.metrics_scrape_token_prefix}…)` : 'not set — /metrics is open'}
            </p>
          )}
          <div className="setup-actions">
            <button className="btn" onClick={genMetricsToken}>
              {hasMetricsToken ? 'Regenerate token' : 'Generate token'}
            </button>
            {hasMetricsToken && (
              <button className="btn ghost" onClick={clearMetricsToken}>
                Clear (reopen /metrics)
              </button>
            )}
          </div>
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

      {vl && (
        <details className="settings-card">
          <summary>Log export — VictoriaLogs</summary>
          <label className="muted">
            Ship the cluster-wide query log from the master to a VictoriaLogs instance (its
            <code> /insert/jsonline </code> endpoint) for long-term retention beyond the local window. Useful for
            keeping history past the dashboard's range — query it in VictoriaLogs with LogsQL.
          </label>
          <div className="field">
            <label className="toggle">
              <input type="checkbox" checked={vl.enabled} onChange={(e) => setVl({ ...vl, enabled: e.target.checked })} />
              <span className="track">
                <span className="thumb" />
              </span>
              <span className="toggle-label">Enable VictoriaLogs export</span>
            </label>
          </div>
          <div className="field">
            <label>VictoriaLogs URL</label>
            <input
              value={vl.url}
              onChange={(e) => setVl({ ...vl, url: e.target.value })}
              placeholder="http://victorialogs:9428"
            />
          </div>
          <div className="field">
            <label>Ship interval (seconds)</label>
            <input
              type="number"
              min={1}
              value={vl.interval_sec}
              onChange={(e) => setVl({ ...vl, interval_sec: Number(e.target.value) })}
            />
          </div>
          <div className="field">
            <label>Username (optional)</label>
            <input value={vl.username} onChange={(e) => setVl({ ...vl, username: e.target.value })} />
          </div>
          <div className="field">
            <label>Password (optional)</label>
            <input
              type="password"
              value={vl.password}
              onChange={(e) => setVl({ ...vl, password: e.target.value })}
              placeholder={vlHasPassword ? '•••••••• (unchanged)' : ''}
            />
          </div>
        </details>
      )}
        </>
      )}

      {view === 'backup' && (
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
      )}

      {/* One global save for every section above. */}
      {view !== 'access' && view !== 'backup' && (
        <div className="settings-savebar">
          {ok && <span className="ok-inline">Saved &amp; applied.</span>}
          <button className="btn ghost-danger" onClick={load} disabled={saving}>
            Reset
          </button>
          <button className="btn primary" onClick={saveAll} disabled={saving}>
            {saving ? 'Saving…' : 'Save changes'}
          </button>
        </div>
      )}
    </div>
  )
}
