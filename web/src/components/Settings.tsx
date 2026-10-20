import { useEffect, useRef, useState, type ReactNode } from 'react'
import {
  api,
  type Settings as S,
  type UpstreamStrategy,
  type ClassifierSettings,
  type ClassifierStatus,
  type VMExportSettings,
  type VLExportSettings,
  type CPSettings,
  type AuditEntry,
} from '../api'
import ApiTokens from './ApiTokens'
import ClusterForwarders from './ClusterForwarders'
import Spinner from './Spinner'
import Modal from './Modal'
import ClassifierHelp from './ClassifierHelp'
import { SkelGroups, SkelList } from './Skeleton'
import About from './About'
import { useCategories } from '../categories'
import { timeAgo } from './tableKit'
import { invalidateAllClientNames } from '../useClientNames'
import { PASSWORD_RULE } from '../passwordPolicy'
import '../styles/settings.css'

const linesToList = (s: string) =>
  s.split(/[\n,]+/).map((x) => x.trim()).filter(Boolean)

// --- Upstream resolver editing ------------------------------------------------
// The textarea spec format (see resolver.ParseUpstream) is hard to get right by
// hand, so we edit each upstream as a structured row and serialize back to the
// canonical spec string the backend expects.
type UpProto = 'plain' | 'tls' | 'https'
type UpRow = { proto: UpProto; host: string; port: string; name: string; url: string }

const emptyRow = (): UpRow => ({ proto: 'plain', host: '', port: '', name: '', url: '' })
const isEmptyRow = (r: UpRow) => (r.proto === 'https' ? !r.url.trim() : !r.host.trim())

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

const PROTO_LABEL: Record<UpProto, string> = { plain: 'Plain', tls: 'DoT', https: 'DoH' }

// upstreamDisplay renders one resolver row as "address" + a muted second line.
const upstreamDisplay = (r: UpRow): { addr: string; sub: string } => {
  const provider = PROVIDERS.find((p) =>
    r.proto === 'https' ? r.url.trim() === p.doh : (p.ips as readonly string[]).includes(r.host.trim()),
  )?.label
  if (r.proto === 'https') {
    return { addr: r.url.trim() || 'No URL yet', sub: [provider, 'DNS over HTTPS'].filter(Boolean).join(' · ') }
  }
  const host = r.host.trim()
  const addr = host ? `${host}:${r.port.trim() || (r.proto === 'tls' ? '853' : '53')}` : 'No address yet'
  if (r.proto === 'tls') {
    return { addr, sub: [provider, r.name.trim() ? `TLS name ${r.name.trim()}` : 'DNS over TLS'].filter(Boolean).join(' · ') }
  }
  return { addr, sub: [provider, 'Unencrypted'].filter(Boolean).join(' · ') }
}

// The settings body as it would be saved: compared against the last saved copy
// to tell whether the resolver section has unsaved changes. Its `forwarders`
// (the control plane's own, which it never uses: it answers no queries) pass
// through untouched; conditional forwarding is the cluster list instead.
const resolverBody = (s: S, upstreamsText: string): S => ({
  ...s,
  upstreams: linesToList(upstreamsText),
})

type View = 'resolver' | 'access' | 'classification' | 'integrations' | 'backup' | 'about'
const VIEW_LABEL: Record<View, string> = {
  resolver: 'Resolver',
  access: 'Access & sign-in',
  classification: 'Classification',
  integrations: 'Integrations',
  backup: 'Backup & restore',
  about: 'About & updates',
}

// The last saved copy of every section, for unsaved-change tracking and Discard.
type Saved = {
  s: S | null
  cls: ClassifierSettings | null
  vm: VMExportSettings | null
  vl: VLExportSettings | null
  cp: CPSettings | null
}

// What each privacy level keeps, shown under the level picker.
const PRIVACY_HINT: Record<number, string> = {
  0: 'Every query is stored with its client and domain.',
  1: 'Domains are stored as "hidden"; clients are kept. The classifier and content categories still work, because a domain is checked before it is hidden.',
  2: 'Domains are hidden and each client becomes a pseudonym (anon-…). A device keeps the same pseudonym for one day (UTC), so per-client stats still work, but days cannot be linked to each other or back to an address.',
  3: 'No query is kept. Only the dashboard counts (totals, actions, content categories) remain; the Queries, Clients and Live views stay empty (a query is removed within a minute of being counted).',
}

const same = (a: unknown, b: unknown) => JSON.stringify(a) === JSON.stringify(b)

// --- Small layout pieces -------------------------------------------------------

// Group is one block of a settings section: title and a one-line explanation on
// the left, the controls on the right (stacked on narrow screens).
// externalContacts lists, in plain words, what the classifier will contact
// with these settings (for the confirmation when it is turned on).
function externalContacts(c: ClassifierSettings): string[] {
  const out: string[] = []
  if (!c.trusted_disable_default) out.push('majestic.com: the trusted list is downloaded (it receives none of your queries).')
  if ((c.threat_feeds ?? []).length || (c.threat_list_url ?? '').trim())
    out.push('The threat feeds’ publishers: their lists are downloaded (they receive none of your queries).')
  if (c.whois_enabled) out.push('rdap.org and domain registries receive every new domain (WHOIS).')
  if (c.whois_enabled && !c.ns_check_disabled) out.push('Cloudflare and Quad9 (DoH) receive domains served by trusted companies’ nameservers.')
  if (c.ai_enabled) out.push(`Your AI model (${c.provider === 'anthropic' ? 'api.anthropic.com' : c.endpoint || 'its endpoint'}) receives every new domain.`)
  if (c.vt_enabled) out.push('virustotal.com receives every new domain.')
  if (c.abuseipdb_enabled) out.push('abuseipdb.com receives the address each new domain resolves to.')
  if (c.opentip_enabled) out.push('opentip.kaspersky.com receives every new domain.')
  return out
}

function Group({ title, desc, children }: { title: ReactNode; desc?: ReactNode; children: ReactNode }) {
  return (
    <section className="sg">
      <header>
        <h2>{title}</h2>
        {desc && <p>{desc}</p>}
      </header>
      <div className="sg-body">{children}</div>
    </section>
  )
}

// Toggle is a settings row: label and explanation left, switch right.
function Toggle({
  label,
  desc,
  checked,
  onChange,
}: {
  label: ReactNode
  desc?: ReactNode
  checked: boolean
  onChange: (v: boolean) => void
}) {
  return (
    <label className="check-row toggle">
      <span className="t">
        <b>{label}</b>
        {desc && <small>{desc}</small>}
      </span>
      <input type="checkbox" checked={checked} onChange={(e) => onChange(e.target.checked)} />
      <span className="track">
        <span className="thumb" />
      </span>
    </label>
  )
}

function Field({ label, hint, children, className }: { label: ReactNode; hint?: ReactNode; children: ReactNode; className?: string }) {
  return (
    <label className={`field${className ? ' ' + className : ''}`}>
      <span>{label}</span>
      {children}
      {hint && <small>{hint}</small>}
    </label>
  )
}

const KeySet = ({ on }: { on?: boolean }) => (on ? <span className="tag ok">Key saved</span> : null)

function Msg({ m }: { m: { ok: boolean; text: string } | null }) {
  if (!m) return null
  return <div className={m.ok ? 'ok-msg' : 'error'}>{m.text}</div>
}

const LockIcon = () => (
  <svg viewBox="0 0 24 24" aria-hidden>
    <rect x="5" y="10" width="14" height="10" rx="2" />
    <path d="M8 10V7a4 4 0 0 1 8 0v3" />
  </svg>
)
const GlobeIcon = () => (
  <svg viewBox="0 0 24 24" aria-hidden>
    <circle cx="12" cy="12" r="8" />
    <path d="M4 12h16M12 4c2.5 2.7 2.5 13.3 0 16M12 4c-2.5 2.7-2.5 13.3 0 16" />
  </svg>
)
const InfoIcon = () => (
  <svg viewBox="0 0 24 24" aria-hidden>
    <circle cx="12" cy="12" r="9" />
    <path d="M12 8v5M12 16h.01" />
  </svg>
)

const fmtTime = (ts: number) =>
  new Date(ts * 1000).toLocaleString(undefined, { dateStyle: 'medium', timeStyle: 'short' })

// onClassifierChange lets the app refresh its nav (the AI tab appears/disappears
// with the classifier's enabled state).
export default function Settings({ onClassifierChange }: { onClassifierChange?: () => void }) {
  const [s, setS] = useState<S | null>(null)
  const [upstreams, setUpstreams] = useState('')
  const [upRows, setUpRows] = useState<UpRow[]>([emptyRow()])
  const [editing, setEditing] = useState<number | null>(null)
  const [rawUpstreams, setRawUpstreams] = useState(false)
  const [qfProto, setQfProto] = useState<UpProto>('tls')
  // Bumped to make the cluster forwarders list reload after the legacy move.
  const [fwdReload, setFwdReload] = useState(0)
  const [legacyBusy, setLegacyBusy] = useState(false)
  const [legacyErr, setLegacyErr] = useState('')
  const [err, setErr] = useState('')
  const [loadErr, setLoadErr] = useState('')
  const [saving, setSaving] = useState(false)
  const [saveErr, setSaveErr] = useState('')
  const [savedNote, setSavedNote] = useState(false)
  const [importMode, setImportMode] = useState<'merge' | 'replace'>('merge')
  const [importMsg, setImportMsg] = useState('')
  const fileRef = useRef<HTMLInputElement>(null)

  // Role: readonly users can read most settings but every write is refused, so
  // the page renders read-only for them. Unknown (lookup failed) = editable; the
  // server still enforces.
  const [role, setRole] = useState<string | null>(null)
  const readonly = role !== null && role !== 'admin'

  // Classifier settings (separate endpoint; null until loaded / if unavailable).
  const [cls, setCls] = useState<ClassifierSettings | null>(null)
  const [clsInfo, setClsInfo] = useState<ClassifierStatus | null>(null)
  const [testing, setTesting] = useState(false)
  const [testMsg, setTestMsg] = useState<{ ok: boolean; text: string } | null>(null)

  // VictoriaMetrics metrics export.
  const [vm, setVm] = useState<VMExportSettings | null>(null)
  const [vmHasPassword, setVmHasPassword] = useState(false)

  // VictoriaLogs query-log export.
  const [vl, setVl] = useState<VLExportSettings | null>(null)
  const [vlHasPassword, setVlHasPassword] = useState(false)

  // Control-plane runtime settings (SSO / session / cluster policy). Own endpoint,
  // admin-only.
  const [cp, setCp] = useState<CPSettings | null>(null)
  const [cpErr, setCpErr] = useState('')
  const [oidcHasSecret, setOidcHasSecret] = useState(false)
  const [ssoOpen, setSsoOpen] = useState(false)
  const [hasMetricsToken, setHasMetricsToken] = useState(false)
  const [newScrapeToken, setNewScrapeToken] = useState('')
  const [tokenMsg, setTokenMsg] = useState<{ ok: boolean; text: string } | null>(null)

  // Settings change history (admin-only).
  const [audit, setAudit] = useState<AuditEntry[] | null>(null)
  const [auditErr, setAuditErr] = useState('')
  const [auditAll, setAuditAll] = useState(false)

  const [saved, setSaved] = useState<Saved>({ s: null, cls: null, vm: null, vl: null, cp: null })

  // A section can be linked to: /settings?section=about (the top bar's
  // "update available" note does).
  const [confirmClassify, setConfirmClassify] = useState(false)
  const [showClsHelp, setShowClsHelp] = useState(false)
  const catList = useCategories()
  const [view, setView] = useState<View>(() => {
    const s = new URLSearchParams(window.location.search).get('section')
    return s && s in VIEW_LABEL ? (s as View) : 'resolver'
  })
  useEffect(() => {
    const onPop = () => {
      const s = new URLSearchParams(window.location.search).get('section')
      if (s && s in VIEW_LABEL) setView(s as View)
    }
    window.addEventListener('popstate', onPop)
    return () => window.removeEventListener('popstate', onPop)
  }, [])

  // applySettings shows a settings object fetched from (or saved to) the server.
  const applySettings = (cur: S) => {
    setS(cur)
    const text = (cur.upstreams || []).join('\n')
    setUpstreams(text)
    setUpRows(textToRows(text))
    setEditing(null)
    setSaved((p) => ({ ...p, s: cur }))
  }

  const loadCP = () => {
    setCpErr('')
    api
      .cpSettings()
      .then((r) => {
        setCp(r.settings)
        setSsoOpen(r.settings.oidc.enabled)
        setOidcHasSecret(r.oidc_has_client_secret)
        setHasMetricsToken(r.has_metrics_scrape_token)
        setSaved((p) => ({ ...p, cp: r.settings }))
      })
      .catch((e) => {
        setCp(null)
        setCpErr(e.message)
      })
  }

  const loadAudit = () => {
    setAuditErr('')
    api
      .settingsAudit()
      .then((a) => setAudit(a || []))
      .catch((e) => setAuditErr(e.message))
  }

  const load = async () => {
    setLoadErr('')
    // The role decides what to fetch: access settings are admin-only.
    const me = await api.me().catch(() => null)
    const r = me?.role ?? null
    setRole(r)
    try {
      applySettings(await api.settings())
    } catch (e: any) {
      setLoadErr(e.message)
    }
    api
      .classifier()
      .then((st) => {
        setCls(st.settings)
        setClsInfo(st)
        setSaved((p) => ({ ...p, cls: st.settings }))
      })
      .catch(() => setCls(null))
    if (r === null || r === 'admin') loadCP()
    api
      .metricsExport()
      .then((r) => {
        setVm(r.settings)
        setVmHasPassword(r.has_password)
        setSaved((p) => ({ ...p, vm: r.settings }))
      })
      .catch(() => setVm(null))
    api
      .logsExport()
      .then((r) => {
        setVl(r.settings)
        setVlHasPassword(r.has_password)
        setSaved((p) => ({ ...p, vl: r.settings }))
      })
      .catch(() => setVl(null))
  }
  useEffect(() => {
    load()
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [])

  // The history is only fetched when its section is opened.
  useEffect(() => {
    if (view === 'backup' && !readonly && audit === null) loadAudit()
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [view, readonly])

  const testClassifier = async () => {
    if (!cls) return
    setTesting(true)
    setTestMsg(null)
    try {
      const r = await api.testClassifier(cls)
      setTestMsg(
        r.ok
          ? { ok: true, text: `Connected: classified ${r.domain} as “${r.category}” (${Math.round((r.confidence || 0) * 100)}%).` }
          : { ok: false, text: r.error || 'Test failed.' },
      )
    } catch (e: any) {
      setTestMsg({ ok: false, text: e.message })
    } finally {
      setTesting(false)
    }
  }

  const genMetricsToken = async () => {
    setTokenMsg(null)
    try {
      const r = await api.generateMetricsToken()
      setNewScrapeToken(r.token)
      setHasMetricsToken(true)
    } catch (e: any) {
      setTokenMsg({ ok: false, text: e.message })
    }
  }

  const clearMetricsToken = async () => {
    setTokenMsg(null)
    try {
      await api.clearMetricsToken()
      setNewScrapeToken('')
      setHasMetricsToken(false)
    } catch (e: any) {
      setTokenMsg({ ok: false, text: e.message })
    }
  }

  // --- Unsaved-change tracking ---
  const dirty = {
    resolver:
      !!s && !!saved.s && !same(resolverBody(s, upstreams), resolverBody(saved.s, (saved.s.upstreams || []).join('\n'))),
    classification: !!cls && !same(cls, saved.cls),
    vm: !!vm && !same(vm, saved.vm),
    vl: !!vl && !same(vl, saved.vl),
    access: !!cp && !same(cp, saved.cp),
  }
  const dirtyViews: Record<View, boolean> = {
    resolver: dirty.resolver,
    access: dirty.access,
    classification: dirty.classification,
    integrations: dirty.vm || dirty.vl,
    backup: false,
    about: false,
  }
  const anyDirty = Object.values(dirtyViews).some(Boolean)
  // Clear the "saved" note as soon as something changes again.
  useEffect(() => {
    if (anyDirty) setSavedNote(false)
  }, [anyDirty])

  const discard = () => {
    if (saved.s) applySettings(saved.s)
    setCls(saved.cls)
    setVm(saved.vm)
    setVl(saved.vl)
    setCp(saved.cp)
    if (saved.cp) setSsoOpen(saved.cp.oidc.enabled)
    setSaveErr('')
  }

  // saveAll persists every section with unsaved changes behind one button:
  // operational settings, classifier, metrics/log export and access.
  // Stops at the first failure; sections saved before it stay saved.
  const saveAll = async () => {
    if (readonly) return
    setSaving(true)
    setSaveErr('')
    setSavedNote(false)
    try {
      if (dirty.resolver && s) {
        applySettings(await api.saveSettings(resolverBody(s, upstreams)))
      }
      if (dirty.classification && cls) {
        const v = await api.saveClassifierSettings(cls)
        setCls(v)
        setSaved((p) => ({ ...p, cls: v }))
        api.classifier().then(setClsInfo).catch(() => {})
        onClassifierChange?.()
      }
      if (dirty.vm && vm) {
        const v = await api.saveMetricsExport(vm)
        setVm(v)
        setVmHasPassword(v.password !== '' || vmHasPassword)
        setSaved((p) => ({ ...p, vm: v }))
      }
      if (dirty.vl && vl) {
        const v = await api.saveLogsExport(vl)
        setVl(v)
        setVlHasPassword(v.password !== '' || vlHasPassword)
        setSaved((p) => ({ ...p, vl: v }))
      }
      if (dirty.access && cp) {
        const r = await api.saveCPSettings(cp)
        setCp(r.settings)
        setOidcHasSecret(r.oidc_has_client_secret)
        setHasMetricsToken(r.has_metrics_scrape_token)
        setSaved((p) => ({ ...p, cp: r.settings }))
      }
      setSavedNote(true)
    } catch (e: any) {
      setSaveErr(e.message)
    } finally {
      setSaving(false)
    }
  }

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
      invalidateAllClientNames() // imported rewrites can rename clients
      await load()
      if (!readonly) loadAudit()
    } catch (e: any) {
      setErr(e.message)
    } finally {
      if (fileRef.current) fileRef.current.value = ''
    }
  }

  const head = (
    <>
      <header className="page-head">
        <h1>Settings</h1>
      </header>
      <p className="intro">Saved in the database and pushed to every agent within a few seconds. No restarts.</p>
    </>
  )

  if (!s) {
    return (
      <div className="pg-settings">
        {head}
        {loadErr ? (
          <div className="error">
            <span className="grow">Couldn't load settings: {loadErr}</span>
            <button className="btn sm" onClick={load}>
              Try again
            </button>
          </div>
        ) : (
          <div className="st-layout" aria-busy="true">
            <div className="st-nav">
              <SkelList rows={5} gap={22} />
            </div>
            <div className="st-main">
              <SkelGroups groups={4} />
            </div>
          </div>
        )}
      </div>
    )
  }

  const patch = (p: Partial<S>) => setS({ ...s, ...p })
  const hedged = s.upstream_strategy === 'hedged'
  const privacyLevel = s.privacy_level ?? 0
  const patchCache = (p: Partial<S['cache']>) => setS({ ...s, cache: { ...s.cache, ...p } })

  // Structured upstream editing keeps the canonical `upstreams` text in sync so
  // saveAll/raw mode stay source-of-truth agnostic.
  const setRows = (rows: UpRow[]) => {
    setUpRows(rows)
    setUpstreams(rowsToText(rows))
  }
  const setRow = (i: number, p: Partial<UpRow>) => setRows(upRows.map((r, j) => (j === i ? { ...r, ...p } : r)))
  const addRow = () => {
    setRows([...upRows, emptyRow()])
    setEditing(upRows.length)
  }
  const delRow = (i: number) => {
    setRows(upRows.filter((_, j) => j !== i))
    setEditing(null)
  }
  // moveRow shifts resolver i one place up (d = -1) or down (d = 1). The list
  // order is the failover order, saved exactly as shown. Focus follows the moved
  // resolver so repeated keyboard presses keep moving the same entry.
  const moveRow = (i: number, d: -1 | 1) => {
    const j = i + d
    if (j < 0 || j >= upRows.length) return
    const rows = [...upRows]
    ;[rows[i], rows[j]] = [rows[j], rows[i]]
    setRows(rows)
    if (editing === i) setEditing(j)
    else if (editing === j) setEditing(i)
    requestAnimationFrame(() => {
      const row = document.querySelector(`[data-upstream-row="${j}"]`)
      const btn =
        row?.querySelector<HTMLButtonElement>(`button[data-move="${d}"]:not(:disabled)`) ??
        row?.querySelector<HTMLButtonElement>('button[data-move]:not(:disabled)')
      btn?.focus()
    })
  }
  const quickFill = (p: (typeof PROVIDERS)[number]) => {
    setEditing(null)
    if (qfProto === 'https') setRows([{ ...emptyRow(), proto: 'https', url: p.doh }])
    else if (qfProto === 'tls') setRows(p.ips.map((ip) => ({ proto: 'tls', host: ip, port: '853', name: p.name, url: '' })))
    else setRows(p.ips.map((ip) => ({ ...emptyRow(), host: ip, port: '53' })))
  }
  // Toggling out of raw text mode re-parses whatever the user typed into rows.
  const toggleRaw = () => {
    if (rawUpstreams) setUpRows(textToRows(upstreams))
    setEditing(null)
    setRawUpstreams(!rawUpstreams)
  }

  // Forwarders saved by older versions in the control plane's own settings.
  // The control plane answers no queries, so they never forwarded anything:
  // offer to move them to the cluster list (where they start applying on the
  // agents) or to drop them.
  const legacyFwd = saved.s?.forwarders ?? []
  const clearLegacyFwd = async (move: boolean) => {
    if (!saved.s || legacyBusy) return
    setLegacyBusy(true)
    setLegacyErr('')
    const notes: string[] = []
    try {
      if (move) {
        // Adding a suffix the list already has would overwrite that entry (the
        // API upserts), so a domain already forwarded keeps its cluster entry.
        const norm = (d: string) => d.trim().toLowerCase().replace(/\.$/, '')
        const have = new Set((await api.forwarders()).map((f) => norm(f.suffix)))
        const kept: string[] = []
        for (const g of legacyFwd) {
          if (have.has(norm(g.suffix))) {
            kept.push(g.suffix)
            continue
          }
          try {
            await api.addForwarder(g.suffix, g.upstreams, 'all', [])
          } catch (e) {
            notes.push(`${g.suffix} not moved: ${e instanceof Error ? e.message : String(e)}`)
          }
        }
        if (kept.length) notes.push(`Already in the list, left as they were: ${kept.join(', ')}`)
        setFwdReload((n) => n + 1)
      }
      const next = await api.saveSettings({ ...saved.s, forwarders: [] })
      // Keep any unsaved resolver edits; only the forwarders change.
      setSaved((p) => ({ ...p, s: next }))
      setS((cur) => (cur ? { ...cur, forwarders: [] } : cur))
      if (notes.length) setLegacyErr(notes.join('. '))
    } catch (e) {
      setLegacyErr(e instanceof Error ? e.message : String(e))
    } finally {
      setLegacyBusy(false)
    }
  }

  const views: View[] = ['resolver', 'access', ...(cls ? (['classification'] as View[]) : []), 'integrations', 'backup', 'about']
  const shownView: View = views.includes(view) ? view : 'resolver'
  const otherDirty = views.filter((v) => v !== shownView && dirtyViews[v]).map((v) => VIEW_LABEL[v])

  // ------------------------------------------------------------------ Resolver
  const resolverView = (
    <>
      <Group
        title="Upstream resolvers"
        desc={
          hedged
            ? 'Where agents send queries they can’t answer from cache. The first is asked; if it is slow, the rest race it.'
            : 'Where agents send queries they can’t answer from cache. Tried top to bottom.'
        }
      >
        {rawUpstreams ? (
          <Field label="One resolver per line" hint="Formats: 1.1.1.1, 1.1.1.1:5353, tls://1.1.1.1:853#cloudflare-dns.com, https://dns.quad9.net/dns-query">
            <textarea
              rows={Math.max(4, upRows.length + 1)}
              value={upstreams}
              onChange={(e) => setUpstreams(e.target.value)}
              placeholder={'tls://1.1.1.1:853#cloudflare-dns.com\nhttps://dns.quad9.net/dns-query\n1.1.1.1:53'}
            />
          </Field>
        ) : (
          <div className="ups">
            {upRows.map((r, i) => {
              const open = editing === i || isEmptyRow(r)
              const d = upstreamDisplay(r)
              return (
                <div className={`up${open ? ' open' : ''}`} key={i} data-upstream-row={i}>
                  <div className="up-line">
                    <span className="ord" title={i === 0 ? 'Primary resolver' : `Fallback ${i}`}>
                      {i + 1}
                    </span>
                    <span className={`proto ${r.proto === 'plain' ? 'plain' : 'enc'}`}>{PROTO_LABEL[r.proto]}</span>
                    <button
                      type="button"
                      className="addr"
                      onClick={() => setEditing(open && editing === i ? null : i)}
                      aria-expanded={open}
                      title="Edit this resolver"
                    >
                      <span className={`a${isEmptyRow(r) ? ' unset' : ''}`}>{d.addr}</span>
                      <small>{d.sub}</small>
                    </button>
                    <span className="up-act">
                      <button
                        type="button"
                        className="ib"
                        data-move={-1}
                        onClick={() => moveRow(i, -1)}
                        disabled={i === 0}
                        aria-label={`Move resolver ${i + 1} up`}
                        title="Move up"
                      >
                        ↑
                      </button>
                      <button
                        type="button"
                        className="ib"
                        data-move={1}
                        onClick={() => moveRow(i, 1)}
                        disabled={i === upRows.length - 1}
                        aria-label={`Move resolver ${i + 1} down`}
                        title="Move down"
                      >
                        ↓
                      </button>
                      <button type="button" className="del" onClick={() => delRow(i)} aria-label={`Remove resolver ${i + 1}`} title="Remove">
                        ✕
                      </button>
                    </span>
                  </div>
                  {open && (
                    <div className="up-edit">
                      <div className="seg" role="group" aria-label="Protocol">
                        {(['tls', 'https', 'plain'] as UpProto[]).map((p) => (
                          <button
                            type="button"
                            key={p}
                            className={r.proto === p ? 'on' : ''}
                            aria-pressed={r.proto === p}
                            onClick={() => setRow(i, { proto: p })}
                          >
                            {p === 'tls' ? 'DNS over TLS' : p === 'https' ? 'DNS over HTTPS' : 'Plain DNS'}
                          </button>
                        ))}
                      </div>
                      {r.proto === 'https' ? (
                        <Field label="URL">
                          <input
                            className="mono"
                            placeholder="https://dns.example.net/dns-query"
                            value={r.url}
                            onChange={(e) => setRow(i, { url: e.target.value })}
                          />
                        </Field>
                      ) : (
                        <div className={`up-fields${r.proto === 'tls' ? ' tls' : ''}`}>
                          <Field label="Host or IP">
                            <input
                              className="mono"
                              placeholder="1.1.1.1"
                              value={r.host}
                              onChange={(e) => setRow(i, { host: e.target.value })}
                            />
                          </Field>
                          <Field label="Port">
                            <input
                              className="mono"
                              inputMode="numeric"
                              placeholder={r.proto === 'tls' ? '853' : '53'}
                              value={r.port}
                              onChange={(e) => setRow(i, { port: e.target.value })}
                            />
                          </Field>
                          {r.proto === 'tls' && (
                            <Field label="TLS server name">
                              <input
                                className="mono"
                                placeholder="cloudflare-dns.com"
                                value={r.name}
                                onChange={(e) => setRow(i, { name: e.target.value })}
                              />
                            </Field>
                          )}
                        </div>
                      )}
                      {!isEmptyRow(r) && (
                        <div>
                          <button type="button" className="btn sm" onClick={() => setEditing(null)}>
                            Done
                          </button>
                        </div>
                      )}
                    </div>
                  )}
                </div>
              )
            })}
          </div>
        )}

        <div className="presets">
          {!rawUpstreams && (
            <button type="button" className="btn sm" onClick={addRow}>
              Add resolver
            </button>
          )}
          <span className="muted">or use a preset:</span>
          <select
            className="qf"
            value={qfProto}
            onChange={(e) => setQfProto(e.target.value as UpProto)}
            aria-label="Preset protocol"
          >
            <option value="tls">DoT</option>
            <option value="https">DoH</option>
            <option value="plain">Plain</option>
          </select>
          {PROVIDERS.map((p) => (
            <button
              type="button"
              key={p.key}
              className="btn sm quiet"
              onClick={() => quickFill(p)}
              title={`Replace the list with ${p.label}`}
            >
              {p.label}
            </button>
          ))}
          <span className="spacer" />
          <button type="button" className="btn sm quiet" onClick={toggleRaw}>
            {rawUpstreams ? 'Back to the list' : 'Edit as text'}
          </button>
        </div>
        <p className="hint">
          DNS over TLS or HTTPS is recommended: connections are pooled, so large and DNSSEC answers avoid UDP
          fragmentation and per-query handshakes. Plain DNS is unencrypted. A preset replaces the list.
        </p>

        <div className="row3">
          <Field label="Strategy">
            <select
              value={hedged ? 'hedged' : 'ordered'}
              onChange={(e) => patch({ upstream_strategy: e.target.value as UpstreamStrategy })}
            >
              <option value="ordered">In order (failover)</option>
              <option value="hedged">Hedged (race after 30 ms)</option>
            </select>
          </Field>
          {!hedged && (
            <Field label="Timeout per resolver (ms)">
              <input
                type="number"
                min={100}
                max={10000}
                step={100}
                value={s.upstream_timeout_ms}
                onChange={(e) => patch({ upstream_timeout_ms: Number(e.target.value) })}
              />
            </Field>
          )}
        </div>
        <p className="hint">
          {hedged
            ? 'Lowest latency, but queries reach several resolvers and which one answers is not predictable. Also applies to conditional forwarders with more than one upstream.'
            : 'How long one resolver may take before the next is tried (default 1500 ms); the last one gets the rest of the 5 s query budget. Also applies to conditional forwarders with more than one upstream.'}
        </p>
      </Group>

      <Group
        title="Conditional forwarders"
        desc={
          <>
            Send a domain to specific resolvers — your router for <code>home.lan</code>, the office DNS for{' '}
            <code>corp.internal</code>. Pushed to the agents in scope, overriding an agent's own forwarder for the same
            domain. Changes apply as soon as you make them.
          </>
        }
      >
        {legacyFwd.length > 0 && (
          <div className="callout warn">
            <InfoIcon />
            <div>
              <b>
                {legacyFwd.length === 1 ? 'One forwarder' : `${legacyFwd.length} forwarders`} from an older version never
                applied
              </b>
              <p>
                {legacyFwd.map((g) => `${g.suffix} → ${(g.upstreams || []).join(', ')}`).join(' · ')}. They were kept on
                the control plane, which answers no queries. Move them to the list below to forward them on every agent,
                or remove them.
              </p>
              {!readonly && (
                <div className="row">
                  <button type="button" className="btn sm" disabled={legacyBusy} onClick={() => clearLegacyFwd(true)}>
                    Move to the list
                  </button>
                  <button type="button" className="btn sm quiet" disabled={legacyBusy} onClick={() => clearLegacyFwd(false)}>
                    Remove
                  </button>
                </div>
              )}
            </div>
          </div>
        )}
        {/* Outside the callout: it goes away once the legacy list is cleared. */}
        {legacyErr && (
          <div className="callout warn" role="status">
            <InfoIcon />
            <div>{legacyErr}</div>
          </div>
        )}
        <ClusterForwarders reload={fwdReload} />
      </Group>

      <Group title="Blocked answers" desc="What a client gets back for a blocked name.">
        <div className="choice" role="radiogroup" aria-label="Blocked answer">
          {[
            { v: 'nxdomain', t: 'NXDOMAIN', d: '“This name doesn’t exist.” Recommended: apps give up fast.' },
            { v: 'zeroip', t: '0.0.0.0', d: 'A null address (:: for IPv6). Some old devices retry less with this.' },
          ].map((o) => (
            <label key={o.v} className={s.block_response === o.v ? 'on' : ''}>
              <input
                type="radio"
                name="block_response"
                checked={s.block_response === o.v}
                onChange={() => patch({ block_response: o.v })}
              />
              <b>{o.t}</b>
              <small>{o.d}</small>
            </label>
          ))}
        </div>
      </Group>

      <Group title="Cache" desc="Answers are reused until their TTL runs out.">
        <Toggle
          label="Cache answers on every agent"
          desc="Turn off only to debug; every query then goes upstream."
          checked={s.cache.enabled}
          onChange={(v) => patchCache({ enabled: v })}
        />
        <div className="row3">
          <Field label="Max entries">
            <input
              type="number"
              min={0}
              value={s.cache.max_entries}
              onChange={(e) => patchCache({ max_entries: Number(e.target.value) })}
            />
          </Field>
          <Field label="Min TTL (seconds)">
            <input
              type="number"
              min={0}
              value={s.cache.min_ttl_sec}
              onChange={(e) => patchCache({ min_ttl_sec: Number(e.target.value) })}
            />
          </Field>
          <Field label="Max TTL (seconds)">
            <input
              type="number"
              min={0}
              value={s.cache.max_ttl_sec}
              onChange={(e) => patchCache({ max_ttl_sec: Number(e.target.value) })}
            />
          </Field>
        </div>
      </Group>

      <Group title="Security" desc="Protocol hardening and abuse limits.">
        <Toggle
          label="DNSSEC"
          desc="Set the DNSSEC-OK bit upstream and pass the authenticated-data flag to clients. Use an upstream that validates (1.1.1.1, 9.9.9.9, 8.8.8.8)."
          checked={s.dnssec}
          onChange={(v) => patch({ dnssec: v })}
        />
        <div className="check-row">
          <label className="t" htmlFor="rate-limit">
            <b>Rate limit per client</b>
            <small>Answer REFUSED above this many queries per minute. 0 turns it off.</small>
          </label>
          <span className="num-wrap">
            <input
              id="rate-limit"
              type="number"
              min={0}
              value={s.rate_limit_qpm}
              onChange={(e) => patch({ rate_limit_qpm: Number(e.target.value) })}
            />
          </span>
        </div>
      </Group>

      <Group
        title="Privacy"
        desc="What MazeDNS keeps about each query. Filtering always sees the real client and domain; this only changes what is stored, shown and exported."
      >
        <div className="row3">
          <Field label="Privacy level">
            <select
              value={privacyLevel}
              onChange={(e) => patch({ privacy_level: Number(e.target.value) })}
            >
              <option value={0}>Show everything</option>
              <option value={1}>Hide domains</option>
              <option value={2}>Hide domains and clients</option>
              <option value={3}>Anonymous (counts only)</option>
            </select>
          </Field>
          {(privacyLevel === 1 || privacyLevel === 2) && (
            <Field label="Domains to hide">
              <select
                value={s.privacy_domain_k ?? 0}
                onChange={(e) => patch({ privacy_domain_k: Number(e.target.value) })}
              >
                <option value={0}>All domains</option>
                <option value={3}>Visited by fewer than 3 devices</option>
                <option value={5}>Visited by fewer than 5 devices</option>
                <option value={10}>Visited by fewer than 10 devices</option>
                <option value={20}>Visited by fewer than 20 devices</option>
              </select>
            </Field>
          )}
          {privacyLevel > 0 && (
            <Field label="Keep full detail for">
              <select
                value={s.privacy_detail_hours ?? 0}
                onChange={(e) => patch({ privacy_detail_hours: Number(e.target.value) })}
              >
                <option value={0}>No time (apply at once)</option>
                <option value={1}>1 hour</option>
                <option value={6}>6 hours</option>
                <option value={24}>24 hours</option>
                <option value={72}>3 days</option>
                <option value={168}>7 days</option>
              </select>
            </Field>
          )}
        </div>
        <p className="hint">{PRIVACY_HINT[privacyLevel] ?? PRIVACY_HINT[0]}</p>
        {(privacyLevel === 1 || privacyLevel === 2) && (s.privacy_domain_k ?? 0) > 0 && (
          <p className="hint">
            A domain is kept only when at least {s.privacy_domain_k} different devices queried it that day (UTC) or the
            day before, so a domain that points to one person (a personal site, a clinic, a small employer) is hidden.
            When a name is rare but its registered domain is common, the registered domain is kept instead
            (u123.tracker.com becomes tracker.com).
          </p>
        )}
        {privacyLevel > 0 && (
          <p className="hint">
            {(s.privacy_detail_hours ?? 0) > 0
              ? `Queries keep full detail for ${s.privacy_detail_hours} h, for troubleshooting, then the level applies to them. Exports to VictoriaLogs always get the reduced data.`
              : 'The level applies as queries arrive.'}{' '}
            Raising the level also applies it to the history already stored. Lowering it cannot bring back what was removed.
          </p>
        )}
      </Group>
    </>
  )

  // -------------------------------------------------------------------- Access
  const passwordOff = !!cp && cp.oidc.enabled && cp.oidc.disable_password_login
  const accessView = readonly ? (
    <div className="callout">
      <InfoIcon />
      <div>
        <b>Only administrators can see access settings</b>
        <p>Sign-in methods, sessions and agent enrollment policy are visible to the admin role.</p>
      </div>
    </div>
  ) : !cp ? (
    cpErr ? (
      <div className="error">
        <span className="grow">Couldn't load access settings: {cpErr}</span>
        <button className="btn sm" onClick={loadCP}>
          Try again
        </button>
      </div>
    ) : (
      <SkelGroups groups={3} />
    )
  ) : (
    <>
      <Group title="Sign-in methods" desc="How people get into this control plane.">
        <div className="method">
          <span className="ic">
            <LockIcon />
          </span>
          <div>
            <b>Username and password</b>
            <small>Local accounts. {PASSWORD_RULE}.</small>
          </div>
          {passwordOff ? <span className="tag">Off</span> : <span className="tag ok">On</span>}
        </div>

        <div className={`method${ssoOpen ? ' open' : ''}`}>
          <span className="ic">
            <GlobeIcon />
          </span>
          <div>
            <b>Single sign-on (OIDC)</b>
            <small>Authentik, Keycloak, Entra ID, Google… Map a group to the admin role.</small>
          </div>
          <span className="method-act">
            {cp.oidc.enabled && <span className="tag ok">On</span>}
            {!ssoOpen ? (
              <button type="button" className="btn sm" onClick={() => setSsoOpen(true)}>
                {cp.oidc.enabled ? 'Edit' : 'Set up SSO'}
              </button>
            ) : (
              !cp.oidc.enabled && (
                <button type="button" className="btn sm quiet" onClick={() => setSsoOpen(false)}>
                  Close
                </button>
              )
            )}
          </span>
          {ssoOpen && (
            <div className="method-body">
              <Toggle
                label="Allow sign-in with SSO"
                desc="Adds a “Continue with SSO” button to the sign-in page."
                checked={cp.oidc.enabled}
                onChange={(v) => setCp({ ...cp, oidc: { ...cp.oidc, enabled: v } })}
              />
              <div className="row2">
                <Field label="Issuer URL" className="span2">
                  <input
                    className="mono"
                    value={cp.oidc.issuer}
                    placeholder="https://idp.example.com/application/o/mazedns/"
                    onChange={(e) => setCp({ ...cp, oidc: { ...cp.oidc, issuer: e.target.value } })}
                  />
                </Field>
                <Field label="Client ID">
                  <input value={cp.oidc.client_id} onChange={(e) => setCp({ ...cp, oidc: { ...cp.oidc, client_id: e.target.value } })} />
                </Field>
                <Field label="Client secret" hint={oidcHasSecret ? 'Saved. Leave empty to keep it.' : undefined}>
                  <input
                    type="password"
                    autoComplete="new-password"
                    placeholder={oidcHasSecret ? '••••••••' : ''}
                    value={cp.oidc.client_secret}
                    onChange={(e) => setCp({ ...cp, oidc: { ...cp.oidc, client_secret: e.target.value } })}
                  />
                </Field>
                <Field label="Redirect URL" className="span2" hint="Register this exact value with your identity provider.">
                  <input
                    className="mono"
                    value={cp.oidc.redirect_url}
                    placeholder={`${window.location.origin}/api/auth/oidc/callback`}
                    onChange={(e) => setCp({ ...cp, oidc: { ...cp.oidc, redirect_url: e.target.value } })}
                  />
                </Field>
                <Field label="Extra scopes" hint="openid, profile and email are always requested.">
                  <input
                    value={(cp.oidc.scopes || []).join(', ')}
                    onChange={(e) =>
                      setCp({
                        ...cp,
                        oidc: { ...cp.oidc, scopes: e.target.value.split(',').map((x) => x.trimStart()) },
                      })
                    }
                    onBlur={() =>
                      setCp({ ...cp, oidc: { ...cp.oidc, scopes: (cp.oidc.scopes || []).map((x) => x.trim()).filter(Boolean) } })
                    }
                  />
                </Field>
                <Field label="Groups claim">
                  <input value={cp.oidc.groups_claim} onChange={(e) => setCp({ ...cp, oidc: { ...cp.oidc, groups_claim: e.target.value } })} />
                </Field>
                <Field label="Admin group" hint="Members get the admin role; everyone else is a viewer.">
                  <input
                    value={cp.oidc.admin_group}
                    placeholder="mazedns-admins"
                    onChange={(e) => setCp({ ...cp, oidc: { ...cp.oidc, admin_group: e.target.value } })}
                  />
                </Field>
                <Field label="Admin email" hint="This identity always gets the admin role on sign-in.">
                  <input
                    value={cp.oidc.admin_email}
                    placeholder="you@example.com"
                    onChange={(e) => setCp({ ...cp, oidc: { ...cp.oidc, admin_email: e.target.value } })}
                  />
                </Field>
              </div>
              <Toggle
                label="Turn off password sign-in"
                desc="SSO only. Local accounts can no longer sign in."
                checked={cp.oidc.disable_password_login}
                onChange={(v) => setCp({ ...cp, oidc: { ...cp.oidc, disable_password_login: v } })}
              />
              <Toggle
                label="Go straight to the identity provider"
                desc="Skip the sign-in page. Signing out still shows it, so you can switch accounts."
                checked={cp.oidc.auto_login}
                onChange={(v) => setCp({ ...cp, oidc: { ...cp.oidc, auto_login: v } })}
              />
              <Toggle
                label="Let SSO users replace their picture"
                desc="Off: the picture from the identity provider always shows. On: people can upload their own under Account, and it wins. Local accounts can always upload."
                checked={!!cp.oidc.allow_avatar_upload}
                onChange={(v) => setCp({ ...cp, oidc: { ...cp.oidc, allow_avatar_upload: v } })}
              />
            </div>
          )}
        </div>

        <div className="callout">
          <InfoIcon />
          <div>
            <b>Keep one local admin</b>
            <p>
              If your identity provider goes down, a local account is the only way in short of the CLI{' '}
              <code>control-plane reset-admin</code>.
            </p>
          </div>
        </div>
      </Group>

      <Group title="Sessions" desc="How long a sign-in lasts and how hard guessing is.">
        <div className="row3">
          <Field label="Stay signed in for (hours)">
            <input
              type="number"
              min={1}
              value={Math.round(cp.session_ttl_sec / 3600)}
              onChange={(e) => setCp({ ...cp, session_ttl_sec: Math.max(1, Number(e.target.value)) * 3600 })}
            />
          </Field>
          <Field label="Sign-in attempts allowed" hint="0 = no limit">
            <input
              type="number"
              min={0}
              value={cp.login_rate_attempts}
              onChange={(e) => setCp({ ...cp, login_rate_attempts: Math.max(0, Number(e.target.value)) })}
            />
          </Field>
          <Field label="Per window (seconds)">
            <input
              type="number"
              min={1}
              value={cp.login_rate_window_sec}
              onChange={(e) => setCp({ ...cp, login_rate_window_sec: Math.max(1, Number(e.target.value)) })}
            />
          </Field>
        </div>
        <p className="hint">Failed and successful sign-ins are throttled per source address and per username.</p>
      </Group>

      <Group title="New agents" desc="What happens when an agent enrolls with a valid key.">
        <Toggle
          label="Ask me before a new agent serves DNS"
          desc="It shows up under Agents waiting for approval."
          checked={cp.require_approval}
          onChange={(v) => setCp({ ...cp, require_approval: v })}
        />
        <div className="row2">
          <Field label="Rotate node keys every (days)" hint="0 = the default, 30 days">
            <input
              type="number"
              min={0}
              value={Math.round(cp.key_max_age_sec / 86400)}
              onChange={(e) => setCp({ ...cp, key_max_age_sec: Math.max(0, Number(e.target.value)) * 86400 })}
            />
          </Field>
          <Field label="Old key stays valid for (minutes)">
            <input
              type="number"
              min={0}
              value={Math.round(cp.key_grace_sec / 60)}
              onChange={(e) => setCp({ ...cp, key_grace_sec: Math.max(0, Number(e.target.value)) * 60 })}
            />
          </Field>
        </div>
        <Field
          label="Address agents use to reach this control plane"
          hint="Optional. Leave empty to use the address agents enrolled with."
        >
          <input
            className="mono"
            placeholder="https://dns.example.com"
            value={cp.advertise_addr}
            onChange={(e) => setCp({ ...cp, advertise_addr: e.target.value })}
          />
        </Field>
      </Group>

      <ApiTokens />
    </>
  )

  // ------------------------------------------------------------ Classification
  const keyPlaceholder = (has: boolean | undefined, empty: string) => (has ? '•••••••• (saved, leave empty to keep)' : empty)
  const classificationView = cls && (
    <>
      <p className="cls-intro">
        Classification tells you two things about every domain your network uses: <b>what it is</b> (its traffic type: social,
        streaming, work, …) and <b>whether it’s safe</b> (its risk).{' '}
        <button type="button" className="linklike" onClick={() => setShowClsHelp(true)}>
          How classification works
        </button>
      </p>

      <Group
        title="Traffic types"
        desc="What each domain is. Every query is labelled as it arrives, for Overview, Queries and Clients. Always on, and local: nothing is sent out."
      >
        <ul className="cls-sources">
          <li>
            <b>Category database</b>
            <span>
              {!catList
                ? 'Loading…'
                : !catList.enabled
                  ? 'Off on this control plane (MAZEDNS_CATEGORY_DB=off).'
                  : catList.database.updated_at
                    ? `UT1, Université Toulouse Capitole: ${catList.database.domains.toLocaleString()} domains, updated ${timeAgo(catList.database.updated_at * 1000)}.`
                    : catList.database.loading
                      ? 'UT1: downloading…'
                      : 'UT1: not loaded yet.'}
              {catList?.database.error && <span className="bad-text"> Last refresh failed: {catList.database.error}</span>}
            </span>
          </li>
          <li>
            <b>Common platforms</b>
            <span>A built-in list of the services behind most everyday traffic: Apple, Microsoft, Google, CDNs, the big apps.</span>
          </li>
          <li>
            <b>Local network</b>
            <span>Names your local records answer, reverse lookups and private names (.lan, .home.arpa…).</span>
          </li>
          <li>
            <b>Your corrections</b>
            <span>Change any domain’s type from its details (Queries → a query → Category); it wins over everything else.</span>
          </li>
          <li>
            <b>
              AI model <span className="muted">(optional)</span>
            </b>
            <span>Labels what none of the above knows. Needs lookups on (below).</span>
          </li>
        </ul>
        <p className="hint">
          To block whole types on every agent (adult, gambling, social…), go to{' '}
          <a
            href="/filtering?tab=categories"
            onClick={(e) => {
              e.preventDefault()
              window.history.pushState({}, '', '/filtering?tab=categories')
              window.dispatchEvent(new PopStateEvent('popstate'))
            }}
          >
            Filtering → Categories
          </a>
          .
        </p>
      </Group>

      <Group
        title="Lookups and risk"
        desc="Looks up each newly seen domain with the services you choose below, to score its risk and, with an AI model, to label its type."
      >
        <Toggle
          label="Look up new domains"
          desc="Each domain starts legitimate; the signals you turn on below adjust its score, with risky TLDs and look-alike names always counted. Runs on the control plane, never on the DNS path. Off: nothing below downloads or sends anything."
          checked={cls.enabled}
          onChange={(v) => (v ? setConfirmClassify(true) : setCls({ ...cls, enabled: false }))}
        />
        <div className="row2">
          <Field label="When a domain looks risky">
            <select value={cls.mode} onChange={(e) => setCls({ ...cls, mode: e.target.value })}>
              <option value="off">Do nothing (off)</option>
              <option value="suggest">Suggest a block for me to approve</option>
              <option value="auto">Block it automatically</option>
            </select>
          </Field>
        </div>
      </Group>

      <Group
        title="Keep private"
        desc="Your own domains are never looked up, so they never reach WHOIS, reputation services or the AI model. Their traffic types still apply: those are looked up locally."
      >
        <Field
          label="Never look up these domains (one per line)"
          hint="Each covers its subdomains (example.com covers nas.example.com). Names answered by your local records and names under a conditional forwarder are always skipped."
        >
          <textarea
            rows={4}
            value={(cls.exclude_domains ?? []).join('\n')}
            onChange={(e) => setCls({ ...cls, exclude_domains: e.target.value.split('\n') })}
            placeholder={'example.com\ncorp.example.net'}
          />
        </Field>
      </Group>

      {!cls.enabled && (
        <div className="callout cls-off-note">
          <InfoIcon />
          <div>
            <b>Lookups are off</b>
            <p>The services below apply once “Look up new domains” is on. They are kept as they are, and none of them downloads or sends anything meanwhile.</p>
          </div>
        </div>
      )}
      <fieldset className="cls-deps" disabled={!cls.enabled}>
      <Group
        title="AI model"
        desc="Optional. Helps both ways: labels the traffic types the database doesn’t know, and adds one bounded risk signal that mainly cuts false positives."
      >
        <Toggle
          label="Use an AI model"
          desc="Sends every new domain to the model you configure: your own endpoint, or the hosted provider’s API (api.anthropic.com, api.openai.com…). Off = static signals only."
          checked={!!cls.ai_enabled}
          onChange={(v) => setCls({ ...cls, ai_enabled: v })}
        />
        {cls.ai_enabled && (
          <div className="row2">
            <Field label="Provider" className="span2">
              <select value={cls.provider || 'openai'} onChange={(e) => setCls({ ...cls, provider: e.target.value })}>
                <option value="openai">OpenAI-compatible (Ollama, OpenAI, LM Studio, vLLM…)</option>
                <option value="anthropic">Anthropic (Claude)</option>
              </select>
            </Field>
            {cls.provider !== 'anthropic' && (
              <Field label="Endpoint (OpenAI-compatible base URL)" className="span2">
                <input
                  className="mono"
                  value={cls.endpoint}
                  onChange={(e) => setCls({ ...cls, endpoint: e.target.value })}
                  placeholder="http://localhost:11434/v1"
                />
              </Field>
            )}
            <Field label="Model">
              <input
                value={cls.model}
                onChange={(e) => setCls({ ...cls, model: e.target.value })}
                placeholder={cls.provider === 'anthropic' ? 'claude-haiku-4-5' : 'llama3.2'}
              />
            </Field>
            <Field
              label={
                <>
                  API key {cls.provider === 'anthropic' ? '' : <span className="faint">(optional)</span>}{' '}
                  <KeySet on={clsInfo?.has_api_key} />
                </>
              }
            >
              <input
                type="password"
                autoComplete="new-password"
                value={cls.api_key}
                onChange={(e) => setCls({ ...cls, api_key: e.target.value })}
                placeholder={keyPlaceholder(clsInfo?.has_api_key, cls.provider === 'anthropic' ? 'sk-ant-…' : 'Usually empty for local models')}
              />
            </Field>
            <Field label="Min gap between model calls (ms)">
              <input
                type="number"
                min={0}
                value={cls.min_gap_ms}
                onChange={(e) => setCls({ ...cls, min_gap_ms: Number(e.target.value) })}
              />
            </Field>
            <Field label="Request timeout (seconds)" hint="Raise it if a local model is slow to warm up.">
              <input
                type="number"
                min={1}
                value={cls.timeout_sec}
                onChange={(e) => setCls({ ...cls, timeout_sec: Number(e.target.value) })}
              />
            </Field>
          </div>
        )}
        <div className="row rw-only">
          <button type="button" className="btn sm" onClick={testClassifier} disabled={testing}>
            {testing ? <Spinner label="Testing…" /> : 'Test connection'}
          </button>
          <span className="hint" style={{ margin: 0 }}>
            Tests the settings as shown, before saving. Review verdicts under Filtering.
          </span>
        </div>
        <Msg m={testMsg} />
      </Group>

      <Group title="Trusted list" desc="Risk: domains on the trusted list are never blocked, even if a signal flags them.">
        <Toggle
          label="Use the built-in public list"
          desc="Majestic Million top domains, downloaded from majestic.com. A download only: it receives none of your queries."
          checked={!cls.trusted_disable_default}
          onChange={(v) => setCls({ ...cls, trusted_disable_default: !v })}
        />
        <div className="row2">
          <Field label="Your own trusted list (optional)" hint="URL or file path; plain, hosts or ranked CSV." className="span2">
            <input
              className="mono"
              value={cls.trusted_list_url}
              onChange={(e) => setCls({ ...cls, trusted_list_url: e.target.value })}
              placeholder="https://… or /path/to/allowlist.txt"
            />
          </Field>
          <Field label="Built-in list size" hint="Load only the top N domains. 0 = 100,000.">
            <input
              type="number"
              min={0}
              value={cls.trusted_top_n}
              onChange={(e) => setCls({ ...cls, trusted_top_n: Number(e.target.value) })}
            />
          </Field>
        </div>
      </Group>

      <Group
        title="Threat-intelligence feeds"
        desc="Risk: a domain on any enabled feed counts as malicious, even if nothing else flags it. Each feed is downloaded from its publisher (abuse.ch, GitHub…) and receives none of your queries."
      >
        <div className="toggles">
          {(clsInfo?.threat_feed_catalog ?? []).map((f) => (
            <Toggle
              key={f.key}
              label={f.name}
              desc={f.desc}
              checked={(cls.threat_feeds ?? []).includes(f.key)}
              onChange={(on) => {
                const cur = cls.threat_feeds ?? []
                setCls({ ...cls, threat_feeds: on ? [...cur, f.key] : cur.filter((k) => k !== f.key) })
              }}
            />
          ))}
        </div>
        <Field label="Your own threat lists (optional)" hint="One URL or file path per line.">
          <textarea
            rows={2}
            value={cls.threat_list_url}
            onChange={(e) => setCls({ ...cls, threat_list_url: e.target.value })}
            placeholder={'https://example.com/malware-domains.txt\n/path/to/threatlist.txt'}
          />
        </Field>
      </Group>

      <Group
        title="Reputation services"
        desc="Risk: optional lookups per new domain. A clean report raises the score, a malicious one lowers it. Keys stay on the server."
      >
        <div className="toggles">
          <Toggle
            label="WHOIS"
            desc="Domain age and registrar. Sends each new domain to rdap.org and its registry (or the registry’s WHOIS server). A strong signal for young, throwaway domains."
            checked={cls.whois_enabled}
            onChange={(v) => setCls({ ...cls, whois_enabled: v })}
          />
          <Toggle
            label="VirusTotal"
            desc="Sends each new domain to virustotal.com for its reputation."
            checked={cls.vt_enabled}
            onChange={(v) => setCls({ ...cls, vt_enabled: v })}
          />
          {cls.vt_enabled && (
            <Field label={<>VirusTotal API key <KeySet on={clsInfo?.has_vt_key} /></>} className="sub-field">
              <input
                type="password"
                autoComplete="new-password"
                value={cls.vt_api_key}
                onChange={(e) => setCls({ ...cls, vt_api_key: e.target.value })}
                placeholder={keyPlaceholder(clsInfo?.has_vt_key, 'Paste your VirusTotal API key')}
              />
            </Field>
          )}
          <Toggle
            label="AbuseIPDB"
            desc="Sends the address each new domain resolves to to abuseipdb.com."
            checked={cls.abuseipdb_enabled}
            onChange={(v) => setCls({ ...cls, abuseipdb_enabled: v })}
          />
          {cls.abuseipdb_enabled && (
            <Field label={<>AbuseIPDB API key <KeySet on={clsInfo?.has_abuseipdb_key} /></>} className="sub-field">
              <input
                type="password"
                autoComplete="new-password"
                value={cls.abuseipdb_api_key}
                onChange={(e) => setCls({ ...cls, abuseipdb_api_key: e.target.value })}
                placeholder={keyPlaceholder(clsInfo?.has_abuseipdb_key, 'Paste your AbuseIPDB API key')}
              />
            </Field>
          )}
          <Toggle
            label="Kaspersky OpenTIP"
            desc="Sends each new domain to opentip.kaspersky.com for its threat zone."
            checked={cls.opentip_enabled}
            onChange={(v) => setCls({ ...cls, opentip_enabled: v })}
          />
          <Toggle
            label="Nameserver check"
            desc="When a domain is served by a trusted company’s own nameservers, asks Cloudflare and Quad9 over DNS-over-HTTPS whether it really resolves before trusting it. Sends that domain to them. Needs WHOIS."
            checked={!cls.ns_check_disabled}
            onChange={(v) => setCls({ ...cls, ns_check_disabled: !v })}
          />
          {cls.opentip_enabled && (
            <Field label={<>OpenTIP API key <KeySet on={clsInfo?.has_opentip_key} /></>} className="sub-field">
              <input
                type="password"
                autoComplete="new-password"
                value={cls.opentip_api_key}
                onChange={(e) => setCls({ ...cls, opentip_api_key: e.target.value })}
                placeholder={keyPlaceholder(clsInfo?.has_opentip_key, 'Paste your OpenTIP API token')}
              />
            </Field>
          )}
        </div>
      </Group>
      </fieldset>

      {showClsHelp && <ClassifierHelp onClose={() => setShowClsHelp(false)} />}
      {confirmClassify && (
        <Modal
          kind="dialog"
          title="Turn on lookups?"
          onClose={() => setConfirmClassify(false)}
          footer={
            <>
              <span className="spacer" />
              <button type="button" className="btn ghost" onClick={() => setConfirmClassify(false)}>
                Cancel
              </button>
              <button
                type="button"
                className="btn primary"
                onClick={() => {
                  setCls({ ...cls, enabled: true })
                  setConfirmClassify(false)
                }}
              >
                Turn on
              </button>
            </>
          }
        >
          <div className="ag-form">
            <p>New domains your clients query will be looked up on the control plane, to score their risk and label their type. With your current choices:</p>
            <ul className="cls-contacts">
              {externalContacts(cls).map((c) => (
                <li key={c}>{c}</li>
              ))}
              {externalContacts(cls).length === 0 && <li>Nothing is contacted: only the local signals (risky TLDs, look-alike names) are used.</li>}
            </ul>
            <p className="muted small">You can change each of these below, before or after saving. Nothing changes until you save.</p>
          </div>
        </Modal>
      )}
    </>
  )

  // -------------------------------------------------------------- Integrations
  const integrationsView = (
    <>
      {!vm && !vl && !cp && <SkelGroups groups={3} />}
      {cp && !readonly && (
        <Group title="Metrics endpoint" desc={<>Protect the control plane’s <code>/metrics</code> with a bearer token.</>}>
          <div className="check-row">
            <span className="t">
              <b>Scrape token</b>
              <small>
                {hasMetricsToken
                  ? `Set (starts with ${cp.metrics_scrape_token_prefix}…). /metrics requires Authorization: Bearer <token>.`
                  : 'Not set: /metrics is open to anyone who can reach this port.'}
              </small>
            </span>
            {hasMetricsToken ? <span className="tag ok">On</span> : <span className="tag warn">Open</span>}
          </div>
          {newScrapeToken && (
            <div className="callout ok">
              <div className="grow" style={{ minWidth: 0 }}>
                <b>Copy the new token now. It won’t be shown again.</b>
                <pre className="codebox">{newScrapeToken}</pre>
                <p>
                  Prometheus: <code>authorization: {'{'} type: Bearer, credentials: &lt;token&gt; {'}'}</code> under the
                  scrape job.
                </p>
              </div>
            </div>
          )}
          <Msg m={tokenMsg} />
          <div className="row">
            <button type="button" className="btn sm" onClick={genMetricsToken}>
              {hasMetricsToken ? 'Make a new token' : 'Make a token'}
            </button>
            {hasMetricsToken && (
              <button type="button" className="btn sm danger" onClick={clearMetricsToken}>
                Remove token (open /metrics)
              </button>
            )}
            <span className="hint" style={{ margin: 0 }}>
              Applies immediately. Stored hashed.
            </span>
          </div>
        </Group>
      )}

      {vm && (
        <Group title="VictoriaMetrics" desc="Push metrics to VictoriaMetrics on an interval for long-term retention.">
          <Toggle
            label="Export metrics"
            desc={
              <>
                Each agent pushes its own Prometheus metrics to <code>/api/v1/import/prometheus</code>, labelled with
                its instance, so nothing has to scrape every agent. Changes apply on the next push.
              </>
            }
            checked={vm.enabled}
            onChange={(v) => setVm({ ...vm, enabled: v })}
          />
          <div className="row3">
            <Field label="URL" className="span3">
              <input
                className="mono"
                value={vm.url}
                onChange={(e) => setVm({ ...vm, url: e.target.value })}
                placeholder="http://victoriametrics:8428"
              />
            </Field>
            <Field label="Push every (seconds)">
              <input
                type="number"
                min={1}
                value={vm.interval_sec}
                onChange={(e) => setVm({ ...vm, interval_sec: Number(e.target.value) })}
              />
            </Field>
            <Field label="Job label">
              <input value={vm.job} onChange={(e) => setVm({ ...vm, job: e.target.value })} placeholder="mazedns" />
            </Field>
            <Field label="Instance label">
              <input
                value={vm.instance}
                onChange={(e) => setVm({ ...vm, instance: e.target.value })}
                placeholder="Empty = hostname"
              />
            </Field>
          </div>
          <div className="row2">
            <Field label="Username (optional)">
              <input value={vm.username} onChange={(e) => setVm({ ...vm, username: e.target.value })} />
            </Field>
            <Field label="Password (optional)" hint={vmHasPassword ? 'Saved. Leave empty to keep it.' : undefined}>
              <input
                type="password"
                autoComplete="new-password"
                value={vm.password}
                onChange={(e) => setVm({ ...vm, password: e.target.value })}
                placeholder={vmHasPassword ? '••••••••' : ''}
              />
            </Field>
          </div>
        </Group>
      )}

      {vl && (
        <Group title="VictoriaLogs" desc="Ship the cluster-wide query log to VictoriaLogs to keep history past the local window.">
          <Toggle
            label="Export the query log"
            desc={
              <>
                The control plane sends batches to <code>/insert/jsonline</code>; query them there with LogsQL.
              </>
            }
            checked={vl.enabled}
            onChange={(v) => setVl({ ...vl, enabled: v })}
          />
          <div className="row3">
            <Field label="URL" className="span2">
              <input
                className="mono"
                value={vl.url}
                onChange={(e) => setVl({ ...vl, url: e.target.value })}
                placeholder="http://victorialogs:9428"
              />
            </Field>
            <Field label="Ship every (seconds)">
              <input
                type="number"
                min={1}
                value={vl.interval_sec}
                onChange={(e) => setVl({ ...vl, interval_sec: Number(e.target.value) })}
              />
            </Field>
          </div>
          <div className="row2">
            <Field label="Username (optional)">
              <input value={vl.username} onChange={(e) => setVl({ ...vl, username: e.target.value })} />
            </Field>
            <Field label="Password (optional)" hint={vlHasPassword ? 'Saved. Leave empty to keep it.' : undefined}>
              <input
                type="password"
                autoComplete="new-password"
                value={vl.password}
                onChange={(e) => setVl({ ...vl, password: e.target.value })}
                placeholder={vlHasPassword ? '••••••••' : ''}
              />
            </Field>
          </div>
        </Group>
      )}
    </>
  )

  // -------------------------------------------------------------------- Backup
  const auditShown = audit ? (auditAll ? audit : audit.slice(0, 12)) : []
  const backupView = readonly ? (
    <div className="callout">
      <InfoIcon />
      <div>
        <b>Only administrators can back up or restore</b>
        <p>Exports contain every rule, rewrite and setting, so they need the admin role.</p>
      </div>
    </div>
  ) : (
    <>
      <Group title="Export" desc="Download settings, rules and rewrites as one JSON file.">
        <div>
          <button type="button" className="btn" onClick={doExport}>
            Export configuration
          </button>
        </div>
      </Group>

      <Group title="Restore" desc="Load an exported file into this control plane.">
        <div className="choice" role="radiogroup" aria-label="Import mode">
          <label className={importMode === 'merge' ? 'on' : ''}>
            <input type="radio" name="import_mode" checked={importMode === 'merge'} onChange={() => setImportMode('merge')} />
            <b>Merge</b>
            <small>Add and update on top of what’s here. Nothing is removed.</small>
          </label>
          <label className={`danger${importMode === 'replace' ? ' on' : ''}`}>
            <input
              type="radio"
              name="import_mode"
              checked={importMode === 'replace'}
              onChange={() => setImportMode('replace')}
            />
            <b>Replace</b>
            <small>Delete every rule and rewrite first, then import. Can’t be undone.</small>
          </label>
        </div>
        {importMsg && <div className="ok-msg">{importMsg}</div>}
        <div>
          <button
            type="button"
            className={`btn${importMode === 'replace' ? ' danger' : ''}`}
            onClick={() => fileRef.current?.click()}
          >
            {importMode === 'replace' ? 'Choose a file and replace…' : 'Choose a file and merge…'}
          </button>
          <input
            ref={fileRef}
            type="file"
            accept="application/json,.json"
            hidden
            onChange={(e) => e.target.files?.[0] && doImport(e.target.files[0])}
          />
        </div>
      </Group>

      <Group title="Change history" desc="Recorded admin actions on settings, people and agents, newest first.">
        {auditErr ? (
          <div className="error">
            <span className="grow">Couldn't load the history: {auditErr}</span>
            <button className="btn sm" onClick={loadAudit}>
              Try again
            </button>
          </div>
        ) : audit === null ? (
          <SkelList rows={5} />
        ) : audit.length === 0 ? (
          <p className="muted" style={{ margin: 0 }}>
            No changes recorded yet.
          </p>
        ) : (
          <>
            <div className="audit">
              <table className="stackable">
                <thead>
                  <tr>
                    <th>When</th>
                    <th>Who</th>
                    <th>What</th>
                  </tr>
                </thead>
                <tbody>
                  {auditShown.map((a, i) => (
                    <tr key={i}>
                      <td className="lead-r nowrap muted">{fmtTime(a.ts)}</td>
                      <td className="lead">{a.user}</td>
                      <td>
                        <span className="mono">{a.action}</span>
                        {a.detail && <div className="muted small wrap">{a.detail}</div>}
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
            {audit.length > 12 && (
              <div>
                <button type="button" className="btn sm quiet" onClick={() => setAuditAll(!auditAll)}>
                  {auditAll ? 'Show fewer' : `Show all ${audit.length}`}
                </button>
              </div>
            )}
          </>
        )}
      </Group>
    </>
  )

  const body =
    shownView === 'resolver'
      ? resolverView
      : shownView === 'access'
      ? accessView
      : shownView === 'classification'
      ? classificationView
      : shownView === 'integrations'
      ? integrationsView
      : backupView

  return (
    <div className="pg-settings">
      {head}
      {err && <div className="error">{err}</div>}

      <div className="st-layout">
        <nav className="st-nav" role="tablist" aria-label="Settings sections">
          {views.map((v) => (
            <button
              key={v}
              type="button"
              role="tab"
              aria-selected={shownView === v}
              className={shownView === v ? 'on' : ''}
              onClick={() => setView(v)}
            >
              {VIEW_LABEL[v]}
              {dirtyViews[v] && <span className="dot warn" title="Unsaved changes" />}
            </button>
          ))}
          <small>Database, listen address and log level stay in the config file.</small>
        </nav>

        <div className="st-main">
          {readonly && shownView !== 'access' && shownView !== 'backup' && shownView !== 'about' && (
            <div className="callout">
              <InfoIcon />
              <div>
                <b>Read-only</b>
                <p>You’re signed in as a viewer. Ask an administrator to change these settings.</p>
              </div>
            </div>
          )}
          {shownView === 'about' ? (
            <About />
          ) : (
            <fieldset className="st-fs" disabled={readonly}>
              {body}
            </fieldset>
          )}

          {!readonly && ((shownView !== 'backup' && shownView !== 'about') || anyDirty) && (
            <div className={`savebar${anyDirty ? ' dirty' : !savedNote && !saveErr ? ' idle' : ''}`} role="status">
              {saveErr ? (
                <span className="bad-text grow">Couldn’t save: {saveErr}</span>
              ) : anyDirty ? (
                <span className="grow">
                  <span className="dot warn" /> Unsaved changes
                  {otherDirty.length > 0 && (
                    <span className="muted">
                      {dirtyViews[shownView] ? ' here and in ' : ' in '}
                      {otherDirty.join(', ')}
                    </span>
                  )}
                </span>
              ) : savedNote ? (
                <span className="ok-text grow">Saved and pushed to agents.</span>
              ) : (
                <span className="muted grow">No unsaved changes</span>
              )}
              <button type="button" className="btn quiet" onClick={discard} disabled={!anyDirty || saving}>
                Discard
              </button>
              <button type="button" className="btn primary" onClick={saveAll} disabled={!anyDirty || saving}>
                {saving ? 'Saving…' : 'Save and apply'}
              </button>
            </div>
          )}
        </div>
      </div>
    </div>
  )
}
