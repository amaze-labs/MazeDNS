export interface Stats {
  total: number
  blocked: number
  cached: number
  forwarded: number
  rewritten: number
  errors: number
  cache_size: number
  log_count: number
}

export interface QueryLogEntry {
  id: number
  ts: number
  client: string
  name: string
  qtype: string
  action: string
  category: string
  rcode: string
  elapsed_ms: number
  node: string
}

export interface Rule {
  id: number
  action: string
  domain: string
  category: string
  enabled: boolean
  updated_at: number
}

export interface Rewrite {
  id: number
  domain: string
  rrtype: string
  value: string
  enabled: boolean
  updated_at: number
}

export interface Node {
  name: string
  key_prefix: string
  address: string
  version: string
  last_seen: number
  created_at: number
  is_master: boolean
  total: number
  blocked: number
  cached: number
  forwarded: number
  rewritten: number
  errors: number
}

export interface SessionUser {
  id: number
  username: string
  role: string
  source?: string // "local" | "oidc"
  avatar_url?: string
}

export interface AuthInfo {
  auth_enabled: boolean
  oidc_enabled: boolean
  password_login_disabled: boolean
  oidc_auto_login: boolean
  cluster_enabled: boolean
  classifier_available: boolean
  classifier_enabled: boolean
}

export interface ScoreFactor {
  label: string
  detail: string
  delta: number // change to legitimacy (negative = risk, 0 = neutral)
}

export interface Classification {
  domain: string
  category: string
  block: boolean
  status: string // suggested|approved|rejected|auto|clean
  confidence: number
  score: number // legitimacy 0-100 (100 = fully legit, low = risky)
  factors?: ScoreFactor[]
  reason: string
  model: string
  trusted: boolean
  threat: boolean
  note: string // operator review note set when allowing/blocking
  updated_at: number
}

export interface DomainClient {
  client: string
  name: string // enriched display name (NetBird peer / reverse-DNS)
  source: string // "netbird" | "rdns" | ""
  count: number
  blocked: number
  last_seen: number
}

export interface NetbirdSettings {
  enabled: boolean
  api_url: string
  token: string
}

export interface ClientIdentity {
  name: string // NetBird peer / reverse-DNS hostname ("" if unknown)
  source: string // "netbird" | "rdns" | ""
}

export interface ClassifierSettings {
  enabled: boolean
  endpoint: string
  model: string
  api_key: string
  mode: string // off|suggest|auto
  min_gap_ms: number
  timeout_sec: number
  trusted_list_url: string
  trusted_top_n: number
  trusted_disable_default: boolean
  threat_feeds: string[]
  threat_list_url: string
  threat_disable_default: boolean
  whois_enabled: boolean
  vt_enabled: boolean
  vt_api_key: string
  abuseipdb_enabled: boolean
  abuseipdb_api_key: string
}

export interface LLMUsageDay {
  day: string
  calls: number
  errors: number
  prompt_tokens: number
  completion_tokens: number
  latency_ms_total: number
}

export interface ThreatFeed {
  key: string
  name: string
  desc: string
  url: string
}

export interface WhoisInfo {
  domain: string
  registrar: string
  registrant: string
  created: string
  expires: string
  updated: string
  age_days: number
  status: string[]
  nameservers: string[]
}

export interface ClassifierStatus {
  settings: ClassifierSettings
  counts: Record<string, number>
  category_counts: Record<string, number>
  trusted_count: number
  threat_count: number
  threat_feed_catalog: ThreatFeed[]
  llm_usage: LLMUsageDay[]
  llm_usage_totals: LLMUsageDay
  has_api_key: boolean
  has_vt_key: boolean
  has_abuseipdb_key: boolean
}

export interface SeriesPoint {
  ts: number
  total: number
  blocked: number
  forwarded: number
  cached: number
  avg_latency_ms: number
}

export interface NodeQueries {
  node: string
  total: number
  blocked: number
}

export interface LatencyPoint {
  ts: number
  overall: number
  by_node: Record<string, number>
}

export interface CategoryCount {
  category: string
  count: number
}

export interface ClientStat {
  client: string
  total: number
  blocked: number
}

export interface DomainStat {
  name: string
  count: number
}

export interface ClientRow {
  client: string
  total: number
  blocked: number
  last_seen: number
}

export interface ClientDetail {
  totals: WindowTotals
  unique_domains: number
  last_seen: number
  avg_latency_ms: number
  actions: CategoryCount[]
  categories: CategoryCount[]
  top_domains: DomainStat[]
  top_blocked: DomainStat[]
}

export interface TypeStat {
  qtype: string
  count: number
}

export interface WindowTotals {
  total: number
  blocked: number
  cached: number
  forwarded: number
  rewritten: number
  errors: number
}

export interface Insights {
  unique_clients: number
  avg_latency_ms: number
  clients: ClientStat[]
  top_queried: DomainStat[]
  top_blocked: DomainStat[]
  qtypes: TypeStat[]
  by_node: NodeQueries[]
  totals: WindowTotals
}

export interface ForwardGroup {
  suffix: string
  upstreams: string[]
}

export interface CacheSettings {
  enabled: boolean
  max_entries: number
  min_ttl_sec: number
  max_ttl_sec: number
}

export interface User {
  id: number
  username: string
  role: string
  source: string
  updated_at: number
}

export interface List {
  id: number
  name: string
  source: string // "file" | "paste" | "url"
  url: string
  category: string
  enabled: boolean
  interval_sec: number
  last_fetch: number
  last_error: string
  rule_count: number
  updated_at: number
}

export interface Protection {
  paused: boolean
  paused_until: number
  seconds_left: number
}

export interface Settings {
  upstreams: string[]
  forwarders: ForwardGroup[]
  block_response: string
  rate_limit_qpm: number
  dnssec: boolean
  cache: CacheSettings
}

async function j<T>(r: Response): Promise<T> {
  if (!r.ok) {
    const body = await r.json().catch(() => ({}))
    throw new Error(body.error || r.statusText)
  }
  return r.json() as Promise<T>
}

// ok handles empty-body (204) responses, throwing the API error message on failure.
async function ok(r: Response): Promise<void> {
  if (!r.ok) {
    const body = await r.json().catch(() => ({}))
    throw new Error(body.error || r.statusText)
  }
}

const jsonHeaders = { 'Content-Type': 'application/json' }

const nodesParam = (nodes?: string[]) =>
  nodes && nodes.length ? `&nodes=${nodes.map(encodeURIComponent).join(',')}` : ''

export const api = {
  // auth
  authInfo: () => fetch('/api/auth/info').then(j<AuthInfo>),
  me: async (): Promise<SessionUser | null> => {
    const r = await fetch('/api/auth/me')
    if (r.status === 401) return null
    return j<SessionUser>(r)
  },
  login: (username: string, password: string) =>
    fetch('/api/auth/login', { method: 'POST', headers: jsonHeaders, body: JSON.stringify({ username, password }) }).then(j<SessionUser>),
  logout: () => fetch('/api/auth/logout', { method: 'POST' }),
  changePassword: (current_password: string, new_password: string) =>
    fetch('/api/auth/password', {
      method: 'POST',
      headers: jsonHeaders,
      body: JSON.stringify({ current_password, new_password }),
    }).then(ok),

  // user management (admin)
  users: () => fetch('/api/users').then(j<User[]>),
  createUser: (username: string, password: string, role: string) =>
    fetch('/api/users', { method: 'POST', headers: jsonHeaders, body: JSON.stringify({ username, password, role }) }).then(
      j<User>,
    ),
  setUserRole: (id: number, role: string) =>
    fetch(`/api/users/${id}/role`, { method: 'PUT', headers: jsonHeaders, body: JSON.stringify({ role }) }).then(ok),
  resetUserPassword: (id: number, password: string) =>
    fetch(`/api/users/${id}/password`, { method: 'PUT', headers: jsonHeaders, body: JSON.stringify({ password }) }).then(ok),
  deleteUser: (id: number) => fetch(`/api/users/${id}`, { method: 'DELETE' }).then(ok),

  // data
  stats: () => fetch('/api/stats').then(j<Stats>),
  timeseries: (hours = 24, nodes?: string[]) =>
    fetch(`/api/stats/timeseries?hours=${hours}${nodesParam(nodes)}`).then(j<{ step: number; points: SeriesPoint[] }>),
  categories: (hours = 24, nodes?: string[]) =>
    fetch(`/api/stats/categories?hours=${hours}${nodesParam(nodes)}`).then(j<CategoryCount[]>),
  categoryTraffic: (hours = 24, nodes?: string[]) =>
    fetch(`/api/stats/category-traffic?hours=${hours}${nodesParam(nodes)}`).then(j<CategoryCount[]>),
  insights: (hours = 24, nodes?: string[]) =>
    fetch(`/api/stats/insights?hours=${hours}${nodesParam(nodes)}`).then(j<Insights>),
  clientList: (hours = 24, nodes?: string[], limit = 200) =>
    fetch(`/api/clients?hours=${hours}&limit=${limit}${nodesParam(nodes)}`).then(j<{ clients: ClientRow[] }>),
  clientDetail: (client: string, hours = 24, nodes?: string[]) =>
    fetch(`/api/clients/detail?client=${encodeURIComponent(client)}&hours=${hours}${nodesParam(nodes)}`).then(
      j<ClientDetail>,
    ),
  setClientName: (client: string, name: string) =>
    fetch('/api/clients/name', { method: 'PUT', headers: jsonHeaders, body: JSON.stringify({ client, name }) }).then(j),
  latency: (hours = 24, nodes?: string[]) =>
    fetch(`/api/stats/latency?hours=${hours}${nodesParam(nodes)}`).then(
      j<{ step: number; nodes: string[]; points: LatencyPoint[] }>,
    ),
  queryLog: (
    opts: {
      limit?: number
      offset?: number
      search?: string
      nodes?: string[]
      action?: string
      qtype?: string
      category?: string
      sort?: string
      desc?: boolean
      hours?: number
    } = {},
  ) => {
    const p = new URLSearchParams({ limit: String(opts.limit ?? 50), offset: String(opts.offset ?? 0) })
    if (opts.hours) p.set('hours', String(opts.hours))
    if (opts.search) p.set('search', opts.search)
    if (opts.action) p.set('action', opts.action)
    if (opts.qtype) p.set('qtype', opts.qtype)
    if (opts.category) p.set('category', opts.category)
    if (opts.sort) p.set('sort', opts.sort)
    if (opts.desc) p.set('desc', 'true')
    if (opts.nodes && opts.nodes.length) p.set('nodes', opts.nodes.join(','))
    return fetch(`/api/querylog?${p.toString()}`).then(j<{ entries: QueryLogEntry[]; total: number }>)
  },

  rules: () => fetch('/api/rules').then(j<Rule[]>),
  addRule: (action: string, domain: string, category: string) =>
    fetch('/api/rules', { method: 'POST', headers: jsonHeaders, body: JSON.stringify({ action, domain, category }) }).then(j),
  importRules: (text: string, category: string) =>
    fetch('/api/rules/import', { method: 'POST', headers: jsonHeaders, body: JSON.stringify({ text, category }) }).then(j<{ imported: number }>),
  deleteRule: (id: number) => fetch(`/api/rules/${id}`, { method: 'DELETE' }),

  settings: () => fetch('/api/settings').then(j<Settings>),
  saveSettings: (s: Settings) =>
    fetch('/api/settings', { method: 'PUT', headers: jsonHeaders, body: JSON.stringify(s) }).then(j<Settings>),

  exportConfig: async (): Promise<Blob> => {
    const r = await fetch('/api/config/export')
    if (!r.ok) {
      const body = await r.json().catch(() => ({}))
      throw new Error(body.error || r.statusText)
    }
    return r.blob()
  },
  importConfig: (bundle: unknown, mode: 'merge' | 'replace') =>
    fetch(`/api/config/import?mode=${mode}`, { method: 'POST', headers: jsonHeaders, body: JSON.stringify(bundle) }).then(
      j<{ mode: string; rules: number; rewrites: number; settings: boolean }>,
    ),

  // managed lists
  lists: () => fetch('/api/lists').then(j<List[]>),
  listRules: (id: number) => fetch(`/api/lists/${id}/rules`).then(j<Rule[]>),
  importList: (name: string, category: string, text: string, source: 'file' | 'paste') =>
    fetch('/api/lists/import', {
      method: 'POST',
      headers: jsonHeaders,
      body: JSON.stringify({ name, category, text, source }),
    }).then(j<{ id: number; name: string; imported: number }>),
  addUrlList: (name: string, url: string, category: string, interval_minutes: number) =>
    fetch('/api/lists/url', {
      method: 'POST',
      headers: jsonHeaders,
      body: JSON.stringify({ name, url, category, interval_minutes }),
    }).then(j<List>),
  refreshList: (id: number) => fetch(`/api/lists/${id}/refresh`, { method: 'POST' }).then(j<List>),
  updateList: (id: number, patch: { enabled?: boolean; interval_minutes?: number }) =>
    fetch(`/api/lists/${id}`, { method: 'PUT', headers: jsonHeaders, body: JSON.stringify(patch) }).then(j<List>),
  deleteList: (id: number) => fetch(`/api/lists/${id}`, { method: 'DELETE' }).then(ok),

  // protection (global block pause)
  protection: () => fetch('/api/protection').then(j<Protection>),
  disableProtection: (seconds: number) =>
    fetch('/api/protection/disable', { method: 'POST', headers: jsonHeaders, body: JSON.stringify({ seconds }) }).then(
      j<Protection>,
    ),
  enableProtection: () => fetch('/api/protection/enable', { method: 'POST' }).then(j<Protection>),

  rewrites: () => fetch('/api/rewrites').then(j<Rewrite[]>),
  addRewrite: (domain: string, rrtype: string, value: string) =>
    fetch('/api/rewrites', { method: 'POST', headers: jsonHeaders, body: JSON.stringify({ domain, rrtype, value }) }).then(j),
  deleteRewrite: (id: number) => fetch(`/api/rewrites/${id}`, { method: 'DELETE' }),

  // LLM classifier
  classifier: () => fetch('/api/classifier').then(j<ClassifierStatus>),
  saveClassifierSettings: (s: ClassifierSettings) =>
    fetch('/api/classifier/settings', { method: 'PUT', headers: jsonHeaders, body: JSON.stringify(s) }).then(j<ClassifierSettings>),
  testClassifier: (s: ClassifierSettings) =>
    fetch('/api/classifier/test', { method: 'POST', headers: jsonHeaders, body: JSON.stringify(s) }).then(
      j<{ ok: boolean; error?: string; domain?: string; category?: string; confidence?: number; reason?: string }>,
    ),
  setClassifierMode: (mode: string) =>
    fetch('/api/classifier/mode', { method: 'PUT', headers: jsonHeaders, body: JSON.stringify({ mode }) }).then(j),
  classifierList: (list: 'trusted' | 'threat', search = '', limit = 200) => {
    const p = new URLSearchParams({ list, limit: String(limit) })
    if (search) p.set('search', search)
    return fetch(`/api/classifier/list?${p.toString()}`).then(j<{ count: number; domains: string[] }>)
  },
  classifications: (status = '', limit = 25, offset = 0, search = '') => {
    const p = new URLSearchParams({ limit: String(limit), offset: String(offset) })
    if (status) p.set('status', status)
    if (search) p.set('search', search)
    return fetch(`/api/classifications?${p.toString()}`).then(j<Classification[]>)
  },
  decideClassification: (
    domain: string,
    decision: 'approve' | 'reject' | 'dismiss',
    category = '',
    note = '',
  ) =>
    fetch('/api/classifications/decision', {
      method: 'POST',
      headers: jsonHeaders,
      body: JSON.stringify({ domain, decision, category, note }),
    }).then(j),
  clearClassifications: () => fetch('/api/classifications', { method: 'DELETE' }).then(j<{ deleted: number }>),
  whois: (domain: string) =>
    fetch(`/api/classifier/whois?domain=${encodeURIComponent(domain)}`).then(
      j<{ ok: boolean; error?: string; domain?: string; whois?: WhoisInfo }>,
    ),
  domainClients: (domain: string) =>
    fetch(`/api/classifier/clients?domain=${encodeURIComponent(domain)}`).then(
      j<{ domain: string; clients: DomainClient[] }>,
    ),

  // Resolve client IPs to identities (NetBird peer / reverse-DNS), batched.
  resolveClients: (ips: string[]) =>
    fetch(`/api/clients/resolve?ips=${encodeURIComponent(ips.join(','))}`).then(j<Record<string, ClientIdentity>>),

  // NetBird client-identity integration
  netbird: () =>
    fetch('/api/netbird').then(j<{ settings: NetbirdSettings; has_token: boolean; peer_count: number }>),
  saveNetbird: (s: NetbirdSettings) =>
    fetch('/api/netbird', { method: 'PUT', headers: jsonHeaders, body: JSON.stringify(s) }).then(j<NetbirdSettings>),
  testNetbird: (s: NetbirdSettings) =>
    fetch('/api/netbird/test', { method: 'POST', headers: jsonHeaders, body: JSON.stringify(s) }).then(
      j<{ ok: boolean; error?: string; peer_count?: number }>,
    ),

  // Per-node internal DNS resolvers (reverse-DNS for internal clients)
  reverseDns: () =>
    fetch('/api/reverse-dns').then(j<{ resolvers: Record<string, string>; nodes: string[] }>),
  saveReverseDns: (resolvers: Record<string, string>) =>
    fetch('/api/reverse-dns', { method: 'PUT', headers: jsonHeaders, body: JSON.stringify({ resolvers }) }).then(
      j<{ resolvers: Record<string, string> }>,
    ),

  // cluster
  clusterNodes: () => fetch('/api/cluster/nodes').then(j<Node[]>),
  addNode: (name: string) =>
    fetch('/api/cluster/nodes', { method: 'POST', headers: jsonHeaders, body: JSON.stringify({ name }) }).then(j<{ name: string; key: string }>),
  renewNodeKey: (name: string) =>
    fetch(`/api/cluster/nodes/${encodeURIComponent(name)}/key`, { method: 'POST' }).then(j<{ name: string; key: string }>),
  deleteNode: (name: string) => fetch(`/api/cluster/nodes/${encodeURIComponent(name)}`, { method: 'DELETE' }),
}
