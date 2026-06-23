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
}

export interface AuthInfo {
  auth_enabled: boolean
  oidc_enabled: boolean
  cluster_enabled: boolean
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

export interface TypeStat {
  qtype: string
  count: number
}

export interface Insights {
  unique_clients: number
  avg_latency_ms: number
  clients: ClientStat[]
  top_queried: DomainStat[]
  top_blocked: DomainStat[]
  qtypes: TypeStat[]
  by_node: NodeQueries[]
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
  insights: (hours = 24, nodes?: string[]) =>
    fetch(`/api/stats/insights?hours=${hours}${nodesParam(nodes)}`).then(j<Insights>),
  queryLog: (opts: { limit?: number; offset?: number; search?: string; nodes?: string[] } = {}) => {
    const p = new URLSearchParams({ limit: String(opts.limit ?? 50), offset: String(opts.offset ?? 0) })
    if (opts.search) p.set('search', opts.search)
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

  // cluster
  clusterNodes: () => fetch('/api/cluster/nodes').then(j<Node[]>),
  addNode: (name: string) =>
    fetch('/api/cluster/nodes', { method: 'POST', headers: jsonHeaders, body: JSON.stringify({ name }) }).then(j<{ name: string; key: string }>),
  deleteNode: (name: string) => fetch(`/api/cluster/nodes/${encodeURIComponent(name)}`, { method: 'DELETE' }),
}
