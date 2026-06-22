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
}

export interface Rule {
  id: number
  action: string
  domain: string
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

export interface SessionUser {
  id: number
  username: string
  role: string
}

export interface AuthInfo {
  auth_enabled: boolean
  oidc_enabled: boolean
}

async function j<T>(r: Response): Promise<T> {
  if (!r.ok) {
    const body = await r.json().catch(() => ({}))
    throw new Error(body.error || r.statusText)
  }
  return r.json() as Promise<T>
}

const jsonHeaders = { 'Content-Type': 'application/json' }

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

  // data
  stats: () => fetch('/api/stats').then(j<Stats>),
  queryLog: (limit = 100) => fetch(`/api/querylog?limit=${limit}`).then(j<QueryLogEntry[]>),

  rules: () => fetch('/api/rules').then(j<Rule[]>),
  addRule: (action: string, domain: string) =>
    fetch('/api/rules', { method: 'POST', headers: jsonHeaders, body: JSON.stringify({ action, domain }) }).then(j),
  deleteRule: (id: number) => fetch(`/api/rules/${id}`, { method: 'DELETE' }),

  rewrites: () => fetch('/api/rewrites').then(j<Rewrite[]>),
  addRewrite: (domain: string, rrtype: string, value: string) =>
    fetch('/api/rewrites', { method: 'POST', headers: jsonHeaders, body: JSON.stringify({ domain, rrtype, value }) }).then(j),
  deleteRewrite: (id: number) => fetch(`/api/rewrites/${id}`, { method: 'DELETE' }),
}
