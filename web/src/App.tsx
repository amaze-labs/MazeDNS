import { useEffect, useState } from 'react'
import Dashboard from './components/Dashboard'
import Queries from './components/Queries'
import Clients from './components/Clients'
import Filtering from './components/Filtering'
import Rewrites from './components/Rewrites'
import Cluster from './components/Cluster'
import Logs from './components/Logs'
import Settings from './components/Settings'
import Account from './components/Account'
import AccountMenu from './components/AccountMenu'
import Login, { SKIP_AUTOLOGIN_KEY } from './components/Login'
import Setup from './components/Setup'
import Spinner from './components/Spinner'
import { Icon, type IconName } from './components/icons'
import { useTheme } from './theme'
import { useNavBadges } from './useNavBadges'
import { api, UNAUTHORIZED, type SessionUser, type AuthInfo } from './api'

type Tab = 'overview' | 'queries' | 'clients' | 'filtering' | 'rewrites' | 'agents' | 'logs' | 'settings' | 'account'
const ALL_TABS: Tab[] = ['overview', 'queries', 'clients', 'filtering', 'rewrites', 'agents', 'logs', 'settings', 'account']

// Sidebar presentation: icon + human label per tab. `extra` tabs drop out of the
// mobile bottom bar, which only has room for the everyday ones.
const TAB_META: Record<Tab, { icon: IconName; label: string; extra?: boolean }> = {
  overview: { icon: 'dashboard', label: 'Overview' },
  queries: { icon: 'queries', label: 'Queries' },
  clients: { icon: 'clients', label: 'Clients' },
  filtering: { icon: 'filtering', label: 'Filtering' },
  rewrites: { icon: 'rewrites', label: 'Rewrites', extra: true },
  agents: { icon: 'cluster', label: 'Agents' },
  logs: { icon: 'logs', label: 'Logs', extra: true },
  settings: { icon: 'settings', label: 'Settings' },
  account: { icon: 'account', label: 'Account' },
}

// Paths from before the redesign keep working.
const ALIASES: Record<string, Tab> = { '': 'overview', dashboard: 'overview', cluster: 'agents', requests: 'queries', ai: 'filtering' }

// The current tab is reflected in the URL path (/overview, /queries, …) so
// pages are linkable and the browser back/forward buttons work.
const tabFromPath = (): Tab => {
  const seg = window.location.pathname.replace(/^\/+|\/+$/g, '')
  if (seg in ALIASES) return ALIASES[seg]
  return ALL_TABS.includes(seg as Tab) ? (seg as Tab) : 'overview'
}

export default function App() {
  const [tab, setTab] = useState<Tab>(tabFromPath)
  const [user, setUser] = useState<SessionUser | null>(null)
  const [info, setInfo] = useState<AuthInfo | null>(null)
  const [loading, setLoading] = useState(true)
  const [collapsed, setCollapsed] = useState(() => localStorage.getItem('mazedns.sidebar.collapsed') === '1')
  const { theme, toggle } = useTheme()

  const toggleSidebar = () => {
    setCollapsed((c) => {
      localStorage.setItem('mazedns.sidebar.collapsed', c ? '0' : '1')
      return !c
    })
  }

  // navigate switches tab and pushes the matching path into history.
  const navigate = (t: Tab) => {
    setTab(t)
    if (window.location.pathname !== `/${t}`) window.history.pushState({}, '', `/${t}`)
  }

  const refresh = async () => {
    const inf = await api.authInfo()
    setInfo(inf)
    // In first-boot setup mode no admin exists yet — don't call the (gated) me().
    if (inf.setup_required) {
      setUser(null)
      setLoading(false)
      return
    }
    setUser(inf.auth_enabled ? await api.me() : { id: 0, username: 'anonymous', role: 'admin' })
    setLoading(false)
  }

  useEffect(() => {
    refresh().catch(() => setLoading(false))
    // Normalize the URL on first load (e.g. "/" or "/dashboard" -> "/overview").
    if (window.location.pathname !== `/${tabFromPath()}`) {
      window.history.replaceState({}, '', `/${tabFromPath()}${window.location.search}`)
    }
    const onPop = () => setTab(tabFromPath())
    // A 401 from any call means the session expired: show the login screen.
    const onUnauthorized = () => setUser(null)
    window.addEventListener('popstate', onPop)
    window.addEventListener(UNAUTHORIZED, onUnauthorized)
    return () => {
      window.removeEventListener('popstate', onPop)
      window.removeEventListener(UNAUTHORIZED, onUnauthorized)
    }
  }, [])

  const isAdmin = user?.role === 'admin'
  const clusterOn = !!info?.cluster_enabled
  const badges = useNavBadges({ agents: !!user && clusterOn, filtering: !!user })

  const logout = async () => {
    // Prevent auto-login from immediately bouncing back into SSO on the next render.
    sessionStorage.setItem(SKIP_AUTOLOGIN_KEY, '1')
    await api.logout()
    setUser(null)
  }

  if (loading) {
    return (
      <div className="app">
        <div className="boot">
          <Spinner size={22} label="Loading…" />
        </div>
      </div>
    )
  }

  if (info?.setup_required) {
    return <Setup onDone={() => refresh()} />
  }

  // A failed /api/auth/info leaves info null: never render the app unauthenticated.
  if (!info || (info.auth_enabled && !user)) {
    return (
      <Login
        oidc={!!info?.oidc_enabled}
        passwordDisabled={!!info?.password_login_disabled}
        autoLogin={!!info?.oidc_auto_login}
        onLogin={() => refresh()}
      />
    )
  }

  // 'account' is reached from the avatar, not the nav.
  const classifierOn = !!(info.classifier_available && info.classifier_enabled)
  const tabs: Tab[] = ['overview', 'queries', 'clients', 'filtering', 'rewrites']
  if (clusterOn) tabs.push('agents')
  // Process logs are admin-only server-side (they can carry client IPs and
  // usernames), so don't offer the tab to readonly users at all.
  if (isAdmin) tabs.push('logs')
  tabs.push('settings')
  const counts: Partial<Record<Tab, number>> = { agents: badges.agents, filtering: badges.filtering }

  // A tab the user can't open (role, cluster off, auth off) falls back to Overview.
  const allowed = tabs.includes(tab) || (tab === 'account' && info.auth_enabled)
  const shown: Tab = allowed ? tab : 'overview'

  return (
    <div className={`app ${collapsed ? 'collapsed' : ''}`}>
      <aside className="sidebar">
        <div className="side-brand">
          <span className="brand-logo">
            <img src="/favicon.svg" alt="" width={22} height={22} />
          </span>
          <span className="brand-name">MazeDNS</span>
        </div>
        <nav className="side-nav" aria-label="Main">
          {tabs.map((t) => (
            <button
              key={t}
              className={`${shown === t ? 'active' : ''} ${TAB_META[t].extra ? 'extra' : ''} ${counts[t] ? 'has-count' : ''}`}
              aria-current={shown === t ? 'page' : undefined}
              onClick={() => navigate(t)}
              title={TAB_META[t].label}
            >
              <span className="side-ic">
                <Icon name={TAB_META[t].icon} />
              </span>
              <span className="side-label">{TAB_META[t].label}</span>
              {!!counts[t] && (
                <span className="side-count" title="Needs attention">
                  {counts[t]}
                </span>
              )}
            </button>
          ))}
        </nav>
        <div className="spacer" />
        <div className="side-foot">
          <button onClick={toggle} title={theme === 'dark' ? 'Switch to light theme' : 'Switch to dark theme'}>
            <span className="side-ic">
              <Icon name={theme === 'dark' ? 'sun' : 'moon'} />
            </span>
            <span className="side-label">{theme === 'dark' ? 'Light theme' : 'Dark theme'}</span>
          </button>
          <button onClick={toggleSidebar} title={collapsed ? 'Expand sidebar' : 'Collapse sidebar'}>
            <span className="side-ic">
              <Icon name={collapsed ? 'chevrons-right' : 'chevrons-left'} />
            </span>
            <span className="side-label">Collapse</span>
          </button>
        </div>
        {user && (
          <div className="side-account">
            <AccountMenu user={user} authEnabled={!!info.auth_enabled} onSettings={() => navigate('account')} onLogout={logout} />
            <span className="side-username">
              <b>{user.username}</b>
              <small>{isAdmin ? 'Administrator' : 'Viewer'}</small>
            </span>
          </div>
        )}
      </aside>
      <main>
        {shown === 'overview' && <Dashboard />}
        {shown === 'queries' && <Queries />}
        {shown === 'clients' && <Clients />}
        {shown === 'filtering' && <Filtering classifier={classifierOn} />}
        {shown === 'rewrites' && <Rewrites />}
        {shown === 'agents' && <Cluster />}
        {shown === 'logs' && <Logs />}
        {shown === 'settings' && <Settings onClassifierChange={() => refresh()} />}
        {shown === 'account' && <Account me={user} oidc={!!info.oidc_enabled} />}
      </main>
    </div>
  )
}
