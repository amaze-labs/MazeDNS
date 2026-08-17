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
import { api, type SessionUser, type AuthInfo } from './api'

type Tab = 'dashboard' | 'queries' | 'clients' | 'filtering' | 'rewrites' | 'cluster' | 'logs' | 'settings' | 'account'
const ALL_TABS: Tab[] = ['dashboard', 'queries', 'clients', 'filtering', 'rewrites', 'cluster', 'logs', 'settings', 'account']

// Sidebar presentation: icon + human label per tab.
const TAB_META: Record<Tab, { icon: IconName; label: string }> = {
  dashboard: { icon: 'dashboard', label: 'Dashboard' },
  queries: { icon: 'queries', label: 'Requests' },
  clients: { icon: 'clients', label: 'Clients' },
  filtering: { icon: 'filtering', label: 'Filtering' },
  rewrites: { icon: 'rewrites', label: 'Rewrites' },
  cluster: { icon: 'cluster', label: 'Cluster' },
  logs: { icon: 'logs', label: 'Logs' },
  settings: { icon: 'settings', label: 'Settings' },
  account: { icon: 'account', label: 'Account' },
}

// The current tab is reflected in the URL path (/dashboard, /queries, …) so
// pages are linkable and the browser back/forward buttons work.
const tabFromPath = (): Tab => {
  const seg = window.location.pathname.replace(/^\/+|\/+$/g, '')
  // AI classification moved under Filtering; keep old /ai links working.
  if (seg === 'ai') return 'filtering'
  return ALL_TABS.includes(seg as Tab) ? (seg as Tab) : 'dashboard'
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
    if (tabFromPath() !== t) window.history.pushState({}, '', `/${t}`)
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
    // Normalize the URL on first load (e.g. "/" -> "/dashboard").
    if (window.location.pathname !== `/${tabFromPath()}`) {
      window.history.replaceState({}, '', `/${tabFromPath()}`)
    }
    const onPop = () => setTab(tabFromPath())
    window.addEventListener('popstate', onPop)
    return () => window.removeEventListener('popstate', onPop)
  }, [])

  const logout = async () => {
    // Prevent auto-login from immediately bouncing back into SSO on the next render.
    sessionStorage.setItem(SKIP_AUTOLOGIN_KEY, '1')
    await api.logout()
    setUser(null)
  }

  if (loading) {
    return (
      <div className="app">
        <Spinner size={22} label="Loading…" />
      </div>
    )
  }

  if (info?.setup_required) {
    return <Setup onDone={() => refresh()} />
  }

  if (info?.auth_enabled && !user) {
    return (
      <Login
        oidc={!!info.oidc_enabled}
        passwordDisabled={!!info.password_login_disabled}
        autoLogin={!!info.oidc_auto_login}
        onLogin={() => refresh()}
      />
    )
  }

  // 'account' is reached from the avatar menu, not the nav.
  const classifierOn = !!(info?.classifier_available && info?.classifier_enabled)
  const tabs: Tab[] = ['dashboard', 'queries', 'clients', 'filtering', 'rewrites']
  if (info?.cluster_enabled) tabs.push('cluster')
  // Process logs are admin-only server-side (they can carry client IPs and
  // usernames), so don't offer the tab to readonly users at all.
  if (user?.role === 'admin') tabs.push('logs')
  tabs.push('settings')

  return (
    <div className={`app ${collapsed ? 'collapsed' : ''}`}>
      <aside className="sidebar">
        <div className="side-brand">
          <span className="brand-logo">
            <Icon name="brand" size={22} />
          </span>
          <span className="brand-name">MazeDNS</span>
        </div>
        <nav className="side-nav">
          {tabs.map((t) => (
            <button
              key={t}
              className={tab === t ? 'active' : ''}
              onClick={() => navigate(t)}
              title={TAB_META[t].label}
            >
              <span className="side-ic">
                <Icon name={TAB_META[t].icon} />
              </span>
              <span className="side-label">{TAB_META[t].label}</span>
            </button>
          ))}
        </nav>
        <div className="spacer" />
        <button
          className="side-collapse"
          onClick={toggle}
          title={theme === 'dark' ? 'Switch to light theme' : 'Switch to dark theme'}
        >
          <span className="side-ic">
            <Icon name={theme === 'dark' ? 'sun' : 'moon'} />
          </span>
          <span className="side-label">{theme === 'dark' ? 'Light theme' : 'Dark theme'}</span>
        </button>
        <button
          className="side-collapse"
          onClick={toggleSidebar}
          title={collapsed ? 'Expand sidebar' : 'Collapse sidebar'}
        >
          <span className="side-ic">
            <Icon name={collapsed ? 'chevrons-right' : 'chevrons-left'} />
          </span>
          <span className="side-label">Collapse</span>
        </button>
        {user && (
          <div className="side-account">
            <AccountMenu
              user={user}
              authEnabled={!!info?.auth_enabled}
              onSettings={() => navigate('account')}
              onLogout={logout}
            />
            <span className="side-label side-username">{user.username}</span>
          </div>
        )}
      </aside>
      <main>
        {tab === 'dashboard' && <Dashboard />}
        {tab === 'queries' && <Queries />}
        {tab === 'clients' && <Clients />}
        {tab === 'filtering' && <Filtering classifier={classifierOn} />}
        {tab === 'rewrites' && <Rewrites />}
        {tab === 'cluster' && info?.cluster_enabled && <Cluster />}
        {tab === 'logs' && user?.role === 'admin' && <Logs />}
        {tab === 'settings' && <Settings onClassifierChange={() => refresh()} />}
        {tab === 'account' && info?.auth_enabled && <Account me={user} oidc={!!info.oidc_enabled} />}
      </main>
    </div>
  )
}
