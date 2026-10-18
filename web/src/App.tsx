import { useEffect, useState } from 'react'
import Dashboard from './components/Dashboard'
import Queries from './components/Queries'
import Clients from './components/Clients'
import Filtering from './components/Filtering'
import LocalDNS from './components/LocalDNS'
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

type Tab = 'overview' | 'queries' | 'clients' | 'filtering' | 'local-dns' | 'agents' | 'logs' | 'settings' | 'account'
const ALL_TABS: Tab[] = ['overview', 'queries', 'clients', 'filtering', 'local-dns', 'agents', 'logs', 'settings', 'account']

// Navigation presentation: icon + human label per tab. On phones the bottom
// bar holds the everyday tabs; the rest (`more`) open from its "More" sheet.
const TAB_META: Record<Tab, { icon: IconName; label: string; more?: boolean }> = {
  overview: { icon: 'dashboard', label: 'Overview' },
  queries: { icon: 'queries', label: 'Queries' },
  clients: { icon: 'clients', label: 'Clients' },
  filtering: { icon: 'filtering', label: 'Filtering' },
  'local-dns': { icon: 'local-dns', label: 'Local DNS', more: true },
  agents: { icon: 'cluster', label: 'Agents', more: true },
  logs: { icon: 'logs', label: 'Logs', more: true },
  settings: { icon: 'settings', label: 'Settings', more: true },
  account: { icon: 'account', label: 'Account' },
}

// Paths from before the redesign and page renames keep working.
const ALIASES: Record<string, Tab> = {
  '': 'overview',
  dashboard: 'overview',
  cluster: 'agents',
  requests: 'queries',
  ai: 'filtering',
  rewrites: 'local-dns',
}

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
  const [moreOpen, setMoreOpen] = useState(false)
  const { theme, toggle } = useTheme()

  // navigate switches tab and pushes the matching path into history.
  const navigate = (t: Tab) => {
    setTab(t)
    setMoreOpen(false)
    if (window.location.pathname !== `/${t}`) window.history.pushState({}, '', `/${t}`)
    window.scrollTo({ top: 0 })
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

  // The running build, shown next to the name in the top bar.
  const [appVersion, setAppVersion] = useState('')
  useEffect(() => {
    if (!user) return
    api
      .serverVersion()
      .then((v) => setAppVersion(v.version))
      .catch(() => {})
  }, [user])

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
  const tabs: Tab[] = ['overview', 'queries', 'clients', 'filtering', 'local-dns']
  if (clusterOn) tabs.push('agents')
  // Process logs are admin-only server-side (they can carry client IPs and
  // usernames), so don't offer the tab to readonly users at all.
  if (isAdmin) tabs.push('logs')
  tabs.push('settings')
  const counts: Partial<Record<Tab, number>> = { agents: badges.agents, filtering: badges.filtering }

  // A tab the user can't open (role, cluster off, auth off) falls back to Overview.
  const allowed = tabs.includes(tab) || (tab === 'account' && info.auth_enabled)
  const shown: Tab = allowed ? tab : 'overview'

  const phoneTabs = tabs.filter((t) => !TAB_META[t].more)
  const moreTabs = tabs.filter((t) => TAB_META[t].more)
  const moreCount = moreTabs.reduce((n, t) => n + (counts[t] ?? 0), 0)
  const themeLabel = theme === 'dark' ? 'Switch to light theme' : 'Switch to dark theme'

  return (
    <div className="app">
      <header className="topbar">
        <a
          className="tb-brand"
          href="/overview"
          onClick={(e) => {
            e.preventDefault()
            navigate('overview')
          }}
        >
          <img className="brand-logo" src="/favicon.svg" alt="" width={32} height={32} />
          <span className="brand-name">MazeDNS</span>
          {appVersion && <span className="brand-version">{appVersion}</span>}
        </a>
        <nav className="tb-nav" aria-label="Main">
          {tabs.map((t) => (
            <button
              key={t}
              className={shown === t ? 'active' : ''}
              aria-current={shown === t ? 'page' : undefined}
              onClick={() => navigate(t)}
            >
              {TAB_META[t].label}
              {!!counts[t] && (
                <span className="tb-count" title="Needs attention">
                  {counts[t]}
                </span>
              )}
            </button>
          ))}
        </nav>
        <div className="tb-tools">
          <div className="tb-theme" role="group" aria-label="Theme">
            <button className={theme === 'light' ? 'on' : ''} onClick={() => theme !== 'light' && toggle()} title="Light theme" aria-pressed={theme === 'light'}>
              <Icon name="sun" size={16} />
            </button>
            <button className={theme === 'dark' ? 'on' : ''} onClick={() => theme !== 'dark' && toggle()} title="Dark theme" aria-pressed={theme === 'dark'}>
              <Icon name="moon" size={16} />
            </button>
          </div>
          {user && (
            <div className="tb-account">
              <AccountMenu user={user} authEnabled={!!info.auth_enabled} onSettings={() => navigate('account')} onLogout={logout} />
              <span className="tb-user">
                <b>{user.username}</b>
                <small>{isAdmin ? 'Administrator' : 'Viewer'}</small>
              </span>
            </div>
          )}
        </div>
      </header>

      {/* Phones: the everyday tabs, plus a sheet with the rest. */}
      <nav className="tabbar" aria-label="Main">
        {phoneTabs.map((t) => (
          <button
            key={t}
            className={`${shown === t ? 'active' : ''} ${counts[t] ? 'has-count' : ''}`}
            aria-current={shown === t ? 'page' : undefined}
            onClick={() => navigate(t)}
          >
            <Icon name={TAB_META[t].icon} size={20} />
            <span>{TAB_META[t].label}</span>
          </button>
        ))}
        {moreTabs.length > 0 && (
          <button
            className={`${moreTabs.includes(shown) ? 'active' : ''} ${moreCount ? 'has-count' : ''}`}
            aria-expanded={moreOpen}
            onClick={() => setMoreOpen((o) => !o)}
          >
            <Icon name="more" size={20} />
            <span>More</span>
          </button>
        )}
      </nav>
      {moreOpen && (
        <>
          <div className="tabbar-scrim" onClick={() => setMoreOpen(false)} />
          <div className="tabbar-sheet" role="menu">
            {moreTabs.map((t) => (
              <button key={t} role="menuitem" className={shown === t ? 'active' : ''} onClick={() => navigate(t)}>
                <Icon name={TAB_META[t].icon} size={18} />
                <span>{TAB_META[t].label}</span>
                {!!counts[t] && <span className="tb-count">{counts[t]}</span>}
              </button>
            ))}
            <button role="menuitem" onClick={toggle}>
              <Icon name={theme === 'dark' ? 'sun' : 'moon'} size={18} />
              <span>{themeLabel}</span>
            </button>
          </div>
        </>
      )}
      <main>
        {shown === 'overview' && <Dashboard />}
        {shown === 'queries' && <Queries />}
        {shown === 'clients' && <Clients />}
        {shown === 'filtering' && <Filtering classifier={classifierOn} />}
        {shown === 'local-dns' && <LocalDNS />}
        {shown === 'agents' && <Cluster />}
        {shown === 'logs' && <Logs />}
        {shown === 'settings' && <Settings onClassifierChange={() => refresh()} />}
        {shown === 'account' && <Account me={user} oidc={!!info.oidc_enabled} />}
      </main>
    </div>
  )
}
