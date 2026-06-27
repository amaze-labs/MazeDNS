import { useEffect, useState } from 'react'
import Dashboard from './components/Dashboard'
import Queries from './components/Queries'
import Filtering from './components/Filtering'
import Classifier from './components/Classifier'
import Rewrites from './components/Rewrites'
import Cluster from './components/Cluster'
import Settings from './components/Settings'
import Account from './components/Account'
import AccountMenu from './components/AccountMenu'
import Login from './components/Login'
import Spinner from './components/Spinner'
import { api, type SessionUser, type AuthInfo } from './api'

type Tab = 'dashboard' | 'queries' | 'filtering' | 'ai' | 'rewrites' | 'cluster' | 'settings' | 'account'
const ALL_TABS: Tab[] = ['dashboard', 'queries', 'filtering', 'ai', 'rewrites', 'cluster', 'settings', 'account']

// The current tab is reflected in the URL path (/dashboard, /queries, …) so
// pages are linkable and the browser back/forward buttons work.
const tabFromPath = (): Tab => {
  const seg = window.location.pathname.replace(/^\/+|\/+$/g, '') as Tab
  return ALL_TABS.includes(seg) ? seg : 'dashboard'
}

export default function App() {
  const [tab, setTab] = useState<Tab>(tabFromPath)
  const [user, setUser] = useState<SessionUser | null>(null)
  const [info, setInfo] = useState<AuthInfo | null>(null)
  const [loading, setLoading] = useState(true)

  // navigate switches tab and pushes the matching path into history.
  const navigate = (t: Tab) => {
    setTab(t)
    if (tabFromPath() !== t) window.history.pushState({}, '', `/${t}`)
  }

  const refresh = async () => {
    const inf = await api.authInfo()
    setInfo(inf)
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

  if (info?.auth_enabled && !user) {
    return <Login oidc={!!info.oidc_enabled} onLogin={() => refresh()} />
  }

  // 'account' is reached from the avatar menu, not the nav.
  const tabs: Tab[] = ['dashboard', 'queries', 'filtering']
  if (info?.classifier_available && info?.classifier_enabled) tabs.push('ai')
  tabs.push('rewrites')
  if (info?.cluster_enabled) tabs.push('cluster')
  tabs.push('settings')

  return (
    <div className="app">
      <header>
        <h1>🧭 MazeDNS</h1>
        <nav>
          {tabs.map((t) => (
            <button key={t} className={tab === t ? 'active' : ''} onClick={() => navigate(t)}>
              {t}
            </button>
          ))}
        </nav>
        <div className="spacer" />
        {user && (
          <AccountMenu
            user={user}
            authEnabled={!!info?.auth_enabled}
            onSettings={() => navigate('account')}
            onLogout={logout}
          />
        )}
      </header>
      <main>
        {tab === 'dashboard' && <Dashboard />}
        {tab === 'queries' && <Queries />}
        {tab === 'filtering' && <Filtering />}
        {tab === 'ai' && info?.classifier_enabled && <Classifier />}
        {tab === 'rewrites' && <Rewrites />}
        {tab === 'cluster' && info?.cluster_enabled && <Cluster />}
        {tab === 'settings' && <Settings onClassifierChange={() => refresh()} />}
        {tab === 'account' && info?.auth_enabled && <Account me={user} />}
      </main>
    </div>
  )
}
