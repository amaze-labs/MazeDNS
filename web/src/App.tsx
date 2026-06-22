import { useEffect, useState } from 'react'
import Dashboard from './components/Dashboard'
import Rules from './components/Rules'
import Rewrites from './components/Rewrites'
import Login from './components/Login'
import { api, type SessionUser, type AuthInfo } from './api'

type Tab = 'dashboard' | 'rules' | 'rewrites'
const tabs: Tab[] = ['dashboard', 'rules', 'rewrites']

export default function App() {
  const [tab, setTab] = useState<Tab>('dashboard')
  const [user, setUser] = useState<SessionUser | null>(null)
  const [info, setInfo] = useState<AuthInfo | null>(null)
  const [loading, setLoading] = useState(true)

  const refresh = async () => {
    const inf = await api.authInfo()
    setInfo(inf)
    setUser(inf.auth_enabled ? await api.me() : { id: 0, username: 'anonymous', role: 'admin' })
    setLoading(false)
  }

  useEffect(() => {
    refresh().catch(() => setLoading(false))
  }, [])

  const logout = async () => {
    await api.logout()
    setUser(null)
  }

  if (loading) {
    return (
      <div className="app">
        <p className="muted">Loading…</p>
      </div>
    )
  }

  if (info?.auth_enabled && !user) {
    return <Login oidc={!!info.oidc_enabled} onLogin={() => refresh()} />
  }

  return (
    <div className="app">
      <header>
        <h1>🧭 MazeDNS</h1>
        <nav>
          {tabs.map((t) => (
            <button key={t} className={tab === t ? 'active' : ''} onClick={() => setTab(t)}>
              {t}
            </button>
          ))}
        </nav>
        <div className="spacer" />
        {user && (
          <div className="user">
            <span className="muted">
              {user.username} · {user.role}
            </span>
            {info?.auth_enabled && (
              <button className="del" onClick={logout}>
                logout
              </button>
            )}
          </div>
        )}
      </header>
      <main>
        {tab === 'dashboard' && <Dashboard />}
        {tab === 'rules' && <Rules />}
        {tab === 'rewrites' && <Rewrites />}
      </main>
    </div>
  )
}
