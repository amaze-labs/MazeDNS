import { useEffect, useLayoutEffect, useRef, useState } from 'react'
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
import { useTheme, type ThemeMode } from './theme'
import { withViewTransition } from './motion'
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
  const { mode, setMode: applyMode } = useTheme()
  // The theme switch cross-fades the whole page where the browser can.
  const setMode = (m: ThemeMode) => m !== mode && withViewTransition(() => applyMode(m))
  // The active-tab pill slides between tabs: its offset and width follow the
  // current tab's button.
  const navRef = useRef<HTMLElement>(null)
  const [ind, setInd] = useState<{ x: number; w: number } | null>(null)
  // stacked: the navigation needs a row of its own (it wouldn't fit beside
  // the brand and the tools), decided from the widths, not a breakpoint.
  const barRef = useRef<HTMLElement>(null)
  const [stacked, setStacked] = useState(false)

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

  // Whether a newer release is out, for the note next to the version.
  const [updateTo, setUpdateTo] = useState('')
  useEffect(() => {
    if (!user) return
    const check = () =>
      api
        .updates()
        .then((u) => setUpdateTo(u.update_available && u.latest ? u.latest : ''))
        .catch(() => {})
    check()
    const t = setInterval(check, 6 * 3600 * 1000)
    return () => clearInterval(t)
  }, [user])

  // Re-measure the active-tab pill whenever the tab, the tab set or a count
  // badge (which changes a button's width) changes, and on resize.
  useLayoutEffect(() => {
    const measure = () => {
      const bar = barRef.current
      const nav = navRef.current
      if (bar && nav) {
        const cs = getComputedStyle(bar)
        const inner = bar.clientWidth - parseFloat(cs.paddingLeft) - parseFloat(cs.paddingRight)
        const gap = parseFloat(cs.columnGap) || 0
        // The navigation's natural width: its buttons, gaps and padding.
        const btns = [...nav.querySelectorAll<HTMLElement>(':scope > button')]
        const ncs = getComputedStyle(nav)
        // A tab's natural width (its content and padding): when stacked the
        // tabs stretch to fill the row, so their box width would mislead.
        const natural = (b: HTMLElement) => {
          const r = document.createRange()
          r.selectNodeContents(b)
          const bcs = getComputedStyle(b)
          return r.getBoundingClientRect().width + parseFloat(bcs.paddingLeft) + parseFloat(bcs.paddingRight)
        }
        const navNeed =
          btns.reduce((w, b) => w + natural(b), 0) +
          (btns.length - 1) * (parseFloat(ncs.columnGap) || 0) +
          parseFloat(ncs.paddingLeft) +
          parseFloat(ncs.paddingRight)
        const others = [...bar.children].filter((c) => c !== nav) as HTMLElement[]
        const othersW = others.reduce((w, c) => w + c.offsetWidth, 0)
        const need = navNeed + othersW + others.length * gap
        setStacked(need > inner)
      }
      const btn = navRef.current?.querySelector<HTMLElement>('button.active')
      setInd((cur) => {
        const next = btn ? { x: btn.offsetLeft, w: btn.offsetWidth } : null
        return cur && next && cur.x === next.x && cur.w === next.w ? cur : next
      })
    }
    measure()
    document.fonts?.ready.then(measure)
    window.addEventListener('resize', measure)
    return () => window.removeEventListener('resize', measure)
  }, [tab, user, info, badges.agents, badges.filtering, appVersion, updateTo])

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
  // Light, follow the system, dark: the same three choices in the top bar
  // and in the phone's More sheet.
  const THEMES: { m: ThemeMode; icon: IconName; label: string }[] = [
    { m: 'light', icon: 'sun', label: 'Light' },
    { m: 'system', icon: 'monitor', label: 'System' },
    { m: 'dark', icon: 'moon', label: 'Dark' },
  ]

  return (
    <div className="app">
      <header className={`topbar${stacked ? ' stacked' : ''}`} ref={barRef}>
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
        {updateTo && (
          <a
            className="tb-update"
            href="/settings?section=about"
            title={`MazeDNS ${updateTo} is available — see what changed`}
            onClick={(e) => {
              e.preventDefault()
              window.history.pushState({}, '', '/settings?section=about')
              window.dispatchEvent(new PopStateEvent('popstate')) // App and Settings follow the URL
            }}
          >
            <span className="dot warn" /> Update to {updateTo}
          </a>
        )}
        <nav className={`tb-nav${ind ? ' has-ind' : ''}`} aria-label="Main" ref={navRef}>
          {ind && <span className="tb-ind" style={{ transform: `translateX(${ind.x}px)`, width: ind.w }} aria-hidden="true" />}
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
            {THEMES.map((o) => (
              <button
                key={o.m}
                className={mode === o.m ? 'on' : ''}
                onClick={() => setMode(o.m)}
                title={o.m === 'system' ? 'Match the system' : `${o.label} theme`}
                aria-pressed={mode === o.m}
              >
                <Icon name={o.icon} size={16} />
              </button>
            ))}
          </div>
          {user && (
            <div className="tb-account">
              <AccountMenu
                user={user}
                roleLabel={isAdmin ? 'Administrator' : 'Viewer'}
                authEnabled={!!info.auth_enabled}
                onSettings={() => navigate('account')}
                onLogout={logout}
              />
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
            <div className="sheet-theme" role="group" aria-label="Theme">
              {THEMES.map((o) => (
                <button key={o.m} className={mode === o.m ? 'on' : ''} onClick={() => setMode(o.m)} aria-pressed={mode === o.m}>
                  <Icon name={o.icon} size={16} />
                  <span>{o.label}</span>
                </button>
              ))}
            </div>
          </div>
        </>
      )}
      <main key={shown} className="page-in">
        {shown === 'overview' && <Dashboard />}
        {shown === 'queries' && <Queries />}
        {shown === 'clients' && <Clients />}
        {shown === 'filtering' && <Filtering classifier={classifierOn} />}
        {shown === 'local-dns' && <LocalDNS />}
        {shown === 'agents' && <Cluster />}
        {shown === 'logs' && <Logs />}
        {shown === 'settings' && <Settings onClassifierChange={() => refresh()} />}
        {shown === 'account' && <Account me={user} oidc={!!info.oidc_enabled} onProfileChange={() => refresh()} />}
      </main>
    </div>
  )
}
