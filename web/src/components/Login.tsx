import { useEffect, useMemo, useState, type FormEvent } from 'react'
import { api } from '../api'
import { Icon } from './icons'
import '../styles/auth.css'

// Set just before logout so auto-login doesn't immediately bounce the user back
// into SSO (letting them actually sign out / switch accounts).
export const SKIP_AUTOLOGIN_KEY = 'mazedns.skipAutoLogin'

// MazeArt draws a deterministic maze with one route traced through it in the
// accent colour: the brand made literal. Purely decorative. Shared with Setup.
export function MazeArt() {
  const { lines, path, end } = useMemo(() => {
    const W = 720
    const H = 900
    const S = 36
    let seed = 7
    const rnd = () => (seed = (seed * 16807) % 2147483647) / 2147483647
    const lines: string[] = []
    for (let y = 0; y < H; y += S)
      for (let x = 0; x < W; x += S) {
        lines.push(rnd() > 0.5 ? `M${x} ${y}L${x + S} ${y + S}` : `M${x + S} ${y}L${x} ${y + S}`)
      }
    let px = 0
    let py = 12 * S
    let path = `M ${px} ${py}`
    let dir = 1
    for (let i = 0; i < 30 && px < W; i++) {
      if (rnd() > 0.45) {
        px += S
        dir = rnd() > 0.5 ? 1 : -1
      } else {
        py = Math.min(18 * S, Math.max(8 * S, py + dir * S))
      }
      path += ` L ${px} ${py}`
    }
    return { lines: lines.join(''), path, end: [px, py] }
  }, [])
  return (
    <svg className="maze" viewBox="0 0 720 900" preserveAspectRatio="xMidYMid slice" aria-hidden>
      <path d={lines} stroke="var(--line)" strokeWidth={2} strokeLinecap="round" fill="none" />
      <path d={path} fill="none" stroke="var(--accent)" strokeWidth={3} strokeLinecap="round" strokeLinejoin="round" />
      <circle cx={end[0]} cy={end[1]} r={6} fill="var(--accent)" />
    </svg>
  )
}

export default function Login({
  oidc,
  passwordDisabled = false,
  autoLogin = false,
  onLogin,
}: {
  oidc: boolean
  passwordDisabled?: boolean
  autoLogin?: boolean
  onLogin: () => void
}) {
  const [username, setUsername] = useState('')
  const [password, setPassword] = useState('')
  const [err, setErr] = useState('')
  const [busy, setBusy] = useState(false)

  // Auto-login: redirect straight to SSO — unless the user just logged out.
  useEffect(() => {
    if (!oidc || !autoLogin) return
    if (sessionStorage.getItem(SKIP_AUTOLOGIN_KEY)) {
      sessionStorage.removeItem(SKIP_AUTOLOGIN_KEY)
      return
    }
    window.location.href = '/api/auth/oidc/login'
  }, [oidc, autoLogin])

  const submit = async (e: FormEvent) => {
    e.preventDefault()
    setErr('')
    setBusy(true)
    try {
      await api.login(username, password)
      onLogin()
    } catch (e: any) {
      setErr(e.message || 'Sign-in failed')
    } finally {
      setBusy(false)
    }
  }

  const passwordOn = !(oidc && passwordDisabled)

  return (
    <div className="auth-login">
      <div className="art-side">
        <MazeArt />
        <div className="art-brand">
          <span className="brand-logo">
            <Icon name="brand" size={24} strokeWidth={2} />
          </span>
          MazeDNS
        </div>
        <blockquote>
          One place to decide what every network you run is allowed to resolve.
          <small>Control plane for your MazeDNS agents</small>
        </blockquote>
      </div>

      <div className="form-side">
        <form className="auth-form" onSubmit={submit}>
          <div>
            <h1>Sign in</h1>
            <p className="lede">
              to the control plane at <span className="mono">{window.location.host}</span>
            </p>
          </div>
          {err && <div className="error">{err}</div>}
          {oidc && (
            <a className="btn block" href="/api/auth/oidc/login">
              Continue with single sign-on
            </a>
          )}
          {oidc && passwordOn && <div className="or">or with a local account</div>}
          {passwordOn && (
            <>
              <label className="field">
                <span>Username</span>
                <input
                  value={username}
                  onChange={(e) => setUsername(e.target.value)}
                  autoComplete="username"
                  autoCapitalize="none"
                  spellCheck={false}
                  autoFocus={!oidc}
                />
              </label>
              <label className="field">
                <span>Password</span>
                <input
                  type="password"
                  value={password}
                  onChange={(e) => setPassword(e.target.value)}
                  autoComplete="current-password"
                />
              </label>
              <button type="submit" className="btn primary block" disabled={busy}>
                {busy ? 'Signing in…' : 'Sign in'}
              </button>
            </>
          )}
          {!passwordOn && <p className="foot">Password sign-in is turned off. Use your identity provider.</p>}
          <p className="foot">
            Locked out? Run <code>control-plane reset-admin</code> on the host.
          </p>
        </form>
      </div>
    </div>
  )
}
