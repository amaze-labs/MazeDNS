import { useEffect, useState, type FormEvent } from 'react'
import { api } from '../api'

// Set just before logout so auto-login doesn't immediately bounce the user back
// into SSO (letting them actually sign out / switch accounts).
export const SKIP_AUTOLOGIN_KEY = 'mazedns.skipAutoLogin'

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
    try {
      await api.login(username, password)
      onLogin()
    } catch (e: any) {
      setErr(e.message || 'login failed')
    }
  }

  return (
    <div className="login">
      <div className="login-card">
        <h1>🧭 MazeDNS</h1>
        {err && <div className="error">{err}</div>}
        {!(oidc && passwordDisabled) && (
          <form onSubmit={submit}>
            <input placeholder="username" value={username} onChange={(e) => setUsername(e.target.value)} autoFocus />
            <input
              type="password"
              placeholder="password"
              value={password}
              onChange={(e) => setPassword(e.target.value)}
            />
            <button type="submit">Sign in</button>
          </form>
        )}
        {oidc && (
          <a className="oidc" href="/api/auth/oidc/login">
            Sign in with SSO
          </a>
        )}
      </div>
    </div>
  )
}
