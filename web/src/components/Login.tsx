import { useState, type FormEvent } from 'react'
import { api } from '../api'

export default function Login({ oidc, onLogin }: { oidc: boolean; onLogin: () => void }) {
  const [username, setUsername] = useState('')
  const [password, setPassword] = useState('')
  const [err, setErr] = useState('')

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
        {oidc && (
          <a className="oidc" href="/api/auth/oidc/login">
            Sign in with SSO
          </a>
        )}
      </div>
    </div>
  )
}
