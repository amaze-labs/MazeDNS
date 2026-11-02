import { useEffect, useMemo, useState, type FormEvent } from 'react'
import { api, isMFAChallenge, type MFAChallenge } from '../api'
import { CodeInput, MFASetupSteps, RecoveryCodes } from './MFA'
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
  // After a correct password: the second factor still to give (or to set up),
  // then, after setting one up, the recovery codes to save.
  const [mfa, setMfa] = useState<MFAChallenge | null>(null)
  const [code, setCode] = useState('')
  const [newCodes, setNewCodes] = useState<string[] | null>(null)

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
      const r = await api.login(username, password)
      if (isMFAChallenge(r)) {
        setMfa(r)
        setPassword('')
        return
      }
      onLogin()
    } catch (e: any) {
      setErr(e.message || 'Sign-in failed')
    } finally {
      setBusy(false)
    }
  }

  const verify = async (e: FormEvent) => {
    e.preventDefault()
    if (!mfa) return
    setErr('')
    setBusy(true)
    try {
      await api.mfaVerify(mfa.challenge, code)
      onLogin()
    } catch (e: any) {
      setErr(e.message || 'Sign-in failed')
      setCode('')
      // An expired or used-up challenge means starting over from the password.
      if (/sign in again/.test(e.message || '')) setMfa(null)
    } finally {
      setBusy(false)
    }
  }

  const restart = () => {
    setMfa(null)
    setCode('')
    setErr('')
  }

  const passwordOn = !(oidc && passwordDisabled)

  // The second step of a password sign-in replaces the form.
  let second: JSX.Element | null = null
  if (newCodes) {
    second = (
      <div className="auth-form">
        <div>
          <h1>Save your recovery codes</h1>
          <p className="lede">Two-factor sign-in is on.</p>
        </div>
        <RecoveryCodes codes={newCodes} onDone={onLogin} doneLabel="Continue" />
      </div>
    )
  } else if (mfa?.mfa === 'verify') {
    second = (
      <form className="auth-form" onSubmit={verify}>
        <div>
          <h1>Two-factor sign-in</h1>
          <p className="lede">Open your authenticator app and enter the code for MazeDNS.</p>
        </div>
        {err && <div className="error">{err}</div>}
        <CodeInput value={code} onChange={setCode} allowRecovery />
        <button type="submit" className="btn primary block" disabled={busy || code.trim().length < 6}>
          {busy ? 'Checking…' : 'Verify'}
        </button>
        <button type="button" className="btn quiet block" onClick={restart}>
          Back
        </button>
        <p className="foot">Lost your phone? Enter one of your recovery codes, or ask an administrator to reset it.</p>
      </form>
    )
  } else if (mfa?.mfa === 'setup') {
    second = (
      <div className="auth-form">
        <div>
          <h1>Set up two-factor sign-in</h1>
          <p className="lede">This control plane requires it for local accounts. It takes a minute.</p>
        </div>
        <MFASetupSteps
          challenge={mfa.challenge}
          onEnabled={(codes) => setNewCodes(codes)}
          onCancel={restart}
        />
      </div>
    )
  }

  return (
    <div className="auth-login">
      <div className="art-side">
        <MazeArt />
        <div className="art-brand">
          <span className="brand-logo">
            <img src="/favicon.svg" alt="" width={24} height={24} />
          </span>
          MazeDNS
        </div>
        <blockquote>
          One place to decide what every network you run is allowed to resolve.
          <small>Control plane for your MazeDNS resolvers</small>
        </blockquote>
      </div>

      <div className="form-side">
        {second ?? (
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
        )}
      </div>
    </div>
  )
}
