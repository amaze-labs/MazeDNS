import { useState, type FormEvent } from 'react'
import { api, type Settings, type OIDCSettings } from '../api'
import { Icon } from './icons'

// Setup is the first-boot wizard shown when the control plane has no admin yet.
// Step 1 chooses how the control plane authenticates — local accounts or an
// external OIDC provider — and completes setup atomically. It runs with no token
// (trust-on-first-use): whoever reaches the fresh control plane first sets it up,
// so it must not be exposed publicly until setup completes.
export default function Setup({ onDone }: { onDone: () => void }) {
  const [step, setStep] = useState(1)
  const [err, setErr] = useState('')
  const [busy, setBusy] = useState(false)

  // Step 1 — auth method + admin.
  const [method, setMethod] = useState<'local' | 'sso'>('local')
  const [username, setUsername] = useState('admin')
  const [password, setPassword] = useState('')
  const [confirm, setConfirm] = useState('')

  // Step 1 (SSO) — OIDC provider.
  const cpURL = `${window.location.protocol}//${window.location.hostname}${
    window.location.port ? ':' + window.location.port : ''
  }`
  const redirectURI = `${cpURL}/api/auth/oidc/callback`
  const [issuer, setIssuer] = useState('')
  const [clientId, setClientId] = useState('')
  const [clientSecret, setClientSecret] = useState('')
  const [scopes, setScopes] = useState('')
  const [groupsClaim, setGroupsClaim] = useState('groups')
  const [adminGroup, setAdminGroup] = useState('')
  const [adminEmail, setAdminEmail] = useState('')
  const [breakGlass, setBreakGlass] = useState(true) // recommended default
  const [copied, setCopied] = useState(false)

  // Step 2 — DNS.
  const [upstreams, setUpstreams] = useState('1.1.1.1:53, 9.9.9.9:53')
  const [blockResponse, setBlockResponse] = useState('nxdomain')

  // Step 3 — cluster.
  const [requireApproval, setRequireApproval] = useState(false)
  const [enrollKey, setEnrollKey] = useState('')

  // SSO-only setups have no local session, so the wizard can't continue into the
  // authenticated DNS/Cluster steps — it jumps to a "sign in with SSO" finish.
  const [ssoOnly, setSsoOnly] = useState(false)
  // Local admin created but the auto-login session didn't start: setup is done,
  // but the authenticated DNS/Cluster steps can't run — finish with a sign-in
  // prompt instead of silently skipping ahead.
  const [needsLogin, setNeedsLogin] = useState(false)

  const pwScore = passwordScore(password)
  const localAdminNeeded = method === 'local' || breakGlass

  // Username / password / confirm fields — shared by the local-admin flow and the
  // optional SSO break-glass account.
  const credentialFields = (
    <>
      <label>
        Username
        <input value={username} onChange={(e) => setUsername(e.target.value)} autoComplete="username" />
      </label>
      <label>
        Password
        <input
          type="password"
          value={password}
          onChange={(e) => setPassword(e.target.value)}
          autoComplete="new-password"
        />
      </label>
      {password && (
        <div className={`pw-meter ${pwScore.level}`}>
          <span /> <small>{pwScore.hint}</small>
        </div>
      )}
      <label>
        Confirm password
        <input
          type="password"
          value={confirm}
          onChange={(e) => setConfirm(e.target.value)}
          autoComplete="new-password"
        />
      </label>
    </>
  )

  const complete = async (e: FormEvent) => {
    e.preventDefault()
    if (localAdminNeeded) {
      if (password !== confirm) return setErr('passwords do not match')
      if (pwScore.level === 'weak') return setErr(pwScore.hint)
    }
    if (method === 'sso') {
      if (!issuer.trim() || !clientId.trim()) return setErr('issuer and client ID are required')
      if (!adminEmail.trim()) return setErr('enter the admin email that gets the admin role on first SSO login')
    }
    setBusy(true)
    setErr('')
    try {
      const oidc: OIDCSettings | undefined =
        method === 'sso'
          ? {
              enabled: true,
              issuer: issuer.trim(),
              client_id: clientId.trim(),
              client_secret: clientSecret,
              redirect_url: redirectURI,
              scopes: scopes
                .split(/[\s,]+/)
                .map((s) => s.trim())
                .filter(Boolean),
              groups_claim: groupsClaim.trim(),
              admin_group: adminGroup.trim(),
              admin_email: adminEmail.trim(),
              disable_password_login: false, // server derives this from break_glass
              auto_login: false,
            }
          : undefined
      const res = await api.setupComplete({
        method,
        username: localAdminNeeded ? username.trim() : undefined,
        password: localAdminNeeded ? password : undefined,
        break_glass: method === 'sso' ? breakGlass : undefined,
        oidc,
      })
      if (res.authenticated) {
        setStep(2)
      } else if (localAdminNeeded) {
        // A local admin was created but the session didn't start — setup itself
        // succeeded, so surface a sign-in finish rather than pretending SSO.
        setNeedsLogin(true)
        setStep(4)
      } else {
        // SSO-only: no local session — finish and send the operator to SSO login.
        setSsoOnly(true)
        setStep(4)
      }
    } catch (e: any) {
      setErr(e.message)
    } finally {
      setBusy(false)
    }
  }

  const saveDNS = async () => {
    setBusy(true)
    setErr('')
    try {
      const cur = await api.settings()
      const next: Settings = {
        ...cur,
        upstreams: upstreams
          .split(/[\s,]+/)
          .map((u) => u.trim())
          .filter(Boolean),
        block_response: blockResponse,
      }
      if (next.upstreams.length === 0) throw new Error('add at least one upstream')
      await api.saveSettings(next)
      setStep(3)
    } catch (e: any) {
      setErr(e.message)
    } finally {
      setBusy(false)
    }
  }

  const saveCluster = async () => {
    setBusy(true)
    setErr('')
    try {
      const { settings } = await api.cpSettings()
      await api.saveCPSettings({ ...settings, require_approval: requireApproval })
      setStep(4)
    } catch (e: any) {
      setErr(e.message)
    } finally {
      setBusy(false)
    }
  }

  const makeEnrollKey = async () => {
    setBusy(true)
    setErr('')
    try {
      const r = await api.createEnrollKey('first-agents', 0, 0)
      setEnrollKey(r.key)
    } catch (e: any) {
      setErr(e.message)
    } finally {
      setBusy(false)
    }
  }

  const copyRedirect = async () => {
    try {
      await navigator.clipboard.writeText(redirectURI)
      setCopied(true)
      setTimeout(() => setCopied(false), 1500)
    } catch {
      /* clipboard blocked — the field is selectable */
    }
  }

  const agentSnippet = `--network host \\
-e MAZEDNS_CP_URL=${cpURL} \\
-e MAZEDNS_CP_IP=<control-plane-ip> \\
-e MAZEDNS_JOIN_TOKEN=${enrollKey || '<enrollment-key>'} \\
-e MAZEDNS_DB_PATH=/data/mazedns.db \\
-e MAZEDNS_API_ADDRESS=0.0.0.0 \\
-e MAZEDNS_API_PORT=9090 \\
-v mazedns-agent-data:/data`

  return (
    <div className="setup-wrap">
      <div className="setup-card">
        <div className="setup-head">
          <span className="brand-logo">
            <Icon name="brand" size={26} />
          </span>
          <h1>Welcome to MazeDNS</h1>
          <p className="muted">Let’s set up your control plane. This takes about a minute.</p>
        </div>
        <ol className="setup-steps">
          {['Auth', 'DNS', 'Cluster', 'Done'].map((label, i) => (
            <li key={label} className={step === i + 1 ? 'active' : step > i + 1 ? 'done' : ''}>
              <span className="setup-step-num">{step > i + 1 ? '✓' : i + 1}</span>
              {label}
            </li>
          ))}
        </ol>

        {err && <div className="error">{err}</div>}

        {step === 1 && (
          <form onSubmit={complete} className="setup-body">
            <p className="muted">Choose how operators sign in to this control plane. You can change this later in Settings.</p>
            <div className="setup-method">
              <label className={`setup-method-opt ${method === 'local' ? 'sel' : ''}`}>
                <input type="radio" name="method" checked={method === 'local'} onChange={() => setMethod('local')} />
                <span className="opt-mark" aria-hidden />
                <span className="opt-text">
                  <strong>Local accounts</strong>
                  <small className="muted">Username &amp; password managed in MazeDNS.</small>
                </span>
              </label>
              <label className={`setup-method-opt ${method === 'sso' ? 'sel' : ''}`}>
                <input type="radio" name="method" checked={method === 'sso'} onChange={() => setMethod('sso')} />
                <span className="opt-mark" aria-hidden />
                <span className="opt-text">
                  <strong>Single sign-on (OIDC)</strong>
                  <small className="muted">Sign in via an external identity provider.</small>
                </span>
              </label>
            </div>

            {method === 'local' && <div className="setup-fieldset">{credentialFields}</div>}

            {method === 'sso' && (
              <>
                <div className="setup-panel">
                  <div className="setup-panel-head">
                    <strong>OIDC provider</strong>
                    <small className="muted">
                      Register MazeDNS as an application in your provider, then paste its details. We’ll verify the issuer
                      before finishing.
                    </small>
                  </div>
                  <label>
                    Redirect URI — register this exact value with your provider
                    <div className="copy-row">
                      <input readOnly value={redirectURI} onFocus={(e) => e.target.select()} />
                      <button type="button" className="btn ghost" onClick={copyRedirect}>
                        {copied ? 'Copied' : 'Copy'}
                      </button>
                    </div>
                  </label>
                  <label>
                    Issuer URL
                    <input
                      value={issuer}
                      onChange={(e) => setIssuer(e.target.value)}
                      placeholder="https://idp.example.com/application/o/mazedns/"
                    />
                  </label>
                  <div className="setup-row">
                    <label>
                      Client ID
                      <input value={clientId} onChange={(e) => setClientId(e.target.value)} />
                    </label>
                    <label>
                      Client secret
                      <input type="password" value={clientSecret} onChange={(e) => setClientSecret(e.target.value)} />
                    </label>
                  </div>
                  <label>
                    Extra scopes (optional, comma-separated)
                    <input
                      value={scopes}
                      onChange={(e) => setScopes(e.target.value)}
                      placeholder="openid, profile and email are always requested"
                    />
                  </label>
                  <div className="setup-row">
                    <label>
                      Groups claim
                      <input value={groupsClaim} onChange={(e) => setGroupsClaim(e.target.value)} />
                    </label>
                    <label>
                      Admin group (optional)
                      <input value={adminGroup} onChange={(e) => setAdminGroup(e.target.value)} placeholder="mazedns-admins" />
                    </label>
                  </div>
                  <label>
                    Admin email — this identity becomes admin on first SSO login
                    <input value={adminEmail} onChange={(e) => setAdminEmail(e.target.value)} placeholder="you@example.com" />
                  </label>
                </div>

                <div className={`setup-panel ${breakGlass ? 'sel' : ''}`}>
                  <label className="toggle setup-toggle-row">
                    <span className="opt-text">
                      <strong>Break-glass local admin</strong>
                      <small className="muted">
                        A local password login kept alongside SSO, so a misconfigured or unreachable identity provider
                        can’t lock you out. Recommended.
                      </small>
                    </span>
                    <input type="checkbox" checked={breakGlass} onChange={(e) => setBreakGlass(e.target.checked)} />
                    <span className="track">
                      <span className="thumb" />
                    </span>
                  </label>
                  {breakGlass ? (
                    <div className="setup-subfields">{credentialFields}</div>
                  ) : (
                    <p className="setup-warn small">
                      Without a break-glass account, a broken IdP locks everyone out — recover with the CLI:{' '}
                      <code>control-plane reset-admin</code>.
                    </p>
                  )}
                </div>
              </>
            )}

            <button className="btn primary" disabled={busy}>
              {busy ? 'Finishing…' : method === 'sso' ? 'Verify SSO & continue' : 'Create admin & continue'}
            </button>
          </form>
        )}

        {step === 2 && (
          <div className="setup-body">
            <p className="muted">Basic DNS defaults — you can change these anytime in Settings.</p>
            <label>
              Upstream resolvers (comma-separated)
              <input value={upstreams} onChange={(e) => setUpstreams(e.target.value)} />
            </label>
            <label>
              Block response
              <select value={blockResponse} onChange={(e) => setBlockResponse(e.target.value)}>
                <option value="nxdomain">NXDOMAIN (recommended)</option>
                <option value="zeroip">Zero IP (0.0.0.0)</option>
              </select>
            </label>
            <div className="setup-actions">
              <button className="btn ghost" onClick={() => setStep(3)} disabled={busy}>
                Skip
              </button>
              <button className="btn primary" onClick={saveDNS} disabled={busy}>
                {busy ? 'Saving…' : 'Save & continue'}
              </button>
            </div>
          </div>
        )}

        {step === 3 && (
          <div className="setup-body">
            <p className="muted">
              Optional: create your first <strong>enrollment key</strong> so DNS agents can join. You can also do this
              later under Cluster.
            </p>
            <label className="setup-check">
              <input type="checkbox" checked={requireApproval} onChange={(e) => setRequireApproval(e.target.checked)} />
              Require admin approval before a new agent serves DNS
            </label>
            {!enrollKey ? (
              <button className="btn" onClick={makeEnrollKey} disabled={busy}>
                Create enrollment key
              </button>
            ) : (
              <div className="enroll">
                <div className="ok-msg">
                  <strong>Enrollment key — shown once.</strong> Start an agent with these flags (the{' '}
                  <code>/data</code> volume holds the node’s identity — keep it across image updates). The full
                  copy-paste snippet is under Cluster → “Deploy a DNS agent”.
                </div>
                <pre className="keybox">{agentSnippet}</pre>
              </div>
            )}
            <div className="setup-actions">
              <button className="btn ghost" onClick={() => setStep(4)} disabled={busy}>
                Skip
              </button>
              <button className="btn primary" onClick={saveCluster} disabled={busy}>
                {busy ? 'Saving…' : 'Save & continue'}
              </button>
            </div>
          </div>
        )}

        {step === 4 && (
          <div className="setup-body">
            {ssoOnly ? (
              <>
                <div className="ok-msg">
                  <strong>SSO configured.</strong> Sign in with your identity provider to finish — the account{' '}
                  <code>{adminEmail}</code> will receive the admin role. Configure DNS and cluster settings after you sign
                  in.
                </div>
                <a className="btn primary" href="/api/auth/oidc/login">
                  Sign in with SSO
                </a>
              </>
            ) : needsLogin ? (
              <>
                <div className="ok-msg">
                  <strong>Setup complete.</strong> Sign in with the admin account you just created to configure DNS and
                  cluster settings.
                </div>
                <button className="btn primary" onClick={onDone}>
                  Go to sign in
                </button>
              </>
            ) : (
              <>
                <div className="ok-msg">
                  <strong>All set!</strong> Your control plane is ready. Configure SSO, metrics, and classification anytime
                  in Settings.
                </div>
                <button className="btn primary" onClick={onDone}>
                  Go to dashboard
                </button>
              </>
            )}
          </div>
        )}
      </div>
    </div>
  )
}

// passwordScore gives a coarse strength signal for the meter (server enforces the
// real minimum on submit).
function passwordScore(pw: string): { level: 'weak' | 'ok' | 'strong'; hint: string } {
  if (pw.length < 10) return { level: 'weak', hint: 'At least 10 characters' }
  const variety = [/[a-z]/, /[A-Z]/, /[0-9]/, /[^a-zA-Z0-9]/].filter((re) => re.test(pw)).length
  if (variety < 2) return { level: 'weak', hint: 'Mix letters with digits or symbols' }
  if (pw.length >= 14 && variety >= 3) return { level: 'strong', hint: 'Strong password' }
  return { level: 'ok', hint: 'Good password' }
}
