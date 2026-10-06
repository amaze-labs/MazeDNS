import { useEffect, useRef, useState, type FormEvent, type ReactNode } from 'react'
import { api, type Settings, type OIDCSettings } from '../api'
import { Icon } from './icons'
import { passwordPolicyError } from '../passwordPolicy'
import { PasswordMeter } from './Account'
import '../styles/auth.css'

const IMAGE = 'ghcr.io/amaze-labs/mazedns-agent:latest'

const WarnIcon = () => (
  <svg viewBox="0 0 24 24" aria-hidden>
    <path d="M12 3l9 16H3z" />
    <path d="M12 10v4M12 17h.01" />
  </svg>
)
const CheckIcon = () => (
  <svg viewBox="0 0 24 24" aria-hidden>
    <circle cx="12" cy="12" r="9" />
    <path d="M8 12l3 3 5-6" />
  </svg>
)

function Field({ label, hint, children }: { label: ReactNode; hint?: ReactNode; children: ReactNode }) {
  return (
    <label className="field">
      <span>{label}</span>
      {children}
      {hint && <small>{hint}</small>}
    </label>
  )
}

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
  const [copied, setCopied] = useState('')

  // Step 2 — DNS.
  const [upstreams, setUpstreams] = useState('1.1.1.1:53, 9.9.9.9:53')
  const [blockResponse, setBlockResponse] = useState('nxdomain')
  const [dnsDone, setDnsDone] = useState<'saved' | 'skipped' | ''>('')

  // Step 3 — cluster.
  const [requireApproval, setRequireApproval] = useState(false)
  const [enrollKey, setEnrollKey] = useState('')
  const [agentDone, setAgentDone] = useState<'saved' | 'skipped' | ''>('')
  // Agents seen when the key was made; anything new afterwards has just joined.
  const baseline = useRef<Set<string> | null>(null)
  const [joined, setJoined] = useState<string[]>([])
  const [watching, setWatching] = useState(false)

  // SSO-only setups have no local session, so the wizard can't continue into the
  // authenticated DNS/Cluster steps — it jumps to a "sign in with SSO" finish.
  const [ssoOnly, setSsoOnly] = useState(false)
  // Local admin created but the auto-login session didn't start: setup is done,
  // but the authenticated DNS/Cluster steps can't run — finish with a sign-in
  // prompt instead of silently skipping ahead.
  const [needsLogin, setNeedsLogin] = useState(false)

  const localAdminNeeded = method === 'local' || breakGlass

  const go = (n: number) => {
    setErr('')
    setStep(n)
    window.scrollTo({ top: 0 })
  }

  // While the agent step shows a fresh key, watch for agents joining with it.
  useEffect(() => {
    if (step !== 3 || !enrollKey || !baseline.current) return
    const tick = () =>
      api
        .clusterNodes()
        .then((ns) => setJoined(ns.filter((n) => !baseline.current!.has(n.id)).map((n) => n.name || n.id)))
        .catch(() => {})
    const t = window.setInterval(tick, 3000)
    return () => window.clearInterval(t)
  }, [step, enrollKey])

  // Username / password / confirm fields — shared by the local-admin flow and the
  // optional SSO break-glass account.
  const credentialFields = (
    <div className="cred">
      <Field label="Username">
        <input value={username} onChange={(e) => setUsername(e.target.value)} autoComplete="username" />
      </Field>
      <span />
      <label className="field">
        <span>Password</span>
        <input type="password" value={password} onChange={(e) => setPassword(e.target.value)} autoComplete="new-password" />
        <PasswordMeter password={password} />
      </label>
      <label className="field">
        <span>Confirm password</span>
        <input type="password" value={confirm} onChange={(e) => setConfirm(e.target.value)} autoComplete="new-password" />
        {confirm && password !== confirm && <small className="bad-text">Doesn’t match yet.</small>}
      </label>
    </div>
  )

  const complete = async (e: FormEvent) => {
    e.preventDefault()
    if (localAdminNeeded) {
      if (!username.trim()) return setErr('Enter a username for the admin account.')
      const policy = passwordPolicyError(password)
      if (policy) return setErr(policy)
      if (password !== confirm) return setErr('The passwords don’t match.')
    }
    if (method === 'sso') {
      if (!issuer.trim() || !clientId.trim()) return setErr('The issuer URL and client ID are required.')
      if (!adminEmail.trim()) return setErr('Enter the admin email that gets the admin role on first SSO sign-in.')
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
        go(2)
      } else if (localAdminNeeded) {
        // A local admin was created but the session didn't start — setup itself
        // succeeded, so surface a sign-in finish rather than pretending SSO.
        setNeedsLogin(true)
        go(4)
      } else {
        // SSO-only: no local session — finish and send the operator to SSO login.
        setSsoOnly(true)
        go(4)
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
      if (next.upstreams.length === 0) throw new Error('Add at least one upstream resolver.')
      await api.saveSettings(next)
      setDnsDone('saved')
      go(3)
    } catch (e: any) {
      setErr(e.message)
    } finally {
      setBusy(false)
    }
  }

  const saveApproval = async () => {
    const { settings } = await api.cpSettings()
    await api.saveCPSettings({ ...settings, require_approval: requireApproval })
  }

  const saveCluster = async () => {
    setBusy(true)
    setErr('')
    try {
      await saveApproval()
      setAgentDone('saved')
      go(4)
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
      // Apply the approval choice first, so an agent that joins with this key
      // right away is already held for approval if asked.
      await saveApproval()
      baseline.current = await api
        .clusterNodes()
        .then((ns) => new Set(ns.map((n) => n.id)))
        .catch(() => null)
      setWatching(!!baseline.current)
      const r = await api.createEnrollKey('first-agents', 0, 0)
      setEnrollKey(r.key)
    } catch (e: any) {
      setErr(e.message)
    } finally {
      setBusy(false)
    }
  }

  const copy = async (what: string, text: string) => {
    try {
      await navigator.clipboard.writeText(text)
      setCopied(what)
      setTimeout(() => setCopied(''), 1500)
    } catch {
      /* clipboard blocked — the text is selectable */
    }
  }

  // Under host networking the agent has no docker DNS, so the control plane's
  // address is pinned. Use the address in the browser when it is already an IP.
  const host = window.location.hostname
  const cpIP = /^\d{1,3}(\.\d{1,3}){3}$/.test(host) ? host : '<control-plane-ip>'
  const keyText = enrollKey || '<enrollment-key>'
  const runHead = `docker run -d --name mazedns-agent --restart unless-stopped \\
  --network host \\
  -e MAZEDNS_CP_URL=${cpURL} \\
  -e MAZEDNS_CP_IP=${cpIP} \\
  -e MAZEDNS_JOIN_TOKEN=`
  const runTail = ` \\
  -e MAZEDNS_DB_PATH=/data/mazedns.db \\
  -e MAZEDNS_API_ADDRESS=0.0.0.0 \\
  -e MAZEDNS_API_PORT=9090 \\
  -v mazedns-agent-data:/data \\
  ${IMAGE}`

  // Sidebar summary of the choices made so far.
  const upstreamSummary = (() => {
    const list = upstreams.split(/[\s,]+/).filter(Boolean)
    return list.length > 1 ? `${list[0]} +${list.length - 1}` : list[0] || ''
  })()
  const steps: { title: string; sub: string }[] = [
    {
      title: 'Sign-in',
      sub:
        step > 1
          ? method === 'local'
            ? `${username}, local password`
            : breakGlass
            ? `SSO + local ${username}`
            : 'Single sign-on'
          : 'Admin account',
    },
    {
      title: 'DNS defaults',
      sub:
        dnsDone === 'saved'
          ? `${upstreamSummary}, ${blockResponse === 'nxdomain' ? 'NXDOMAIN' : '0.0.0.0'}`
          : dnsDone === 'skipped'
          ? 'Skipped'
          : 'Resolvers and blocking',
    },
    {
      title: 'First agent',
      sub: agentDone === 'saved' ? (enrollKey ? 'Key created' : 'Saved') : agentDone === 'skipped' ? 'Skipped' : 'Optional',
    },
    { title: 'Done', sub: '' },
  ]
  const finishedEarly = ssoOnly || needsLogin

  return (
    <div className="auth-setup">
      <aside className="setup-side">
        <div className="setup-brand">
          <span className="brand-logo">
            <Icon name="brand" size={22} strokeWidth={2} />
          </span>
          MazeDNS setup
        </div>
        <ol className="steps">
          {steps.map((st, i) => {
            const n = i + 1
            const skippedByFlow = finishedEarly && (n === 2 || n === 3)
            const state = step === n ? 'on' : step > n && !skippedByFlow ? 'done' : ''
            return (
              <li key={st.title} className={state} aria-current={step === n ? 'step' : undefined}>
                <span className="n">{state === 'done' ? '✓' : n}</span>
                <div>
                  <b>{st.title}</b>
                  {st.sub && <small>{skippedByFlow ? 'After you sign in' : st.sub}</small>}
                </div>
              </li>
            )
          })}
        </ol>
        {step === 1 && (
          <div className="callout warn">
            <WarnIcon />
            <div>
              <b>Setup is open</b>
              <p>Whoever reaches this page first becomes admin. Keep this port private until you finish.</p>
            </div>
          </div>
        )}
      </aside>

      <main className="stage">
        {step === 1 && (
          <form onSubmit={complete}>
            <h1>How will people sign in?</h1>
            <p className="lede">You can change this later in Settings. It takes about a minute.</p>
            {err && <div className="error">{err}</div>}

            <div className="choice" role="radiogroup" aria-label="Sign-in method">
              <label className={method === 'local' ? 'on' : ''}>
                <input type="radio" name="method" checked={method === 'local'} onChange={() => setMethod('local')} />
                <b>Local accounts</b>
                <small>Usernames and passwords kept in MazeDNS.</small>
              </label>
              <label className={method === 'sso' ? 'on' : ''}>
                <input type="radio" name="method" checked={method === 'sso'} onChange={() => setMethod('sso')} />
                <b>Single sign-on (OIDC)</b>
                <small>Authentik, Keycloak, Entra ID, Google…</small>
              </label>
            </div>

            {method === 'local' && (
              <section className="block">
                <h2>Admin account</h2>
                {credentialFields}
              </section>
            )}

            {method === 'sso' && (
              <>
                <section className="block">
                  <h2>Identity provider</h2>
                  <p className="muted small">
                    Register MazeDNS as an application with your provider, then paste its details. The issuer is checked
                    before setup finishes.
                  </p>
                  <Field label="Redirect URI" hint="Register this exact value with your provider.">
                    <span className="copy-row">
                      <input className="mono" readOnly value={redirectURI} onFocus={(e) => e.target.select()} />
                      <button type="button" className="btn" onClick={() => copy('redirect', redirectURI)}>
                        {copied === 'redirect' ? 'Copied' : 'Copy'}
                      </button>
                    </span>
                  </Field>
                  <Field label="Issuer URL">
                    <input
                      className="mono"
                      value={issuer}
                      onChange={(e) => setIssuer(e.target.value)}
                      placeholder="https://idp.example.com/application/o/mazedns/"
                    />
                  </Field>
                  <div className="two">
                    <Field label="Client ID">
                      <input value={clientId} onChange={(e) => setClientId(e.target.value)} />
                    </Field>
                    <Field label="Client secret">
                      <input
                        type="password"
                        autoComplete="new-password"
                        value={clientSecret}
                        onChange={(e) => setClientSecret(e.target.value)}
                      />
                    </Field>
                  </div>
                  <Field label="Extra scopes (optional)" hint="Comma-separated. openid, profile and email are always requested.">
                    <input value={scopes} onChange={(e) => setScopes(e.target.value)} />
                  </Field>
                  <div className="two">
                    <Field label="Groups claim">
                      <input value={groupsClaim} onChange={(e) => setGroupsClaim(e.target.value)} />
                    </Field>
                    <Field label="Admin group (optional)">
                      <input value={adminGroup} onChange={(e) => setAdminGroup(e.target.value)} placeholder="mazedns-admins" />
                    </Field>
                  </div>
                  <Field label="Admin email" hint="This identity becomes admin on its first SSO sign-in.">
                    <input value={adminEmail} onChange={(e) => setAdminEmail(e.target.value)} placeholder="you@example.com" />
                  </Field>
                </section>

                <section className="block">
                  <label className="check-row toggle boxed">
                    <span className="t">
                      <b>Keep a local admin as well</b>
                      <small>
                        A password sign-in alongside SSO, so a broken or unreachable identity provider can’t lock you out.
                        Recommended.
                      </small>
                    </span>
                    <input type="checkbox" checked={breakGlass} onChange={(e) => setBreakGlass(e.target.checked)} />
                    <span className="track">
                      <span className="thumb" />
                    </span>
                  </label>
                  {breakGlass ? (
                    credentialFields
                  ) : (
                    <div className="callout warn">
                      <WarnIcon />
                      <div>
                        <b>No way back in without the CLI</b>
                        <p>
                          If the identity provider breaks, recover with <code>control-plane reset-admin</code> on the host.
                        </p>
                      </div>
                    </div>
                  )}
                </section>
              </>
            )}

            <div className="stage-actions">
              <span className="spacer" />
              <button className="btn primary" disabled={busy}>
                {busy ? 'Finishing…' : method === 'sso' ? 'Check SSO and continue' : 'Create admin and continue'}
              </button>
            </div>
          </form>
        )}

        {step === 2 && (
          <div>
            <h1>DNS defaults</h1>
            <p className="lede">Where agents forward what they can’t answer, and what a blocked name returns. You can change both in Settings.</p>
            {err && <div className="error">{err}</div>}
            <section className="block">
              <Field
                label="Upstream resolvers"
                hint={
                  <>
                    Comma-separated, tried in order. Encrypted ones work too: <code>tls://1.1.1.1:853#cloudflare-dns.com</code>{' '}
                    or <code>https://dns.quad9.net/dns-query</code>.
                  </>
                }
              >
                <input className="mono" value={upstreams} onChange={(e) => setUpstreams(e.target.value)} />
              </Field>
            </section>
            <section className="block">
              <h2>Blocked answers</h2>
              <div className="choice" role="radiogroup" aria-label="Blocked answer">
                <label className={blockResponse === 'nxdomain' ? 'on' : ''}>
                  <input type="radio" name="block" checked={blockResponse === 'nxdomain'} onChange={() => setBlockResponse('nxdomain')} />
                  <b>NXDOMAIN</b>
                  <small>“This name doesn’t exist.” Recommended: apps give up fast.</small>
                </label>
                <label className={blockResponse === 'zeroip' ? 'on' : ''}>
                  <input type="radio" name="block" checked={blockResponse === 'zeroip'} onChange={() => setBlockResponse('zeroip')} />
                  <b>0.0.0.0</b>
                  <small>A null address. Some old devices retry less with this.</small>
                </label>
              </div>
            </section>
            <div className="stage-actions">
              <span className="spacer" />
              <button
                className="btn"
                onClick={() => {
                  setDnsDone('skipped')
                  go(3)
                }}
                disabled={busy}
              >
                Skip for now
              </button>
              <button className="btn primary" onClick={saveDNS} disabled={busy}>
                {busy ? 'Saving…' : 'Save and continue'}
              </button>
            </div>
          </div>
        )}

        {step === 3 && (
          <div>
            <h1>Start your first agent</h1>
            <p className="lede">
              The control plane doesn’t answer DNS itself. Run an agent on any host your clients can reach: it joins with
              an enrollment key and copies these settings.
            </p>
            {err && <div className="error">{err}</div>}

            <label className="check-row toggle boxed">
              <span className="t">
                <b>Ask me before a new agent serves DNS</b>
                <small>New agents wait under Agents until you approve them. Safer if a key could leak.</small>
              </span>
              <input type="checkbox" checked={requireApproval} onChange={(e) => setRequireApproval(e.target.checked)} />
              <span className="track">
                <span className="thumb" />
              </span>
            </label>

            {!enrollKey ? (
              <section className="block">
                <p className="muted" style={{ margin: 0 }}>
                  Make a key to get a ready-to-run command. You can also skip this and add agents later under Agents.
                </p>
                <div>
                  <button className="btn" onClick={makeEnrollKey} disabled={busy}>
                    {busy ? 'Creating…' : 'Create an enrollment key'}
                  </button>
                </div>
              </section>
            ) : (
              <section className="block">
                <div className="keybox">
                  <div className="keybox-head">
                    <span>Run this on the agent’s host</span>
                    <button type="button" className="btn sm" onClick={() => copy('run', runHead + keyText + runTail)}>
                      {copied === 'run' ? 'Copied' : 'Copy'}
                    </button>
                  </div>
                  <pre>
                    {runHead}
                    <span className="hl">{keyText}</span>
                    {runTail}
                  </pre>
                </div>
                <p className="muted small" style={{ margin: 0 }}>
                  The key is shown once. The <code>/data</code> volume holds the agent’s identity, so keep it across image
                  updates.
                  {cpIP !== host && (
                    <>
                      {' '}
                      Replace <code>&lt;control-plane-ip&gt;</code> with this machine’s address.
                    </>
                  )}{' '}
                  Compose files and per-agent keys are under Agents.
                </p>
                {watching &&
                  (joined.length > 0 ? (
                    <div className="callout ok">
                      <CheckIcon />
                      <div>
                        <b>
                          {joined.length === 1 ? `${joined[0]} joined` : `${joined.length} agents joined`}
                          {requireApproval ? ' and is waiting for approval' : ''}
                        </b>
                        <p>Continue to finish setup.</p>
                      </div>
                    </div>
                  ) : (
                    <div className="callout">
                      <span className="spin" aria-hidden />
                      <div>
                        <b>Waiting for an agent…</b>
                        <p>This updates as soon as one joins. You can also continue and add agents later.</p>
                      </div>
                    </div>
                  ))}
              </section>
            )}

            <div className="stage-actions">
              <span className="spacer" />
              <button
                className="btn"
                onClick={() => {
                  setAgentDone('skipped')
                  go(4)
                }}
                disabled={busy}
              >
                Skip for now
              </button>
              <button className="btn primary" onClick={saveCluster} disabled={busy}>
                {busy ? 'Saving…' : 'Save and continue'}
              </button>
            </div>
          </div>
        )}

        {step === 4 && (
          <div>
            {ssoOnly ? (
              <>
                <h1>Single sign-on is ready</h1>
                <p className="lede">
                  Sign in with your identity provider to finish. <span className="mono">{adminEmail}</span> gets the admin
                  role; set up DNS and agents after you sign in.
                </p>
                <div className="stage-actions">
                  <a className="btn primary" href="/api/auth/oidc/login">
                    Continue with single sign-on
                  </a>
                </div>
              </>
            ) : needsLogin ? (
              <>
                <h1>Setup complete</h1>
                <p className="lede">Sign in with the admin account you just created to set up DNS and agents.</p>
                <div className="stage-actions">
                  <button className="btn primary" onClick={onDone}>
                    Go to sign-in
                  </button>
                </div>
              </>
            ) : (
              <>
                <h1>You’re all set</h1>
                <p className="lede">
                  The control plane is ready. Single sign-on, metrics export and domain classification are in Settings
                  whenever you need them.
                </p>
                <div className="stage-actions">
                  <button className="btn primary" onClick={onDone}>
                    Open the overview
                  </button>
                </div>
              </>
            )}
          </div>
        )}
      </main>
    </div>
  )
}
