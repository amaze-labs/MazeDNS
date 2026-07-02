import { useState, type FormEvent } from 'react'
import { api, type Settings } from '../api'

// Setup is the first-boot wizard shown when the control plane has no admin yet.
// Step 1 (create admin) is guarded by the one-time token printed to the container
// log; it completes setup atomically and logs the new admin in, so the later
// optional steps run authenticated.
export default function Setup({ onDone }: { onDone: () => void }) {
  const [step, setStep] = useState(1)
  const [err, setErr] = useState('')
  const [busy, setBusy] = useState(false)

  // Step 1 — admin.
  const [token, setToken] = useState('')
  const [username, setUsername] = useState('admin')
  const [password, setPassword] = useState('')
  const [confirm, setConfirm] = useState('')

  // Step 2 — DNS.
  const [upstreams, setUpstreams] = useState('1.1.1.1:53, 9.9.9.9:53')
  const [blockResponse, setBlockResponse] = useState('nxdomain')

  // Step 3 — cluster.
  const [requireApproval, setRequireApproval] = useState(false)
  const [enrollKey, setEnrollKey] = useState('')

  const pwScore = passwordScore(password)

  const createAdmin = async (e: FormEvent) => {
    e.preventDefault()
    if (password !== confirm) return setErr('passwords do not match')
    if (pwScore.level === 'weak') return setErr(pwScore.hint)
    setBusy(true)
    setErr('')
    try {
      await api.setupComplete(token.trim(), username.trim(), password)
      setStep(2)
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

  const cpURL = `${window.location.protocol}//${window.location.hostname}${
    window.location.port ? ':' + window.location.port : ''
  }`
  const agentSnippet = `-e MAZEDNS_CP_URL=${cpURL} \\
-e MAZEDNS_JOIN_TOKEN=${enrollKey || '<enrollment-key>'}`

  return (
    <div className="setup-wrap">
      <div className="setup-card">
        <div className="setup-head">
          <span className="brand-logo">🧭</span>
          <h1>Welcome to MazeDNS</h1>
          <p className="muted">Let’s set up your control plane. This takes about a minute.</p>
        </div>
        <ol className="setup-steps">
          {['Admin', 'DNS', 'Cluster', 'Done'].map((label, i) => (
            <li key={label} className={step === i + 1 ? 'active' : step > i + 1 ? 'done' : ''}>
              <span className="setup-step-num">{step > i + 1 ? '✓' : i + 1}</span>
              {label}
            </li>
          ))}
        </ol>

        {err && <div className="error">{err}</div>}

        {step === 1 && (
          <form onSubmit={createAdmin} className="setup-body">
            <p className="muted">
              Paste the <strong>setup token</strong> printed in the container log (<code>docker logs</code>), then create
              your admin account.
            </p>
            <label>
              Setup token
              <input value={token} onChange={(e) => setToken(e.target.value)} placeholder="from the server log" autoFocus />
            </label>
            <label>
              Username
              <input value={username} onChange={(e) => setUsername(e.target.value)} />
            </label>
            <label>
              Password
              <input type="password" value={password} onChange={(e) => setPassword(e.target.value)} />
            </label>
            {password && (
              <div className={`pw-meter ${pwScore.level}`}>
                <span /> <small>{pwScore.hint}</small>
              </div>
            )}
            <label>
              Confirm password
              <input type="password" value={confirm} onChange={(e) => setConfirm(e.target.value)} />
            </label>
            <button className="btn primary" disabled={busy}>
              {busy ? 'Creating…' : 'Create admin & continue'}
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
                  <strong>Enrollment key — shown once.</strong> Start an agent with:
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
            <div className="ok-msg">
              <strong>All set!</strong> Your control plane is ready. Configure SSO, metrics, and classification anytime in
              Settings.
            </div>
            <button className="btn primary" onClick={onDone}>
              Go to dashboard
            </button>
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
