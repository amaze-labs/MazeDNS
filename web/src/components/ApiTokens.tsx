import { FormEvent, useEffect, useState } from 'react'
import { api, APIToken } from '../api'
import { TableStatusRow } from './tableKit'

// Expiry presets, in days (0 = never).
const EXPIRY_OPTIONS = [
  { days: 0, label: 'Never' },
  { days: 30, label: 'In 30 days' },
  { days: 90, label: 'In 90 days' },
  { days: 365, label: 'In 1 year' },
]

function dateStr(unixSec: number): string {
  return new Date(unixSec * 1000).toLocaleString()
}

// ApiTokens manages bearer tokens for integrations (Settings → Access). It is a
// settings group of its own; changes apply immediately, outside the save bar.
export default function ApiTokens() {
  const [tokens, setTokens] = useState<APIToken[]>([])
  const [loading, setLoading] = useState(true)
  const [err, setErr] = useState('')
  const [name, setName] = useState('')
  const [role, setRole] = useState<'readonly' | 'admin'>('readonly')
  const [days, setDays] = useState(0)
  const [busy, setBusy] = useState(false)
  const [created, setCreated] = useState<{ name: string; token: string } | null>(null)
  const [copied, setCopied] = useState(false)

  const load = () =>
    api
      .apiTokens()
      .then((t) => {
        setTokens(t)
        setErr('')
      })
      .catch((e) => setErr(e.message))
      .finally(() => setLoading(false))

  useEffect(() => {
    load()
  }, [])

  const submit = async (e: FormEvent) => {
    e.preventDefault()
    const expires = days ? Math.floor(Date.now() / 1000) + days * 86400 : 0
    setBusy(true)
    try {
      const t = await api.createAPIToken(name.trim(), role, expires)
      setCreated({ name: t.name, token: t.token })
      setCopied(false)
      setName('')
      load()
    } catch (e: any) {
      setErr(e.message)
    } finally {
      setBusy(false)
    }
  }

  const revoke = async (t: APIToken) => {
    if (!window.confirm(`Revoke API token “${t.name}”? Integrations using it stop working immediately.`)) return
    try {
      await api.deleteAPIToken(t.id)
      load()
    } catch (e: any) {
      setErr(e.message)
    }
  }

  const copy = async () => {
    if (!created) return
    try {
      await navigator.clipboard.writeText(created.token)
      setCopied(true)
    } catch {
      /* clipboard unavailable: the token stays visible to copy by hand */
    }
  }

  const now = Date.now() / 1000

  return (
    <section className="sg">
      <header>
        <h2>API tokens</h2>
        <p>
          Let integrations (an IPAM sync, scripts) call the API with <code>Authorization: Bearer &lt;token&gt;</code> instead of
          a person’s password.
        </p>
      </header>
      <div className="sg-body">
        <p className="hint" style={{ margin: 0 }}>
          A token can do what its role allows on DNS data — rewrites, forwarders, rules, lists, clients and read-only views — but
          never manages people, tokens, sign-in, credentials, backups or agents. It keeps working when password sign-in is off
          for SSO, but never outranks its creator: it stops if their account is removed, and acts as a viewer if they are no
          longer an administrator. Each token is shown once, then stored hashed; revoking it applies on the next request.
        </p>

        <form onSubmit={submit}>
          <div className="row3">
            <label className="field">
              <span>Name</span>
              <input placeholder="ipam-sync" value={name} maxLength={64} required onChange={(e) => setName(e.target.value)} />
            </label>
            <label className="field">
              <span>Role</span>
              <select value={role} onChange={(e) => setRole(e.target.value as 'readonly' | 'admin')}>
                <option value="readonly">Viewer</option>
                <option value="admin">Administrator</option>
              </select>
            </label>
            <label className="field">
              <span>Expires</span>
              <select value={days} onChange={(e) => setDays(Number(e.target.value))}>
                {EXPIRY_OPTIONS.map((o) => (
                  <option key={o.days} value={o.days}>
                    {o.label}
                  </option>
                ))}
              </select>
            </label>
          </div>
          <div className="row">
            <button type="submit" className="btn sm" disabled={busy || !name.trim()}>
              Make a token
            </button>
            <span className="hint" style={{ margin: 0 }}>
              Applies immediately.
            </span>
          </div>
        </form>

        {created && (
          <div className="callout ok">
            <div className="grow" style={{ minWidth: 0 }}>
              <b>Copy the token for “{created.name}” now. It won’t be shown again.</b>
              <pre className="codebox">{created.token}</pre>
              <div className="row">
                <button type="button" className="btn sm" onClick={copy}>
                  {copied ? 'Copied' : 'Copy'}
                </button>
                <button type="button" className="btn sm quiet" onClick={() => setCreated(null)}>
                  Done
                </button>
              </div>
            </div>
          </div>
        )}

        <table className="stackable">
          <thead>
            <tr>
              <th>Token</th>
              <th>Role</th>
              <th className="hide-sm">Last used</th>
              <th className="hide-sm">Expires</th>
              <th></th>
            </tr>
          </thead>
          <tbody>
            {tokens.map((t) => (
              <tr key={t.id}>
                <td className="lead">
                  <b>{t.name}</b> <code className="muted">{t.token_prefix}…</code>
                  <small className="muted" style={{ display: 'block' }}>
                    Made {dateStr(t.created_at)}
                    {t.created_by ? ` by ${t.created_by}` : ''}
                  </small>
                </td>
                <td className="lead-r">
                  <span className={`tag${t.role === 'admin' ? ' warn' : ''}`}>{t.role === 'admin' ? 'Administrator' : 'Viewer'}</span>
                </td>
                <td className="hide-sm">{t.last_used_at ? dateStr(t.last_used_at) : <span className="muted">Never</span>}</td>
                <td className="hide-sm">
                  {!t.expires_at ? (
                    <span className="muted">Never</span>
                  ) : t.expires_at <= now ? (
                    <span className="tag">Expired</span>
                  ) : (
                    dateStr(t.expires_at)
                  )}
                </td>
                <td className="actions">
                  <button type="button" className="btn sm quiet" onClick={() => revoke(t)}>
                    Revoke
                  </button>
                </td>
              </tr>
            ))}
            <TableStatusRow loading={loading} error={err} empty={tokens.length === 0} colSpan={5}>
              No API tokens yet
            </TableStatusRow>
          </tbody>
        </table>
      </div>
    </section>
  )
}
