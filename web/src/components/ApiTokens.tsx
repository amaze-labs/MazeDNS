import { FormEvent, useEffect, useState } from 'react'
import { api, APIToken } from '../api'
import { TableStatusRow } from './tableKit'

// Expiry presets, in days (0 = never).
const EXPIRY_OPTIONS = [
  { days: 0, label: 'never expires' },
  { days: 30, label: 'expires in 30 days' },
  { days: 90, label: 'expires in 90 days' },
  { days: 365, label: 'expires in 1 year' },
]

function dateStr(unixSec: number): string {
  if (!unixSec) return '—'
  return new Date(unixSec * 1000).toLocaleString()
}

// ApiTokens manages bearer tokens for integrations (Settings → Access & SSO).
export default function ApiTokens() {
  const [tokens, setTokens] = useState<APIToken[]>([])
  const [loading, setLoading] = useState(true)
  const [err, setErr] = useState('')
  const [name, setName] = useState('')
  const [role, setRole] = useState<'readonly' | 'admin'>('readonly')
  const [days, setDays] = useState(0)
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
    try {
      const t = await api.createAPIToken(name.trim(), role, expires)
      setCreated({ name: t.name, token: t.token })
      setCopied(false)
      setName('')
      load()
    } catch (e: any) {
      setErr(e.message)
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
    <details className="settings-card" open>
      <summary>API tokens</summary>
      <p className="muted">
        Let integrations (an IPAM sync, scripts) call the API with <code>Authorization: Bearer &lt;token&gt;</code>{' '}
        instead of a user's password. A token can do what its role allows on DNS data — rewrites, forwarders, rules,
        lists, clients and read-only views — but never manages users, tokens, sign-in, credentials, backups or cluster
        nodes. Tokens keep working when password login is disabled for SSO, but never outrank their creator: they
        stop working if the creator's account is deleted, and act as readonly if the creator is no longer an admin.
        Each token is shown once, then stored hashed; revoking it takes effect on the next request.
      </p>
      {err && <div className="error">{err}</div>}
      <form className="row" onSubmit={submit}>
        <input
          placeholder="name (e.g. ipam-sync)"
          value={name}
          maxLength={64}
          required
          onChange={(e) => setName(e.target.value)}
        />
        <select value={role} onChange={(e) => setRole(e.target.value as 'readonly' | 'admin')} title="Role">
          <option value="readonly">readonly</option>
          <option value="admin">admin</option>
        </select>
        <select value={days} onChange={(e) => setDays(Number(e.target.value))} title="Expiry">
          {EXPIRY_OPTIONS.map((o) => (
            <option key={o.days} value={o.days}>
              {o.label}
            </option>
          ))}
        </select>
        <button type="submit" className="btn primary">
          Create token
        </button>
      </form>

      {created && (
        <div className="enroll">
          <div className="ok-msg">
            <strong>API token “{created.name}” — copy it now, it won't be shown again.</strong>{' '}
            <button className="btn ghost" onClick={copy}>
              {copied ? 'Copied' : 'Copy'}
            </button>{' '}
            <button className="btn ghost" onClick={() => setCreated(null)}>
              Dismiss
            </button>
          </div>
          <pre className="keybox">{created.token}</pre>
        </div>
      )}

      <div className="table-scroll">
        <table className="agents-table nowrap">
          <thead>
            <tr>
              <th>Token</th>
              <th>Name</th>
              <th>Role</th>
              <th>Last used</th>
              <th>Expires</th>
              <th>Created</th>
              <th></th>
            </tr>
          </thead>
          <tbody>
            {tokens.map((t) => (
              <tr key={t.id}>
                <td>
                  <code>{t.token_prefix}…</code>
                </td>
                <td>{t.name}</td>
                <td>
                  <span className={`badge ${t.role === 'admin' ? 'blocked' : 'info'}`}>{t.role}</span>
                </td>
                <td>{t.last_used_at ? dateStr(t.last_used_at) : <span className="muted">never</span>}</td>
                <td>
                  {!t.expires_at ? (
                    <span className="muted">never</span>
                  ) : t.expires_at <= now ? (
                    <span className="badge info">expired</span>
                  ) : (
                    dateStr(t.expires_at)
                  )}
                </td>
                <td>
                  {dateStr(t.created_at)}
                  {t.created_by ? ` · ${t.created_by}` : ''}
                </td>
                <td>
                  <button className="del" onClick={() => revoke(t)} title="Revoke token">
                    Revoke
                  </button>
                </td>
              </tr>
            ))}
            <TableStatusRow loading={loading} error={err} empty={tokens.length === 0} colSpan={7}>
              No API tokens yet.
            </TableStatusRow>
          </tbody>
        </table>
      </div>
    </details>
  )
}
