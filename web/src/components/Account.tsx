import { useEffect, useState, type FormEvent } from 'react'
import { api, type SessionUser, type User } from '../api'

export default function Account({ me }: { me: SessionUser | null }) {
  const isAdmin = me?.role === 'admin'

  // Change own password
  const [cur, setCur] = useState('')
  const [next, setNext] = useState('')
  const [confirm, setConfirm] = useState('')
  const [pwErr, setPwErr] = useState('')
  const [pwMsg, setPwMsg] = useState('')

  // User management (admin)
  const [users, setUsers] = useState<User[]>([])
  const [nu, setNu] = useState({ username: '', password: '', role: 'readonly' })
  const [uErr, setUErr] = useState('')
  const [uMsg, setUMsg] = useState('')

  const loadUsers = () => {
    if (isAdmin) api.users().then(setUsers).catch((e) => setUErr(e.message))
  }
  useEffect(() => {
    loadUsers()
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [isAdmin])

  const changePw = async (e: FormEvent) => {
    e.preventDefault()
    setPwErr('')
    setPwMsg('')
    if (next !== confirm) {
      setPwErr('New passwords do not match')
      return
    }
    try {
      await api.changePassword(cur, next)
      setCur('')
      setNext('')
      setConfirm('')
      setPwMsg('Password updated.')
    } catch (e: any) {
      setPwErr(e.message)
    }
  }

  const createUser = async (e: FormEvent) => {
    e.preventDefault()
    setUErr('')
    setUMsg('')
    try {
      await api.createUser(nu.username.trim(), nu.password, nu.role)
      setNu({ username: '', password: '', role: 'readonly' })
      setUMsg(`User “${nu.username.trim()}” created.`)
      loadUsers()
    } catch (e: any) {
      setUErr(e.message)
    }
  }

  const changeRole = async (u: User, role: string) => {
    setUErr('')
    setUMsg('')
    try {
      await api.setUserRole(u.id, role)
      setUMsg(`${u.username} is now ${role}. Their sessions were revoked.`)
      loadUsers()
    } catch (e: any) {
      setUErr(e.message)
      loadUsers()
    }
  }

  const resetPw = async (u: User) => {
    const p = window.prompt(`New password for ${u.username} (min 8 characters):`)
    if (!p) return
    setUErr('')
    setUMsg('')
    try {
      await api.resetUserPassword(u.id, p)
      setUMsg(`Password reset for ${u.username}. Their sessions were revoked.`)
    } catch (e: any) {
      setUErr(e.message)
    }
  }

  const del = async (u: User) => {
    if (!window.confirm(`Delete user “${u.username}”? This cannot be undone.`)) return
    setUErr('')
    setUMsg('')
    try {
      await api.deleteUser(u.id)
      loadUsers()
    } catch (e: any) {
      setUErr(e.message)
    }
  }

  // SSO (OIDC) accounts have no local password — managed by the identity provider.
  const isSSO = me?.source === 'oidc'

  return (
    <div className="settings">
      <h2>Account</h2>

      {isSSO ? (
        <section className="settings-card">
          <h3>Password</h3>
          <p className="muted" style={{ textAlign: 'left' }}>
            Your account is managed by single sign-on, so there is no password to change here. Update it with your SSO
            provider.
          </p>
        </section>
      ) : (
        <section className="settings-card">
          <h3>Change my password</h3>
          {pwErr && <div className="error">{pwErr}</div>}
          {pwMsg && <div className="ok-msg">{pwMsg}</div>}
          <form onSubmit={changePw}>
            <div className="field">
              <label>Current password</label>
              <input type="password" autoComplete="current-password" value={cur} onChange={(e) => setCur(e.target.value)} />
            </div>
            <div className="field">
              <label>New password (min 8 characters)</label>
              <input type="password" autoComplete="new-password" value={next} onChange={(e) => setNext(e.target.value)} />
            </div>
            <div className="field">
              <label>Confirm new password</label>
              <input
                type="password"
                autoComplete="new-password"
                value={confirm}
                onChange={(e) => setConfirm(e.target.value)}
              />
            </div>
            <button type="submit" className="btn primary">
              Update password
            </button>
          </form>
        </section>
      )}

      {isAdmin && (
        <section className="settings-card">
          <h3>Users</h3>
          {uErr && <div className="error">{uErr}</div>}
          {uMsg && <div className="ok-msg">{uMsg}</div>}
          <table>
            <thead>
              <tr>
                <th>User</th>
                <th>Role</th>
                <th>Source</th>
                <th></th>
              </tr>
            </thead>
            <tbody>
              {users.map((u) => (
                <tr key={u.id}>
                  <td>
                    {u.username}
                    {me?.id === u.id && <span className="muted"> (you)</span>}
                  </td>
                  <td>
                    {u.source === 'local' ? (
                      <select value={u.role} onChange={(e) => changeRole(u, e.target.value)}>
                        <option value="admin">admin</option>
                        <option value="readonly">readonly</option>
                      </select>
                    ) : (
                      <span className={`role-badge ${u.role}`}>{u.role}</span>
                    )}
                  </td>
                  <td>
                    <span className="muted">{u.source}</span>
                  </td>
                  <td>
                    <div className="actions">
                      {u.source === 'local' && (
                        <button className="btn ghost" onClick={() => resetPw(u)}>
                          Reset password
                        </button>
                      )}
                      {me?.id !== u.id && (
                        <button className="del" onClick={() => del(u)}>
                          ✕
                        </button>
                      )}
                    </div>
                  </td>
                </tr>
              ))}
              {users.length === 0 && (
                <tr>
                  <td colSpan={4} className="muted">
                    No users
                  </td>
                </tr>
              )}
            </tbody>
          </table>

          <h3 style={{ marginTop: 20 }}>Add user</h3>
          <form className="row" onSubmit={createUser}>
            <input
              placeholder="username"
              value={nu.username}
              onChange={(e) => setNu({ ...nu, username: e.target.value })}
            />
            <input
              type="password"
              autoComplete="new-password"
              placeholder="password (min 8)"
              value={nu.password}
              onChange={(e) => setNu({ ...nu, password: e.target.value })}
            />
            <select value={nu.role} onChange={(e) => setNu({ ...nu, role: e.target.value })}>
              <option value="readonly">readonly</option>
              <option value="admin">admin</option>
            </select>
            <button type="submit" className="btn primary">
              Create
            </button>
          </form>
        </section>
      )}
    </div>
  )
}
