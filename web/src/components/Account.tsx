import { useEffect, useRef, useState, type FormEvent } from 'react'
import { api, type SessionUser, type User } from '../api'
import { PASSWORD_RULE, passwordPolicyError, passwordStrength } from '../passwordPolicy'
import { TableStatusRow } from './tableKit'
import Modal from './Modal'
import Avatar from './Avatar'
import { fileToAvatar } from '../avatar'
import { SKIP_AUTOLOGIN_KEY } from './Login'
import { CodeInput, MFASetupSteps, RecoveryCodes } from './MFA'
import '../styles/account.css'

const ROLE_LABEL: Record<string, string> = { admin: 'Administrator', readonly: 'Viewer' }
const roleLabel = (r: string) => ROLE_LABEL[r] || r
const sourceLabel = (s?: string) => (s === 'oidc' ? 'Single sign-on' : 'Local')

// PasswordMeter is the live strength read-out under a new-password field. It
// uses the same rule as the server, so "weak" means "will be refused".
export function PasswordMeter({ password }: { password: string }) {
  if (!password) return <small className="pw-hint">{PASSWORD_RULE}.</small>
  const st = passwordStrength(password)
  const k = st.level === 'weak' ? 'var(--block)' : st.level === 'ok' ? 'var(--warn)' : 'var(--ok)'
  return (
    <span className="pw-meter" aria-live="polite">
      <span className="meter">
        <i style={{ width: `${Math.round(st.fill * 100)}%`, ['--k' as string]: k }} />
      </span>
      <small style={{ color: k }}>{st.label}</small>
    </span>
  )
}

// TwoFactorCard is the signed-in local account's two-factor sign-in: set it up,
// replace the recovery codes, or turn it off (not while the policy requires it).
function TwoFactorCard({ me, onChange }: { me: SessionUser; onChange?: () => void }) {
  const [dialog, setDialog] = useState<'' | 'setup' | 'codes' | 'off'>('')
  const [codes, setCodes] = useState<string[] | null>(null)
  const [code, setCode] = useState('')
  const [pw, setPw] = useState('')
  const [err, setErr] = useState('')
  const [msg, setMsg] = useState('')
  const [busy, setBusy] = useState(false)
  const on = !!me.mfa_enabled

  const open = (d: typeof dialog) => {
    setDialog(d)
    setCodes(null)
    setCode('')
    setPw('')
    setErr('')
    setMsg('')
  }
  const close = () => {
    setDialog('')
    setCodes(null)
    onChange?.()
  }
  const newCodes = async (e: FormEvent) => {
    e.preventDefault()
    setBusy(true)
    setErr('')
    try {
      setCodes((await api.mfaRecoveryCodes(code)).recovery_codes)
    } catch (e: any) {
      setErr(e.message)
      setCode('')
    } finally {
      setBusy(false)
    }
  }
  const turnOff = async (e: FormEvent) => {
    e.preventDefault()
    setBusy(true)
    setErr('')
    try {
      await api.mfaDisable(pw, code)
      close()
      setMsg('Two-factor sign-in is off.')
    } catch (e: any) {
      setErr(e.message)
      setCode('')
    } finally {
      setBusy(false)
    }
  }

  return (
    <section className="card acct-mfa">
      <div>
        <h2>
          Two-factor sign-in <span className={`tag${on ? ' ok' : ''}`}>{on ? 'On' : 'Off'}</span>
        </h2>
        <p className="muted">
          {on
            ? 'Signing in asks for a code from your authenticator app after your password.'
            : me.mfa_required
            ? 'Required for local accounts on this control plane. You’ll be asked to set it up at your next sign-in, or do it now.'
            : 'Ask for a code from an authenticator app after your password, so a leaked password alone can’t sign in.'}
        </p>
        {msg && <div className="ok-msg">{msg}</div>}
      </div>
      <div className="mfa-actions">
        {on ? (
          <>
            <button className="btn sm" onClick={() => open('codes')}>
              New recovery codes
            </button>
            {!me.mfa_required && (
              <button className="btn sm quiet" onClick={() => open('off')}>
                Turn off
              </button>
            )}
          </>
        ) : (
          <button className="btn primary" onClick={() => open('setup')}>
            Set up
          </button>
        )}
      </div>

      {dialog === 'setup' && (
        <Modal kind="dialog" title={codes ? 'Save your recovery codes' : 'Set up two-factor sign-in'} onClose={close}>
          {codes ? (
            <RecoveryCodes codes={codes} onDone={close} doneLabel="Done" />
          ) : (
            <MFASetupSteps onEnabled={(c) => setCodes(c)} onCancel={close} />
          )}
        </Modal>
      )}
      {dialog === 'codes' && (
        <Modal kind="dialog" title="New recovery codes" onClose={close}>
          {codes ? (
            <RecoveryCodes codes={codes} onDone={close} doneLabel="Done" />
          ) : (
            <form className="mfa-setup" onSubmit={newCodes}>
              <p className="muted" style={{ margin: 0 }}>
                Your current recovery codes stop working.
              </p>
              {err && <div className="error">{err}</div>}
              <CodeInput value={code} onChange={setCode} />
              <div className="mfa-actions">
                <span className="spacer" />
                <button type="submit" className="btn primary" disabled={busy || code.length !== 6}>
                  {busy ? 'Checking…' : 'Make new codes'}
                </button>
              </div>
            </form>
          )}
        </Modal>
      )}
      {dialog === 'off' && (
        <Modal kind="dialog" title="Turn off two-factor sign-in?" onClose={close}>
          <form className="mfa-setup" onSubmit={turnOff}>
            <p className="muted" style={{ margin: 0 }}>
              Your password alone will sign you in again, and your recovery codes stop working.
            </p>
            {err && <div className="error">{err}</div>}
            <label className="field">
              <span>Password</span>
              <input type="password" autoComplete="current-password" autoFocus value={pw} onChange={(e) => setPw(e.target.value)} />
            </label>
            <CodeInput value={code} onChange={setCode} allowRecovery autoFocus={false} />
            <div className="mfa-actions">
              <span className="spacer" />
              <button type="submit" className="btn danger solid" disabled={busy || !pw || code.trim().length < 6}>
                {busy ? 'Turning off…' : 'Turn off'}
              </button>
            </div>
          </form>
        </Modal>
      )}
    </section>
  )
}

export default function Account({
  me,
  oidc = false,
  onProfileChange,
}: {
  me: SessionUser | null
  oidc?: boolean
  onProfileChange?: () => void // reload the signed-in account (its picture changed)
}) {
  // With SSO enabled, accounts and roles are governed by the identity provider's
  // groups, so local user management is hidden.
  const isAdmin = me?.role === 'admin' && !oidc

  // Change own password
  const [cur, setCur] = useState('')
  const [next, setNext] = useState('')
  const [confirm, setConfirm] = useState('')
  const [pwErr, setPwErr] = useState('')
  const [pwMsg, setPwMsg] = useState('')
  const [pwBusy, setPwBusy] = useState(false)

  // User management (admin)
  const [users, setUsers] = useState<User[]>([])
  const [usersLoaded, setUsersLoaded] = useState(false)
  const [nu, setNu] = useState({ username: '', password: '', role: 'readonly' })
  const [uErr, setUErr] = useState('')
  const [uMsg, setUMsg] = useState('')
  const [adding, setAdding] = useState(false)

  // Dialogs: reset someone's password, delete someone.
  const [resetFor, setResetFor] = useState<User | null>(null)
  const [resetPw, setResetPw] = useState('')
  const [resetErr, setResetErr] = useState('')
  const [delFor, setDelFor] = useState<User | null>(null)
  const [mfaResetFor, setMfaResetFor] = useState<User | null>(null)
  const [busy, setBusy] = useState(false)
  // Profile picture: upload (resized in the browser) or remove.
  const fileRef = useRef<HTMLInputElement>(null)
  const [picBusy, setPicBusy] = useState(false)
  const [picErr, setPicErr] = useState('')
  const pickPicture = async (file?: File) => {
    if (!file) return
    setPicBusy(true)
    setPicErr('')
    try {
      await api.setAvatar(await fileToAvatar(file))
      onProfileChange?.()
    } catch (e: any) {
      setPicErr(e.message)
    } finally {
      setPicBusy(false)
      if (fileRef.current) fileRef.current.value = ''
    }
  }
  const removePicture = async () => {
    setPicBusy(true)
    setPicErr('')
    try {
      await api.removeAvatar()
      onProfileChange?.()
    } catch (e: any) {
      setPicErr(e.message)
    } finally {
      setPicBusy(false)
    }
  }

  const loadUsers = () => {
    if (!isAdmin) return
    api
      .users()
      .then((us) => {
        setUsers(us)
        setUsersLoaded(true)
      })
      .catch((e) => setUErr(e.message))
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
      setPwErr('The new passwords don’t match.')
      return
    }
    const policyErr = passwordPolicyError(next)
    if (policyErr) {
      setPwErr(policyErr)
      return
    }
    setPwBusy(true)
    try {
      await api.changePassword(cur, next)
      setCur('')
      setNext('')
      setConfirm('')
      setPwMsg('Password changed.')
    } catch (e: any) {
      setPwErr(e.message)
    } finally {
      setPwBusy(false)
    }
  }

  const createUser = async (e: FormEvent) => {
    e.preventDefault()
    setUErr('')
    setUMsg('')
    const policyErr = passwordPolicyError(nu.password)
    if (policyErr) {
      setUErr(policyErr)
      return
    }
    try {
      await api.createUser(nu.username.trim(), nu.password, nu.role)
      setNu({ username: '', password: '', role: 'readonly' })
      setUMsg(`Added ${nu.username.trim()} as ${roleLabel(nu.role).toLowerCase()}.`)
      setAdding(false)
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
      setUMsg(`${u.username} is now ${roleLabel(role).toLowerCase()}. Their sessions were signed out.`)
      loadUsers()
    } catch (e: any) {
      setUErr(e.message)
      loadUsers()
    }
  }

  const doReset = async (e: FormEvent) => {
    e.preventDefault()
    if (!resetFor) return
    const policyErr = passwordPolicyError(resetPw)
    if (policyErr) {
      setResetErr(policyErr)
      return
    }
    setBusy(true)
    setResetErr('')
    try {
      await api.resetUserPassword(resetFor.id, resetPw)
      setUErr('')
      setUMsg(`Password reset for ${resetFor.username}. Their sessions were signed out.`)
      setResetFor(null)
    } catch (e: any) {
      setResetErr(e.message)
    } finally {
      setBusy(false)
    }
  }

  const doDelete = async () => {
    if (!delFor) return
    setBusy(true)
    setUErr('')
    setUMsg('')
    try {
      await api.deleteUser(delFor.id)
      setUMsg(`Removed ${delFor.username}.`)
      loadUsers()
    } catch (e: any) {
      setUErr(e.message)
    } finally {
      setBusy(false)
      setDelFor(null)
    }
  }

  const doMfaReset = async () => {
    if (!mfaResetFor) return
    setBusy(true)
    setUErr('')
    setUMsg('')
    try {
      await api.resetUserMFA(mfaResetFor.id)
      setUMsg(`Two-factor sign-in reset for ${mfaResetFor.username}. Their sessions were signed out.`)
      loadUsers()
    } catch (e: any) {
      setUErr(e.message)
    } finally {
      setBusy(false)
      setMfaResetFor(null)
    }
  }

  const signOut = async () => {
    // Keep SSO auto-login from bouncing straight back in after signing out.
    sessionStorage.setItem(SKIP_AUTOLOGIN_KEY, '1')
    await api.logout().catch(() => {})
    window.location.assign('/')
  }

  // SSO (OIDC) accounts have no local password — managed by the identity provider.
  const isSSO = me?.source === 'oidc'

  return (
    <div className="pg-account">
      <header className="page-head">
        <h1>Account</h1>
        <span className="spacer" />
        <button className="btn" onClick={signOut}>
          Sign out
        </button>
      </header>
      <p className="intro">
        {me?.role === 'admin' ? 'Your sign-in and, as an administrator, everyone else’s.' : 'Your sign-in.'}
      </p>

      <section className="card acct-card">
        <div className="profile">
          <Avatar name={me?.username || '?'} url={me?.avatar_url} size={56} />
          <div className="who">
            <b>{me?.username}</b>
            <span className="muted">
              {roleLabel(me?.role || '')} · {isSSO ? 'single sign-on account' : 'local account'}
            </span>
          </div>
          <p className="muted small role-note">
            {me?.role === 'admin'
              ? 'Administrators can change settings, rules, resolvers and people.'
              : 'Viewers see everything but can’t change settings, rules or resolvers.'}
          </p>
          <div className="pic-actions">
            {me?.can_upload_avatar ? (
              <>
                <input
                  ref={fileRef}
                  type="file"
                  accept="image/jpeg,image/png,image/webp"
                  hidden
                  onChange={(e) => pickPicture(e.target.files?.[0])}
                />
                <button type="button" className="btn sm" disabled={picBusy} onClick={() => fileRef.current?.click()}>
                  {picBusy ? 'Saving…' : me.has_uploaded_avatar ? 'Change picture' : 'Upload a picture'}
                </button>
                {me.has_uploaded_avatar && (
                  <button type="button" className="btn sm quiet" disabled={picBusy} onClick={removePicture}>
                    Remove
                  </button>
                )}
                <span className="muted small">
                  {isSSO && !me.has_uploaded_avatar ? 'Replaces the picture from your identity provider.' : 'JPEG, PNG or WebP; cropped to a square.'}
                </span>
              </>
            ) : (
              isSSO && <span className="muted small">Your picture comes from your identity provider.</span>
            )}
          </div>
          {picErr && <div className="error pic-err">{picErr}</div>}
        </div>

        <div className="pw">
          <h2>{isSSO ? 'Password' : 'Change password'}</h2>
          {isSSO ? (
            <p className="muted">
              Your account is managed by single sign-on, so there is no password to change here. Change it with your
              identity provider.
            </p>
          ) : (
            <form className="pw-form" onSubmit={changePw}>
              {pwErr && <div className="error">{pwErr}</div>}
              {pwMsg && <div className="ok-msg">{pwMsg}</div>}
              <label className="field">
                <span>Current password</span>
                <input type="password" autoComplete="current-password" value={cur} onChange={(e) => setCur(e.target.value)} />
              </label>
              <label className="field">
                <span>New password</span>
                <input type="password" autoComplete="new-password" value={next} onChange={(e) => setNext(e.target.value)} />
                <PasswordMeter password={next} />
              </label>
              <label className="field">
                <span>Confirm new password</span>
                <input
                  type="password"
                  autoComplete="new-password"
                  value={confirm}
                  onChange={(e) => setConfirm(e.target.value)}
                />
                {confirm && next !== confirm && <small className="bad-text">Doesn’t match yet.</small>}
              </label>
              <div>
                <button type="submit" className="btn primary" disabled={pwBusy || !cur || !next || !confirm}>
                  {pwBusy ? 'Changing…' : 'Change password'}
                </button>
              </div>
            </form>
          )}
        </div>
      </section>

      {me && !isSSO && me.source !== 'token' && <TwoFactorCard
          me={me}
          onChange={() => {
            onProfileChange?.()
            loadUsers() // the people table shows who has it on
          }}
        />}

      {oidc && me?.role === 'admin' && (
        <>
          <h2 className="section">People</h2>
          <div className="callout">
            <div>
              <b>Managed by your identity provider</b>
              <p>Single sign-on is on, so accounts and roles come from your identity provider’s groups.</p>
            </div>
          </div>
        </>
      )}

      {isAdmin && (
        <>
          <div className="people-head">
            <div>
              <h2 className="section">People</h2>
              <p className="section">Viewers see everything but can’t change settings, rules or resolvers.</p>
            </div>
            <span className="spacer" />
            {!adding && (
              <button className="btn" onClick={() => setAdding(true)}>
                Add person
              </button>
            )}
          </div>
          {uErr && <div className="error">{uErr}</div>}
          {uMsg && <div className="ok-msg">{uMsg}</div>}
          <section className="card flush">
            {adding && (
              <form className="add-user" onSubmit={createUser}>
                <label className="field">
                  <span>Username</span>
                  <input
                    autoFocus
                    autoComplete="off"
                    value={nu.username}
                    onChange={(e) => setNu({ ...nu, username: e.target.value })}
                  />
                </label>
                <label className="field">
                  <span>Password</span>
                  <input
                    type="password"
                    autoComplete="new-password"
                    value={nu.password}
                    onChange={(e) => setNu({ ...nu, password: e.target.value })}
                  />
                  <PasswordMeter password={nu.password} />
                </label>
                <label className="field">
                  <span>Role</span>
                  <select value={nu.role} onChange={(e) => setNu({ ...nu, role: e.target.value })}>
                    <option value="readonly">Viewer</option>
                    <option value="admin">Administrator</option>
                  </select>
                </label>
                <div className="add-actions">
                  <button type="submit" className="btn primary" disabled={!nu.username.trim() || !nu.password}>
                    Add
                  </button>
                  <button
                    type="button"
                    className="btn quiet"
                    onClick={() => {
                      setAdding(false)
                      setNu({ username: '', password: '', role: 'readonly' })
                    }}
                  >
                    Cancel
                  </button>
                </div>
              </form>
            )}
            <table className="stackable">
              <thead>
                <tr>
                  <th>Person</th>
                  <th>Role</th>
                  <th className="hide-sm">Sign-in</th>
                  <th></th>
                </tr>
              </thead>
              <tbody>
                {users.map((u) => (
                  <tr key={u.id}>
                    <td className="lead">
                      <span className="person">
                        <Avatar name={u.username} url={u.avatar_url} size={28} />
                        <b className="uname">{u.username}</b>
                      </span>
                      {me?.id === u.id && <span className="muted"> (you)</span>}
                    </td>
                    <td className="lead-r">
                      {u.source === 'local' && me?.id !== u.id ? (
                        <select
                          className="role-select"
                          aria-label={`Role of ${u.username}`}
                          value={u.role}
                          onChange={(e) => changeRole(u, e.target.value)}
                        >
                          <option value="admin">Administrator</option>
                          <option value="readonly">Viewer</option>
                        </select>
                      ) : (
                        <span className={`tag${u.role === 'admin' ? ' ok' : ''}`}>{roleLabel(u.role)}</span>
                      )}
                    </td>
                    <td className="hide-sm">
                      {sourceLabel(u.source)}
                      {u.mfa_enabled && (
                        <span className="tag ok mfa-tag" title="Two-factor sign-in is on">
                          2FA
                        </span>
                      )}
                    </td>
                    <td className="actions">
                      {u.source === 'local' && (
                        <button
                          className="btn sm"
                          onClick={() => {
                            setResetFor(u)
                            setResetPw('')
                            setResetErr('')
                          }}
                        >
                          Reset password
                        </button>
                      )}
                      {u.source === 'local' && u.mfa_enabled && me?.id !== u.id && (
                        <button className="btn sm" onClick={() => setMfaResetFor(u)}>
                          Reset 2FA
                        </button>
                      )}
                      {me?.id !== u.id && (
                        <button className="btn sm quiet" onClick={() => setDelFor(u)}>
                          Remove
                        </button>
                      )}
                    </td>
                  </tr>
                ))}
                <TableStatusRow loading={!usersLoaded} error={uErr} empty={users.length === 0} colSpan={4}>
                  No people yet
                </TableStatusRow>
              </tbody>
            </table>
          </section>
        </>
      )}

      {resetFor && (
        <Modal
          kind="dialog"
          title={`Reset ${resetFor.username}’s password`}
          onClose={() => setResetFor(null)}
          footer={
            <>
              <span className="spacer" />
              <button className="btn quiet" onClick={() => setResetFor(null)}>
                Cancel
              </button>
              <button className="btn primary" form="reset-pw" type="submit" disabled={busy || !resetPw}>
                {busy ? 'Resetting…' : 'Reset password'}
              </button>
            </>
          }
        >
          <form id="reset-pw" className="pg-account-dialog" onSubmit={doReset}>
            <p className="muted" style={{ margin: 0 }}>
              They’ll be signed out everywhere and need the new password to sign back in.
            </p>
            {resetErr && <div className="error">{resetErr}</div>}
            <label className="field">
              <span>New password</span>
              <input
                type="password"
                autoComplete="new-password"
                autoFocus
                value={resetPw}
                onChange={(e) => setResetPw(e.target.value)}
              />
              <PasswordMeter password={resetPw} />
            </label>
          </form>
        </Modal>
      )}

      {mfaResetFor && (
        <Modal
          kind="dialog"
          title={`Reset ${mfaResetFor.username}’s two-factor sign-in?`}
          onClose={() => setMfaResetFor(null)}
          footer={
            <>
              <span className="spacer" />
              <button className="btn quiet" onClick={() => setMfaResetFor(null)}>
                Cancel
              </button>
              <button className="btn danger solid" onClick={doMfaReset} disabled={busy}>
                {busy ? 'Resetting…' : 'Reset'}
              </button>
            </>
          }
        >
          <p className="muted" style={{ margin: 0 }}>
            For someone who lost their authenticator and recovery codes. They’re signed out everywhere and sign in with
            their password alone, or set two-factor sign-in up again if it’s required.
          </p>
        </Modal>
      )}

      {delFor && (
        <Modal
          kind="dialog"
          title={`Remove ${delFor.username}?`}
          onClose={() => setDelFor(null)}
          footer={
            <>
              <span className="spacer" />
              <button className="btn quiet" onClick={() => setDelFor(null)}>
                Cancel
              </button>
              <button className="btn danger solid" onClick={doDelete} disabled={busy}>
                {busy ? 'Removing…' : 'Remove'}
              </button>
            </>
          }
        >
          <p className="muted" style={{ margin: 0 }}>
            Their account and sessions are deleted. This can’t be undone.
          </p>
        </Modal>
      )}
    </div>
  )
}
