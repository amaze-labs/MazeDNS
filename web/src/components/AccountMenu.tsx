import { useEffect, useState } from 'react'
import type { SessionUser } from '../api'
import Avatar from './Avatar'

// AccountMenu is the top-bar account chip — the picture, name and role as one
// button — that opens a menu with the account's details, its settings and
// sign out. Esc or a click outside closes it.
export default function AccountMenu({
  user,
  roleLabel,
  authEnabled,
  onSettings,
  onLogout,
}: {
  user: SessionUser
  roleLabel: string
  authEnabled: boolean
  onSettings: () => void
  onLogout: () => void
}) {
  const [open, setOpen] = useState(false)
  useEffect(() => {
    if (!open) return
    const onKey = (e: KeyboardEvent) => e.key === 'Escape' && setOpen(false)
    window.addEventListener('keydown', onKey)
    return () => window.removeEventListener('keydown', onKey)
  }, [open])
  return (
    <div className="acct">
      <button
        className={`acct-trigger ${open ? 'open' : ''}`}
        onClick={() => setOpen((o) => !o)}
        aria-haspopup="menu"
        aria-expanded={open}
        aria-label={`Account: ${user.username}`}
      >
        <Avatar name={user.username} url={user.avatar_url} className="acct-avatar" />
        <span className="tb-user">
          <b>{user.username}</b>
          <small>{roleLabel}</small>
        </span>
      </button>
      {open && (
        <>
          <div className="acct-backdrop" onClick={() => setOpen(false)} />
          <div className="acct-menu" role="menu">
            <div className="acct-head">
              <Avatar name={user.username} url={user.avatar_url} size={40} />
              <div className="acct-id">
                <div className="acct-name">{user.username}</div>
                <span className={`role-badge ${user.role}`}>{roleLabel}</span>
              </div>
            </div>
            {authEnabled && (
              <>
                <div className="acct-divider" />
                <button
                  className="acct-item"
                  role="menuitem"
                  onClick={() => {
                    setOpen(false)
                    onSettings()
                  }}
                >
                  <span className="acct-ic">⚙</span> Account settings
                </button>
                <button
                  className="acct-item danger"
                  role="menuitem"
                  onClick={() => {
                    setOpen(false)
                    onLogout()
                  }}
                >
                  <span className="acct-ic">⎋</span> Log out
                </button>
              </>
            )}
          </div>
        </>
      )}
    </div>
  )
}
