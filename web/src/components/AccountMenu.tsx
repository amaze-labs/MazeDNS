import { useState } from 'react'
import type { SessionUser } from '../api'

// AccountMenu is the top-bar avatar that opens a dropdown with the signed-in
// user's basic info, a link to account settings, and logout.
export default function AccountMenu({
  user,
  authEnabled,
  onSettings,
  onLogout,
}: {
  user: SessionUser
  authEnabled: boolean
  onSettings: () => void
  onLogout: () => void
}) {
  const [open, setOpen] = useState(false)
  const [imgOk, setImgOk] = useState(true)
  const initial = (user.username.trim()[0] || '?').toUpperCase()
  // Show the OIDC profile picture when present; fall back to the initial if it's
  // missing or fails to load.
  const avatar = user.avatar_url && imgOk ? user.avatar_url : ''
  const Face = ({ cls }: { cls: string }) =>
    avatar ? (
      <img className={cls} src={avatar} alt="" referrerPolicy="no-referrer" onError={() => setImgOk(false)} />
    ) : (
      <div className={cls}>{initial}</div>
    )
  return (
    <div className="acct">
      <button
        className={`acct-avatar ${open ? 'open' : ''} ${avatar ? 'has-img' : ''}`}
        onClick={() => setOpen((o) => !o)}
        title={user.username}
        aria-label="Account menu"
      >
        {avatar ? <img src={avatar} alt="" referrerPolicy="no-referrer" onError={() => setImgOk(false)} /> : initial}
      </button>
      {open && (
        <>
          <div className="acct-backdrop" onClick={() => setOpen(false)} />
          <div className="acct-menu">
            <div className="acct-head">
              <Face cls="acct-avatar lg" />
              <div className="acct-id">
                <div className="acct-name">{user.username}</div>
                <span className={`role-badge ${user.role}`}>{user.role}</span>
              </div>
            </div>
            {authEnabled && (
              <>
                <div className="acct-divider" />
                <button
                  className="acct-item"
                  onClick={() => {
                    setOpen(false)
                    onSettings()
                  }}
                >
                  <span className="acct-ic">⚙</span> Account settings
                </button>
                <button
                  className="acct-item danger"
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
