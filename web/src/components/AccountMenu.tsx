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
  const initial = (user.username.trim()[0] || '?').toUpperCase()
  return (
    <div className="acct">
      <button
        className={`acct-avatar ${open ? 'open' : ''}`}
        onClick={() => setOpen((o) => !o)}
        title={user.username}
        aria-label="Account menu"
      >
        {initial}
      </button>
      {open && (
        <>
          <div className="acct-backdrop" onClick={() => setOpen(false)} />
          <div className="acct-menu">
            <div className="acct-head">
              <div className="acct-avatar lg">{initial}</div>
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
