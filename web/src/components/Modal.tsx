import { useEffect, type ReactNode } from 'react'

// Modal is a centered dialog with a backdrop. Closes on backdrop click or Esc.
// Pass size="wide" for content-heavy dialogs (e.g. the client inspector).
export default function Modal({
  title,
  onClose,
  children,
  size,
}: {
  title: string
  onClose: () => void
  children: ReactNode
  size?: 'wide'
}) {
  useEffect(() => {
    const onKey = (e: KeyboardEvent) => e.key === 'Escape' && onClose()
    window.addEventListener('keydown', onKey)
    return () => window.removeEventListener('keydown', onKey)
  }, [onClose])
  return (
    <div className="modal-backdrop" onClick={onClose}>
      <div className={`modal${size === 'wide' ? ' modal-wide' : ''}`} onClick={(e) => e.stopPropagation()} role="dialog" aria-modal="true">
        <div className="modal-head">
          <h3>{title}</h3>
          <button className="modal-close" onClick={onClose} aria-label="Close">
            ✕
          </button>
        </div>
        <div className="modal-body">{children}</div>
      </div>
    </div>
  )
}
