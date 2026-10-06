import { useEffect, useRef, type ReactNode } from 'react'

// Modal shows detail views as a side panel (drawer) that slides in from the right,
// keeping the list behind it visible; kind="dialog" centres a smaller panel for
// short forms and confirmations. Closes on scrim click or Esc, moves focus into
// the panel on open and back to the opener on close.
export default function Modal({
  title,
  onClose,
  children,
  size,
  kind = 'drawer',
  eyebrow,
  footer,
}: {
  title: ReactNode
  onClose: () => void
  children: ReactNode
  size?: 'wide'
  kind?: 'drawer' | 'dialog'
  eyebrow?: ReactNode // small line above the title (status, context)
  footer?: ReactNode // actions pinned to the bottom of the panel
}) {
  const panel = useRef<HTMLDivElement>(null)
  // Keep the latest onClose in a ref so the focus effect runs once per opening:
  // callers that poll often pass a fresh inline onClose, which must not pull
  // focus out of a field the user is typing in.
  const close = useRef(onClose)
  close.current = onClose
  useEffect(() => {
    const opener = document.activeElement as HTMLElement | null
    panel.current?.focus()
    const onKey = (e: KeyboardEvent) => e.key === 'Escape' && close.current()
    window.addEventListener('keydown', onKey)
    return () => {
      window.removeEventListener('keydown', onKey)
      opener?.focus?.()
    }
  }, [])

  const body = (
    <>
      <div className="panel-head">
        <div className="panel-title">
          {eyebrow && <div className="eyebrow">{eyebrow}</div>}
          <h2>{title}</h2>
        </div>
        <button className="close" onClick={onClose} aria-label="Close">
          ✕
        </button>
      </div>
      <div className="panel-body">{children}</div>
      {footer && <div className="panel-foot">{footer}</div>}
    </>
  )

  if (kind === 'dialog') {
    return (
      <div className="scrim center" onClick={onClose}>
        <div className="dialog" ref={panel} tabIndex={-1} role="dialog" aria-modal="true" onClick={(e) => e.stopPropagation()}>
          {body}
        </div>
      </div>
    )
  }
  return (
    <>
      <div className="scrim" onClick={onClose} />
      <aside className={`drawer${size === 'wide' ? ' wide' : ''}`} ref={panel} tabIndex={-1} role="dialog" aria-modal="true">
        {body}
      </aside>
    </>
  )
}
