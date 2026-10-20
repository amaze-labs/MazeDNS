import { useEffect, useRef, useState, type FormEvent, type ReactNode } from 'react'
import Modal from './Modal'
import ScopePicker, { type Scope } from './ScopePicker'
import '../styles/local-dns.css'

const errMsg = (e: unknown) => (e instanceof Error ? e.message : String(e)) || 'Request failed'

// EditScopedModal edits the mutable part of a scoped entry (record answer or
// forwarding resolvers, plus the scope). Save errors, including the backend's
// 409 when the new scope overlaps another entry for the same name, are shown
// inside the dialog so the operator can adjust the scope and retry.
export default function EditScopedModal({
  title,
  intro,
  fieldLabel,
  fieldPlaceholder,
  initialText,
  initialScope,
  nodes,
  sites,
  onClose,
  onSave,
}: {
  title: string
  intro: ReactNode
  fieldLabel: string
  fieldPlaceholder: string
  initialText: string
  initialScope: Scope
  nodes: string[] | null
  sites: string[] | null
  onClose: () => void
  onSave: (text: string, scope: Scope) => Promise<void>
}) {
  const [text, setText] = useState(initialText)
  const [scope, setScope] = useState<Scope>(initialScope)
  const [saving, setSaving] = useState(false)
  const [err, setErr] = useState('')
  // Modal focuses its panel on open (its effect runs after ours), so move focus
  // into the field on the next tick instead of relying on autoFocus.
  const field = useRef<HTMLInputElement>(null)
  useEffect(() => {
    const t = setTimeout(() => field.current?.focus(), 0)
    return () => clearTimeout(t)
  }, [])

  const save = async (e?: FormEvent) => {
    e?.preventDefault()
    if (saving) return
    setSaving(true)
    setErr('')
    try {
      await onSave(text.trim(), scope)
    } catch (e) {
      setErr(errMsg(e))
      setSaving(false)
    }
  }

  return (
    <Modal
      kind="dialog"
      title={title}
      onClose={onClose}
      footer={
        <>
          <span className="spacer" />
          <button className="btn ghost" onClick={onClose} disabled={saving}>
            Cancel
          </button>
          <button className="btn primary" onClick={() => save()} disabled={saving}>
            {saving ? 'Saving…' : 'Save'}
          </button>
        </>
      }
    >
      <form className="rw-edit" onSubmit={save}>
        <p className="muted">{intro}</p>
        <label className="field">
          <span>{fieldLabel}</span>
          <input
            ref={field}
            className="mono"
            placeholder={fieldPlaceholder}
            value={text}
            onChange={(e) => setText(e.target.value)}
          />
        </label>
        <div className="field">
          <label htmlFor="edit-scope">Scope</label>
          <ScopePicker id="edit-scope" value={scope} onChange={setScope} nodes={nodes} sites={sites} />
        </div>
        {err && (
          <div className="error" role="alert">
            {err}
          </div>
        )}
        {/* Enter in the field submits the form. */}
        <button type="submit" hidden />
      </form>
    </Modal>
  )
}
