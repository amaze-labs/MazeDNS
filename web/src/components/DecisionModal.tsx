import { useEffect, useState } from 'react'
import Modal from './Modal'

// Security categories apply when blocking; content categories (+ "other") apply
// when allowing. Kept in sync with internal/classifier/classifier.go.
const BLOCK_CATS = ['ads', 'trackers', 'malware', 'phishing']
const CONTENT_CATS = [
  'social', 'streaming', 'shopping', 'news', 'gaming', 'productivity',
  'search', 'email', 'finance', 'technology', 'cdn', 'adult', 'other',
]
const cap = (s: string) => s.charAt(0).toUpperCase() + s.slice(1)

export type Decision = 'approve' | 'reject'

// useDecision holds the category + note form for an allow/block decision. The
// submit callback must throw on failure: the error is shown in the form and the
// typed note is kept so the operator can retry.
export function useDecision(
  decision: Decision,
  currentCategory: string,
  currentNote: string,
  onSubmit: (category: string, note: string) => Promise<void>,
) {
  const blocking = decision === 'approve'
  const cats = blocking ? BLOCK_CATS : CONTENT_CATS
  const [category, setCategory] = useState(cats.includes(currentCategory) ? currentCategory : cats[0])
  const [note, setNote] = useState(currentNote || '')
  const [saving, setSaving] = useState(false)
  const [err, setErr] = useState('')
  // Switching between block and allow swaps the category set.
  useEffect(() => {
    setCategory(cats.includes(currentCategory) ? currentCategory : cats[0])
    setErr('')
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [decision])
  const submit = async () => {
    setSaving(true)
    setErr('')
    try {
      await onSubmit(category, note.trim())
    } catch (e: any) {
      setErr(e?.message || 'The decision could not be saved.')
    } finally {
      setSaving(false)
    }
  }
  return { blocking, cats, category, setCategory, note, setNote, saving, err, submit }
}
export type DecisionState = ReturnType<typeof useDecision>

// DecisionFields renders the category picker and note box (with any save error).
export function DecisionFields({ d }: { d: DecisionState }) {
  return (
    <div className="decision">
      {d.err && (
        <div className="error" role="alert">
          {d.err}
        </div>
      )}
      <p className="muted decision-lead">
        {d.blocking
          ? 'Block this domain and record why. Pick the security category that fits best and add a short note for whoever reviews it later.'
          : 'Allow this domain so it is never blocked. Pick the content category that describes it best and add a short note for whoever reviews it later.'}
      </p>
      <label className="field">
        <span>Category</span>
        <select value={d.category} onChange={(e) => d.setCategory(e.target.value)}>
          {d.cats.map((c) => (
            <option key={c} value={c}>
              {cap(c)}
            </option>
          ))}
        </select>
      </label>
      <label className="field">
        <span>Note</span>
        <textarea
          rows={3}
          className="note"
          placeholder={d.blocking ? 'Why block it? Optional, but helps later.' : 'Why allow it? Optional, but helps later.'}
          value={d.note}
          onChange={(e) => d.setNote(e.target.value)}
        />
      </label>
    </div>
  )
}

// DecisionActions is the confirm/cancel pair for a decision form.
export function DecisionActions({ d, onCancel, cancelLabel = 'Cancel' }: { d: DecisionState; onCancel: () => void; cancelLabel?: string }) {
  return (
    <>
      <button className={`btn ${d.blocking ? 'danger solid' : 'primary'}`} onClick={d.submit} disabled={d.saving}>
        {d.saving ? 'Saving…' : d.blocking ? 'Block domain' : 'Allow domain'}
      </button>
      <button className="btn quiet" onClick={onCancel} disabled={d.saving}>
        {cancelLabel}
      </button>
    </>
  )
}

// DecisionModal asks for the category and a review note when an operator allows
// or blocks a classified domain straight from the review table. It stays open
// (keeping the note) when saving fails. onClose must be a stable callback.
export default function DecisionModal({
  domain,
  decision,
  currentCategory,
  currentNote,
  onClose,
  onSubmit,
}: {
  domain: string
  decision: Decision
  currentCategory: string
  currentNote: string
  onClose: () => void
  onSubmit: (category: string, note: string) => Promise<void>
}) {
  const d = useDecision(decision, currentCategory, currentNote, onSubmit)
  return (
    <Modal
      kind="dialog"
      eyebrow={d.blocking ? 'Block domain' : 'Allow domain'}
      title={<span className="mono">{domain}</span>}
      onClose={onClose}
      footer={<DecisionActions d={d} onCancel={onClose} />}
    >
      <DecisionFields d={d} />
    </Modal>
  )
}
