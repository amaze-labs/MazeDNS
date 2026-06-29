import { useState } from 'react'
import Modal from './Modal'

// Security categories apply when blocking; content categories (+ "other") apply
// when allowing. Kept in sync with internal/classifier/classifier.go.
const BLOCK_CATS = ['ads', 'trackers', 'malware', 'phishing']
const CONTENT_CATS = [
  'social', 'streaming', 'shopping', 'news', 'gaming', 'productivity',
  'search', 'email', 'finance', 'technology', 'cdn', 'adult', 'other',
]

// DecisionModal captures the corrected category and a review note when an
// operator allows (whitelists) or blocks a classified domain, so the reasoning
// is recorded and can be reviewed or amended later.
export default function DecisionModal({
  domain,
  decision,
  currentCategory,
  currentNote,
  onClose,
  onSubmit,
}: {
  domain: string
  decision: 'approve' | 'reject'
  currentCategory: string
  currentNote: string
  onClose: () => void
  onSubmit: (category: string, note: string) => Promise<void>
}) {
  const blocking = decision === 'approve'
  const cats = blocking ? BLOCK_CATS : CONTENT_CATS
  const [category, setCategory] = useState(cats.includes(currentCategory) ? currentCategory : cats[0])
  const [note, setNote] = useState(currentNote || '')
  const [saving, setSaving] = useState(false)
  const [err, setErr] = useState('')

  const submit = async () => {
    setSaving(true)
    setErr('')
    try {
      await onSubmit(category, note.trim())
    } catch (e: any) {
      setErr(e.message)
      setSaving(false)
    }
  }

  return (
    <Modal title={`${blocking ? 'Block' : 'Allow'} ${domain}`} onClose={onClose}>
      {err && <div className="error">{err}</div>}
      <p className="muted" style={{ textAlign: 'left', marginTop: 0 }}>
        {blocking
          ? 'Block this domain and record why. Pick the security category that best fits and add a short note for review.'
          : 'Allow this domain (it will never be blocked). Pick the content category that best describes it and add a short note for review.'}
      </p>
      <div className="field">
        <label>Category</label>
        <select value={category} onChange={(e) => setCategory(e.target.value)}>
          {cats.map((c) => (
            <option key={c} value={c}>
              {c}
            </option>
          ))}
        </select>
      </div>
      <div className="field">
        <label>Description / reason</label>
        <textarea
          rows={3}
          style={{ width: '100%', resize: 'vertical' }}
          placeholder="Why is this domain being allowed/blocked? (optional but recommended)"
          value={note}
          onChange={(e) => setNote(e.target.value)}
        />
      </div>
      <div className="settings-actions" style={{ marginTop: 8 }}>
        <button className="btn ghost" onClick={onClose} disabled={saving}>
          Cancel
        </button>
        <button className={`btn ${blocking ? 'danger' : 'primary'}`} onClick={submit} disabled={saving}>
          {saving ? 'Saving…' : blocking ? 'Block domain' : 'Allow domain'}
        </button>
      </div>
    </Modal>
  )
}
