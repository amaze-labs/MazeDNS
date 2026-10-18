import { useState } from 'react'
import { api, type CategoryInfo } from '../api'
import { reloadCategories, useCategories } from '../categories'
import { SkelToggles } from './Skeleton'
import { timeAgo } from './tableKit'

const fmtCount = (n: number) =>
  n >= 1_000_000 ? `${(n / 1_000_000).toFixed(1)}M` : n >= 10_000 ? `${Math.round(n / 1000)}k` : n.toLocaleString()

// CategoryBlocking blocks whole categories network-wide (Filtering → Categories).
// A switch applies at once: the setting reaches every agent with its next poll,
// and each agent loads the category database for just the blocked categories.
export default function CategoryBlocking({ canEdit }: { canEdit: boolean }) {
  const list = useCategories()
  const [busy, setBusy] = useState('')
  const [err, setErr] = useState('')

  if (!list) {
    return (
      <section className="card cat-block" aria-busy="true">
        <SkelToggles count={12} />
      </section>
    )
  }
  if (!list.enabled) {
    return (
      <section className="card">
        <p className="muted nomargin">
          Domain categories are turned off on this control plane (<code>MAZEDNS_CATEGORY_DB=off</code>).
        </p>
      </section>
    )
  }

  const blocked = list.categories.filter((c) => c.blocked).map((c) => c.id)
  const toggle = async (c: CategoryInfo, on: boolean) => {
    setBusy(c.id)
    setErr('')
    try {
      await api.setBlockedCategories(on ? [...blocked, c.id] : blocked.filter((id) => id !== c.id))
      await reloadCategories()
    } catch (e: any) {
      setErr(e.message)
    } finally {
      setBusy('')
    }
  }
  const db = list.database
  const groups: [string, string, CategoryInfo[]][] = [
    ['Content', 'Legitimate traffic, blocked only if you choose to (parental control, focus, policy).', list.categories.filter((c) => !c.security && c.id !== 'other' && c.id !== 'local')],
    ['Security', 'The classifier already blocks these on its own judgement; blocking the category also blocks everything the database lists for it.', list.categories.filter((c) => c.security)],
  ]

  return (
    <section className="card cat-block">
      <div className="card-head">
        <div>
          <h2>Block by category</h2>
          <p className="sub">
            Block every domain in a category on every agent. Your allow rules still win, and pausing protection pauses these too.
          </p>
        </div>
      </div>
      <p className="muted small nomargin">
        {db.loading && !db.updated_at
          ? 'Loading the category database…'
          : db.updated_at
            ? `Category database (UT1, Université Toulouse Capitole): ${fmtCount(db.domains)} domains, updated ${timeAgo(db.updated_at * 1000)}.`
            : 'The category database hasn’t loaded yet.'}
        {db.error && <span className="bad-text"> Last refresh failed: {db.error}</span>} Each agent loads only the categories you block
        (Adult is the largest: about 45 MB of memory).
      </p>
      {err && <div className="error">{err}</div>}
      {groups.map(([title, desc, cats]) => (
        <div key={title} className="cat-group">
          <h3>{title}</h3>
          <p className="muted small nomargin">{desc}</p>
          <div className="cat-grid">
            {cats.map((c) => (
              <label key={c.id} className="check-row toggle">
                <span className="t">
                  <b>{c.label}</b>
                  <small>{c.domains ? `${fmtCount(c.domains)} domains in the database` : 'Known from the language model and your overrides'}</small>
                </span>
                <input type="checkbox" checked={c.blocked} disabled={!canEdit || busy !== ''} onChange={(e) => toggle(c, e.target.checked)} />
                <span className="track">
                  <span className="thumb" />
                </span>
              </label>
            ))}
          </div>
        </div>
      ))}
    </section>
  )
}
