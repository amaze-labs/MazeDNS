import { useState } from 'react'
import Lists from './Lists'
import Rules from './Rules'

// Filtering groups the two related filtering tools — managed blocklists and
// manual allow/deny rules — under one nav section with sub-tabs.
export default function Filtering() {
  const [sub, setSub] = useState<'lists' | 'rules'>('lists')
  return (
    <div>
      <div className="subtabs">
        <button className={sub === 'lists' ? 'active' : ''} onClick={() => setSub('lists')}>
          Blocklists
        </button>
        <button className={sub === 'rules' ? 'active' : ''} onClick={() => setSub('rules')}>
          Manual rules
        </button>
      </div>
      {sub === 'lists' ? <Lists /> : <Rules />}
    </div>
  )
}
