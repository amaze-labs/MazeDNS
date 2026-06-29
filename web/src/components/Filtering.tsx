import { useState } from 'react'
import Lists from './Lists'
import Rules from './Rules'
import Classifier from './Classifier'

type Sub = 'ai' | 'lists' | 'rules'

// Filtering groups the related filtering tools — the AI domain classifier,
// managed blocklists, and manual allow/deny rules — under one nav section with
// sub-tabs. The AI sub-tab leads (and is the default) when the classifier is on.
export default function Filtering({ classifier = false }: { classifier?: boolean }) {
  const [sub, setSub] = useState<Sub>(classifier ? 'ai' : 'lists')
  // If the classifier gets disabled while it's the active sub-tab, fall back.
  const active: Sub = sub === 'ai' && !classifier ? 'lists' : sub
  return (
    <div>
      <div className="subtabs">
        {classifier && (
          <button className={active === 'ai' ? 'active' : ''} onClick={() => setSub('ai')}>
            AI classification
          </button>
        )}
        <button className={active === 'lists' ? 'active' : ''} onClick={() => setSub('lists')}>
          Blocklists
        </button>
        <button className={active === 'rules' ? 'active' : ''} onClick={() => setSub('rules')}>
          Manual rules
        </button>
      </div>
      {active === 'ai' && <Classifier />}
      {active === 'lists' && <Lists />}
      {active === 'rules' && <Rules />}
    </div>
  )
}
