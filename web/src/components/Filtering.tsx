import { useState } from 'react'
import Lists from './Lists'
import Rules from './Rules'
import Classifier from './Classifier'

type Sub = 'lists' | 'rules' | 'ai'

// Filtering groups the related filtering tools — managed blocklists, manual
// allow/deny rules, and the AI domain classifier — under one nav section with
// sub-tabs. The AI sub-tab only appears when the classifier is enabled.
export default function Filtering({ classifier = false }: { classifier?: boolean }) {
  const [sub, setSub] = useState<Sub>('lists')
  // If the classifier gets disabled while it's the active sub-tab, fall back.
  const active: Sub = sub === 'ai' && !classifier ? 'lists' : sub
  return (
    <div>
      <div className="subtabs">
        <button className={active === 'lists' ? 'active' : ''} onClick={() => setSub('lists')}>
          Blocklists
        </button>
        <button className={active === 'rules' ? 'active' : ''} onClick={() => setSub('rules')}>
          Manual rules
        </button>
        {classifier && (
          <button className={active === 'ai' ? 'active' : ''} onClick={() => setSub('ai')}>
            AI classification
          </button>
        )}
      </div>
      {active === 'lists' && <Lists />}
      {active === 'rules' && <Rules />}
      {active === 'ai' && <Classifier />}
    </div>
  )
}
