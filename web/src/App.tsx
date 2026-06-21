import { useState } from 'react'
import Dashboard from './components/Dashboard'
import Rules from './components/Rules'
import Rewrites from './components/Rewrites'

type Tab = 'dashboard' | 'rules' | 'rewrites'
const tabs: Tab[] = ['dashboard', 'rules', 'rewrites']

export default function App() {
  const [tab, setTab] = useState<Tab>('dashboard')
  return (
    <div className="app">
      <header>
        <h1>🧭 MazeDNS</h1>
        <nav>
          {tabs.map((t) => (
            <button key={t} className={tab === t ? 'active' : ''} onClick={() => setTab(t)}>
              {t}
            </button>
          ))}
        </nav>
      </header>
      <main>
        {tab === 'dashboard' && <Dashboard />}
        {tab === 'rules' && <Rules />}
        {tab === 'rewrites' && <Rewrites />}
      </main>
    </div>
  )
}
