import { useCallback, useEffect, useRef, useState } from 'react'
import { api, type ClassifierStatus, type List, type Protection, type Rule } from '../api'
import { pollWhileVisible } from '../poll'
import Lists from './Lists'
import Rules from './Rules'
import Classifier from './Classifier'
import '../styles/filtering.css'

type Sub = 'review' | 'lists' | 'rules'

// Pause presets for the global block switch (seconds; 0 = until resumed).
const PAUSE_PRESETS = [
  { label: '30 sec', seconds: 30 },
  { label: '5 min', seconds: 300 },
  { label: '30 min', seconds: 1800 },
  { label: 'Until I resume', seconds: 0 },
]
// The API pauses "indefinitely" by setting the deadline 100 years out.
const INDEFINITE = 86400 * 365

function fmtLeft(s: number): string {
  if (s < 60) return `${s} s`
  if (s < 3600) return `${Math.floor(s / 60)} min ${s % 60} s`
  return `${Math.floor(s / 3600)} h ${Math.floor((s % 3600) / 60)} min`
}

// Filtering groups everything that decides what gets blocked: managed blocklists,
// the operator's own allow/block rules and, when the classifier is enabled, the
// review queue of scored domains. The page owns the data the three tabs share
// (protection state, list/rule/review counts, the viewer's role) so the header
// and tab counts stay current whichever tab is open.
export default function Filtering({ classifier = false }: { classifier?: boolean }) {
  const [sub, setSub] = useState<Sub>(classifier ? 'review' : 'lists')
  // If the classifier gets disabled while Review is open, fall back.
  const active: Sub = sub === 'review' && !classifier ? 'lists' : sub

  // Readonly users can look but not change anything: every write endpoint here
  // requires the admin role, so hide the controls instead of letting them fail.
  // Unknown until /me answers — keep edit controls hidden until then.
  const [canEdit, setCanEdit] = useState(false)
  useEffect(() => {
    api
      .me()
      .then((u) => setCanEdit(u?.role === 'admin'))
      .catch(() => setCanEdit(false))
  }, [])

  // ---- Shared data ----
  const [lists, setLists] = useState<List[]>([])
  const [listsLoaded, setListsLoaded] = useState(false)
  const [listsErr, setListsErr] = useState('')
  const [rules, setRules] = useState<Rule[]>([])
  const [rulesLoaded, setRulesLoaded] = useState(false)
  const [rulesErr, setRulesErr] = useState('')
  const [info, setInfo] = useState<ClassifierStatus | null>(null)
  const [infoErr, setInfoErr] = useState('')

  const loadLists = useCallback(
    () =>
      api
        .lists()
        .then((ls) => {
          setLists(ls)
          setListsLoaded(true)
          setListsErr('')
        })
        .catch((e) => setListsErr(e.message)),
    [],
  )
  const loadRules = useCallback(
    () =>
      api
        .rules()
        .then((rs) => {
          setRules(rs)
          setRulesLoaded(true)
          setRulesErr('')
        })
        .catch((e) => setRulesErr(e.message)),
    [],
  )
  const loadInfo = useCallback(
    () =>
      api
        .classifier()
        .then((i) => {
          setInfo(i)
          setInfoErr('')
        })
        .catch((e) => setInfoErr(e.message)),
    [],
  )

  useEffect(() => {
    loadLists()
    loadRules()
    // Lists refresh on their own schedule (and show fetch errors), so keep them
    // current; rules only change from this UI or a config import.
    const stopLists = pollWhileVisible(loadLists, 8000)
    const stopRules = pollWhileVisible(loadRules, 30000)
    return () => {
      stopLists()
      stopRules()
    }
  }, [loadLists, loadRules])
  useEffect(() => {
    if (!classifier) return
    loadInfo()
    return pollWhileVisible(loadInfo, 8000)
  }, [classifier, loadInfo])

  // ---- Protection (global pause) ----
  const [prot, setProt] = useState<Protection | null>(null)
  const [protErr, setProtErr] = useState('')
  const [protBusy, setProtBusy] = useState(false)
  // seconds_left counts down locally between polls.
  const fetchedAt = useRef(Date.now())
  const [, tick] = useState(0)
  const applyProt = (p: Protection) => {
    fetchedAt.current = Date.now()
    setProt(p)
  }
  const loadProt = useCallback(
    () =>
      api
        .protection()
        .then((p) => {
          applyProt(p)
          setProtErr('')
        })
        .catch((e) => setProtErr(e.message)),
    [],
  )
  useEffect(() => {
    loadProt()
    return pollWhileVisible(loadProt, 10000)
  }, [loadProt])
  const timed = !!prot?.paused && prot.seconds_left < INDEFINITE
  useEffect(() => {
    if (!timed) return
    const id = setInterval(() => tick((n) => n + 1), 1000)
    return () => clearInterval(id)
  }, [timed])
  const left = prot ? Math.max(0, prot.seconds_left - Math.floor((Date.now() - fetchedAt.current) / 1000)) : 0
  useEffect(() => {
    if (timed && left === 0) loadProt()
  }, [timed, left, loadProt])

  const pause = async (seconds: number) => {
    setProtBusy(true)
    try {
      applyProt(await api.disableProtection(seconds))
      setProtErr('')
    } catch (e: any) {
      setProtErr(e.message)
    } finally {
      setProtBusy(false)
    }
  }
  const resume = async () => {
    setProtBusy(true)
    try {
      applyProt(await api.enableProtection())
      setProtErr('')
    } catch (e: any) {
      setProtErr(e.message)
    } finally {
      setProtBusy(false)
    }
  }

  const enabledLists = lists.filter((l) => l.enabled).length
  const toCheck = info?.counts?.suggested ?? 0
  const st = info?.settings
  const aiOn = !!(st?.ai_enabled && st?.model?.trim() && (st?.provider === 'anthropic' || st?.endpoint?.trim()))
  const plural = (n: number, w: string) => `${n.toLocaleString()} ${w}${n === 1 ? '' : 's'}`

  return (
    <div className="pg-filtering">
      <header className="page-head">
        <h1>Filtering</h1>
        <span className="spacer" />
        {classifier && info && (
          <span className={`tag ${st?.mode === 'off' ? '' : 'ok'} hide-sm`}>
            {st?.mode === 'off' ? 'Classifier paused' : 'Classifier on'} · {aiOn ? `static analysis + ${st?.model}` : 'static analysis'}
          </span>
        )}
      </header>

      <section className={`card protect${prot?.paused ? ' paused' : ''}`}>
        {!prot ? (
          <div className="state">
            <span className="dot off" />
            <div>
              <b>{protErr ? 'Protection status unavailable' : 'Checking protection…'}</b>
              {protErr && <small className="bad-text">{protErr}</small>}
            </div>
          </div>
        ) : prot.paused ? (
          <>
            <div className="state">
              <span className="dot warn pulse" />
              <div>
                <b>Blocking is paused</b>
                <small>
                  {timed ? `Resumes on its own in ${fmtLeft(left)}.` : 'Paused until you resume it.'} Every query is answered, even
                  ones on a list.
                </small>
              </div>
            </div>
            <span className="spacer" />
            {canEdit && (
              <button className="btn primary" onClick={resume} disabled={protBusy}>
                Resume blocking
              </button>
            )}
          </>
        ) : (
          <>
            <div className="state">
              <span className="dot pulse" />
              <div>
                <b>Protection is on</b>
                <small>
                  {!listsLoaded || !rulesLoaded
                    ? 'Blocking is active.'
                    : enabledLists + rules.length === 0
                      ? 'Blocking is active. No lists or rules added here yet.'
                      : `Blocking with ${plural(enabledLists, 'list')} and ${plural(rules.length, 'rule')}.`}
                </small>
              </div>
            </div>
            <span className="spacer" />
            {canEdit && (
              <>
                <span className="muted hide-sm">Pause for</span>
                <div className="seg" role="group" aria-label="Pause blocking for">
                  {PAUSE_PRESETS.map((p) => (
                    <button key={p.seconds} onClick={() => pause(p.seconds)} disabled={protBusy}>
                      {p.label}
                    </button>
                  ))}
                </div>
              </>
            )}
          </>
        )}
        {prot && protErr && <div className="prot-err bad-text small">{protErr}</div>}
      </section>

      <nav className="tabs" role="tablist" aria-label="Filtering sections">
        <button role="tab" aria-selected={active === 'lists'} className={active === 'lists' ? 'on' : ''} onClick={() => setSub('lists')}>
          Blocklists {listsLoaded && <span className="n">{lists.length.toLocaleString()}</span>}
        </button>
        <button role="tab" aria-selected={active === 'rules'} className={active === 'rules' ? 'on' : ''} onClick={() => setSub('rules')}>
          Your rules {rulesLoaded && <span className="n">{rules.length.toLocaleString()}</span>}
        </button>
        {classifier && (
          <button role="tab" aria-selected={active === 'review'} className={active === 'review' ? 'on' : ''} onClick={() => setSub('review')}>
            Review {info && <span className={`n${toCheck > 0 ? ' warn' : ''}`}>{toCheck > 0 ? `${toCheck.toLocaleString()} to check` : 'all clear'}</span>}
          </button>
        )}
      </nav>

      {active === 'lists' && (
        <Lists lists={lists} loaded={listsLoaded} loadErr={listsErr} reload={loadLists} canEdit={canEdit} />
      )}
      {active === 'rules' && (
        <Rules rules={rules} loaded={rulesLoaded} loadErr={rulesErr} reload={loadRules} canEdit={canEdit} />
      )}
      {active === 'review' && <Classifier info={info} infoErr={infoErr} reloadInfo={loadInfo} canEdit={canEdit} />}
    </div>
  )
}
