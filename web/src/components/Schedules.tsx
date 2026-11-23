import { useEffect, useState, type FormEvent } from 'react'
import { api, type BlockSchedule, type ClientGroup, type Schedules as Body } from '../api'
import { useCategories } from '../categories'
import Modal from './Modal'
import { SkelList } from './Skeleton'
import '../styles/schedules.css'

const errMsg = (e: unknown) => (e instanceof Error ? e.message : String(e)) || 'Request failed'

// Days in display order (Monday first); values are 0 = Sunday … 6 = Saturday.
const DAYS = [
  { v: 1, short: 'Mon' },
  { v: 2, short: 'Tue' },
  { v: 3, short: 'Wed' },
  { v: 4, short: 'Thu' },
  { v: 5, short: 'Fri' },
  { v: 6, short: 'Sat' },
  { v: 0, short: 'Sun' },
]

const browserZone = (() => {
  try {
    return Intl.DateTimeFormat().resolvedOptions().timeZone || ''
  } catch {
    return ''
  }
})()

const zones: string[] = (() => {
  try {
    return (Intl as unknown as { supportedValuesOf?: (k: string) => string[] }).supportedValuesOf?.('timeZone') ?? []
  } catch {
    return []
  }
})()

const lines = (t: string) =>
  t
    .split(/[\n,]/)
    .map((x) => x.trim())
    .filter(Boolean)

function daysText(days: number[]): string {
  const set = new Set(days)
  if (set.size === 7) return 'Every day'
  const wk = [1, 2, 3, 4, 5]
  if (set.size === 5 && wk.every((d) => set.has(d))) return 'Mon–Fri'
  if (set.size === 2 && set.has(0) && set.has(6)) return 'Sat–Sun'
  return DAYS.filter((d) => set.has(d.v))
    .map((d) => d.short)
    .join(', ')
}

function whenText(s: BlockSchedule): string {
  const span = s.start === s.end ? 'all day' : `${s.start}–${s.end}${s.end < s.start ? ' (next day)' : ''}`
  return `${daysText(s.days)}, ${span}`
}

function blocksText(s: BlockSchedule, label: (id: string) => string): string {
  const parts: string[] = []
  const cats = s.categories || []
  const doms = s.domains || []
  if (cats.length) parts.push(cats.map(label).join(', '))
  if (doms.length) parts.push(doms.length <= 3 ? doms.join(', ') : `${doms.slice(0, 2).join(', ')} +${doms.length - 2} more`)
  return parts.join(' · ')
}

const emptySchedule = (): BlockSchedule => ({
  name: '',
  enabled: true,
  domains: [],
  categories: [],
  days: [0, 1, 2, 3, 4],
  start: '22:00',
  end: '06:00',
  time_zone: browserZone,
  groups: [],
})

// Schedules is Filtering → Schedules: block domains or categories during a
// weekly time window ("downtime"), for everyone or for groups of devices.
export default function Schedules({ canEdit }: { canEdit: boolean }) {
  const [data, setData] = useState<Body | null>(null)
  const [loadErr, setLoadErr] = useState('')
  const [err, setErr] = useState('')
  const [busy, setBusy] = useState(false)
  const [editSched, setEditSched] = useState<{ i: number; s: BlockSchedule } | null>(null)
  const [editGroup, setEditGroup] = useState<{ i: number; g: ClientGroup } | null>(null)
  const catList = useCategories()
  const catLabel = (id: string) => catList?.categories.find((c) => c.id === id)?.label ?? id

  const load = () => {
    setLoadErr('')
    api
      .schedules()
      .then(setData)
      .catch((e) => setLoadErr(errMsg(e)))
  }
  useEffect(load, [])

  // save replaces both lists; on success the server's normalized copy is shown.
  const save = async (next: Body): Promise<boolean> => {
    setBusy(true)
    setErr('')
    try {
      setData(await api.saveSchedules(next))
      return true
    } catch (e) {
      setErr(errMsg(e))
      return false
    } finally {
      setBusy(false)
    }
  }

  if (loadErr) {
    return (
      <div className="error">
        <span className="grow">Couldn't load schedules: {loadErr}</span>
        <button className="btn sm" onClick={load}>
          Try again
        </button>
      </div>
    )
  }
  if (!data) {
    return (
      <section className="card">
        <SkelList rows={3} />
      </section>
    )
  }

  const { schedules, client_groups: groups } = data
  const groupUse = (name: string) => schedules.filter((s) => (s.groups || []).includes(name)).map((s) => s.name)

  return (
    <div className="sched">
      {err && !editSched && !editGroup && (
        <div className="error" role="alert">
          {err}
        </div>
      )}

      <section className="card flush">
        <div className="card-head">
          <div>
            <h2>Schedules</h2>
            <p className="sub">
              Block domains or categories during set hours, like social media on school nights. A domain also blocks its
              subdomains. Allow rules still win, and pausing blocking pauses schedules too.
            </p>
          </div>
          {canEdit && (
            <button className="btn sm primary" onClick={() => setEditSched({ i: -1, s: emptySchedule() })}>
              Add schedule
            </button>
          )}
        </div>
        {schedules.length === 0 ? (
          <p className="muted sched-empty">No schedules yet.</p>
        ) : (
          <ul className="rowlist">
            {schedules.map((s, i) => (
              <li key={s.name} className={`rowitem sched-row${s.enabled ? '' : ' off'}`}>
                <div className="grow">
                  <b>{s.name}</b>
                  {!s.enabled && <span className="tag">Off</span>}
                  <small>
                    {whenText(s)}
                    {s.time_zone ? ` · ${s.time_zone}` : ''}
                  </small>
                  <small>
                    Blocks {blocksText(s, catLabel)} · for {(s.groups || []).length ? (s.groups || []).join(', ') : 'everyone'}
                  </small>
                </div>
                {canEdit && (
                  <span className="sched-act">
                    <label className="sched-switch" title={s.enabled ? 'Turn off' : 'Turn on'}>
                      <input
                        type="checkbox"
                        checked={s.enabled}
                        disabled={busy}
                        aria-label={`${s.name} on`}
                        onChange={(e) =>
                          save({ ...data, schedules: schedules.map((x, j) => (j === i ? { ...x, enabled: e.target.checked } : x)) })
                        }
                      />
                    </label>
                    <button className="btn sm" onClick={() => setEditSched({ i, s })}>
                      Edit
                    </button>
                    <button
                      className="btn sm quiet"
                      disabled={busy}
                      onClick={() => {
                        if (window.confirm(`Delete the schedule “${s.name}”?`)) save({ ...data, schedules: schedules.filter((_, j) => j !== i) })
                      }}
                    >
                      Delete
                    </button>
                  </span>
                )}
              </li>
            ))}
          </ul>
        )}
      </section>

      <section className="card flush">
        <div className="card-head">
          <div>
            <h2>Client groups</h2>
            <p className="sub">
              Devices by IP address or range, so a schedule can apply to just them. Give each device a fixed address (a DHCP
              reservation) or its own VLAN so it stays in the group.
            </p>
          </div>
          {canEdit && (
            <button className="btn sm" onClick={() => setEditGroup({ i: -1, g: { name: '', members: [] } })}>
              Add group
            </button>
          )}
        </div>
        {groups.length === 0 ? (
          <p className="muted sched-empty">No client groups: schedules apply to everyone.</p>
        ) : (
          <ul className="rowlist">
            {groups.map((g, i) => {
              const used = groupUse(g.name)
              return (
                <li key={g.name} className="rowitem sched-row">
                  <div className="grow">
                    <b>{g.name}</b>
                    <small className="mono">{g.members.join(', ')}</small>
                    {used.length > 0 && <small>Used by {used.join(', ')}</small>}
                  </div>
                  {canEdit && (
                    <span className="sched-act">
                      <button className="btn sm" onClick={() => setEditGroup({ i, g })}>
                        Edit
                      </button>
                      <button
                        className="btn sm quiet"
                        disabled={busy || used.length > 0}
                        title={used.length > 0 ? 'Remove it from its schedules first' : undefined}
                        onClick={() => {
                          if (window.confirm(`Delete the group “${g.name}”?`)) save({ ...data, client_groups: groups.filter((_, j) => j !== i) })
                        }}
                      >
                        Delete
                      </button>
                    </span>
                  )}
                </li>
              )
            })}
          </ul>
        )}
      </section>

      {editSched && (
        <ScheduleEditor
          initial={editSched.s}
          isNew={editSched.i < 0}
          groups={groups}
          categories={(catList?.enabled ? catList.categories : []).filter((c) => c.id !== 'other' && c.id !== 'local')}
          busy={busy}
          err={err}
          onClose={() => {
            setEditSched(null)
            setErr('')
          }}
          onSave={async (s) => {
            const next =
              editSched.i < 0 ? [...schedules, s] : schedules.map((x, j) => (j === editSched.i ? s : x))
            if (await save({ ...data, schedules: next })) setEditSched(null)
          }}
        />
      )}
      {editGroup && (
        <GroupEditor
          initial={editGroup.g}
          isNew={editGroup.i < 0}
          busy={busy}
          err={err}
          onClose={() => {
            setEditGroup(null)
            setErr('')
          }}
          onSave={async (g) => {
            const old = editGroup.i < 0 ? null : groups[editGroup.i]
            const nextGroups = editGroup.i < 0 ? [...groups, g] : groups.map((x, j) => (j === editGroup.i ? g : x))
            // A rename follows into the schedules that use the group.
            const nextScheds =
              old && old.name !== g.name
                ? schedules.map((s) => ({ ...s, groups: (s.groups || []).map((n) => (n === old.name ? g.name : n)) }))
                : schedules
            if (await save({ client_groups: nextGroups, schedules: nextScheds })) setEditGroup(null)
          }}
        />
      )}
    </div>
  )
}

function ScheduleEditor({
  initial,
  isNew,
  groups,
  categories,
  busy,
  err,
  onClose,
  onSave,
}: {
  initial: BlockSchedule
  isNew: boolean
  groups: ClientGroup[]
  categories: { id: string; label: string }[]
  busy: boolean
  err: string
  onClose: () => void
  onSave: (s: BlockSchedule) => void
}) {
  const [s, setS] = useState<BlockSchedule>(initial)
  const [domains, setDomains] = useState((initial.domains || []).join('\n'))
  const set = (patch: Partial<BlockSchedule>) => setS((p) => ({ ...p, ...patch }))
  const toggle = (list: (string | number)[] | undefined, v: string | number) =>
    (list || []).includes(v) ? (list || []).filter((x) => x !== v) : [...(list || []), v]

  const submit = (e?: FormEvent) => {
    e?.preventDefault()
    onSave({ ...s, name: s.name.trim(), domains: lines(domains) })
  }
  const everyone = (s.groups || []).length === 0

  return (
    <Modal
      title={isNew ? 'Add schedule' : `Edit ${initial.name}`}
      onClose={onClose}
      footer={
        <>
          <span className="spacer" />
          <button className="btn ghost" onClick={onClose} disabled={busy}>
            Cancel
          </button>
          <button className="btn primary" onClick={() => submit()} disabled={busy || !s.name.trim()}>
            {busy ? 'Saving…' : 'Save'}
          </button>
        </>
      }
    >
      <form className="sched-form" onSubmit={submit}>
        <label className="field">
          <span>Name</span>
          <input value={s.name} placeholder="School nights" onChange={(e) => set({ name: e.target.value })} />
        </label>

        <fieldset className="field">
          <legend>Days</legend>
          <div className="sched-days">
            {DAYS.map((d) => (
              <button
                type="button"
                key={d.v}
                className={`chip${s.days.includes(d.v) ? ' on' : ''}`}
                aria-pressed={s.days.includes(d.v)}
                onClick={() => set({ days: toggle(s.days, d.v) as number[] })}
              >
                {d.short}
              </button>
            ))}
          </div>
        </fieldset>

        <div className="sched-times">
          <label className="field">
            <span>From</span>
            <input type="time" value={s.start} onChange={(e) => set({ start: e.target.value })} />
          </label>
          <label className="field">
            <span>Until</span>
            <input type="time" value={s.end} onChange={(e) => set({ end: e.target.value })} />
          </label>
          <label className="field">
            <span>Time zone</span>
            <input list="sched-zones" value={s.time_zone || ''} placeholder="Resolver's local time" onChange={(e) => set({ time_zone: e.target.value })} />
            <datalist id="sched-zones">
              {zones.map((z) => (
                <option key={z} value={z} />
              ))}
            </datalist>
          </label>
        </div>
        <p className="muted sched-hint">
          {s.start === s.end
            ? 'Same start and end: the whole day.'
            : s.end < s.start
              ? `Runs past midnight: from ${s.start} on the chosen days until ${s.end} the next morning.`
              : `From ${s.start} to ${s.end} on the chosen days.`}
        </p>

        {categories.length > 0 && (
          <fieldset className="field">
            <legend>Block categories</legend>
            <div className="sched-cats">
              {categories.map((c) => (
                <button
                  type="button"
                  key={c.id}
                  className={`chip${(s.categories || []).includes(c.id) ? ' on' : ''}`}
                  aria-pressed={(s.categories || []).includes(c.id)}
                  onClick={() => set({ categories: toggle(s.categories, c.id) as string[] })}
                >
                  {c.label}
                </button>
              ))}
            </div>
          </fieldset>
        )}

        <label className="field">
          <span>Block domains</span>
          <textarea
            className="mono"
            rows={4}
            placeholder={'snapchat.com\ntiktok.com'}
            value={domains}
            onChange={(e) => setDomains(e.target.value)}
          />
          <small>One per line. Subdomains are included.</small>
        </label>

        <fieldset className="field">
          <legend>Applies to</legend>
          <label className="sched-radio">
            <input type="radio" checked={everyone} onChange={() => set({ groups: [] })} /> Everyone
          </label>
          {groups.length === 0 ? (
            <small className="muted">Add a client group below to limit a schedule to some devices.</small>
          ) : (
            groups.map((g) => (
              <label key={g.name} className="sched-radio">
                <input
                  type="checkbox"
                  checked={(s.groups || []).includes(g.name)}
                  onChange={() => set({ groups: toggle(s.groups, g.name) as string[] })}
                />{' '}
                {g.name} <span className="muted mono">{g.members.join(', ')}</span>
              </label>
            ))
          )}
        </fieldset>

        {err && (
          <div className="error" role="alert">
            {err}
          </div>
        )}
        <button type="submit" hidden />
      </form>
    </Modal>
  )
}

function GroupEditor({
  initial,
  isNew,
  busy,
  err,
  onClose,
  onSave,
}: {
  initial: ClientGroup
  isNew: boolean
  busy: boolean
  err: string
  onClose: () => void
  onSave: (g: ClientGroup) => void
}) {
  const [name, setName] = useState(initial.name)
  const [members, setMembers] = useState(initial.members.join('\n'))
  const submit = (e?: FormEvent) => {
    e?.preventDefault()
    onSave({ name: name.trim(), members: lines(members) })
  }
  return (
    <Modal
      kind="dialog"
      title={isNew ? 'Add client group' : `Edit ${initial.name}`}
      onClose={onClose}
      footer={
        <>
          <span className="spacer" />
          <button className="btn ghost" onClick={onClose} disabled={busy}>
            Cancel
          </button>
          <button className="btn primary" onClick={() => submit()} disabled={busy || !name.trim()}>
            {busy ? 'Saving…' : 'Save'}
          </button>
        </>
      }
    >
      <form className="sched-form" onSubmit={submit}>
        <label className="field">
          <span>Name</span>
          <input value={name} placeholder="Kids" onChange={(e) => setName(e.target.value)} />
        </label>
        <label className="field">
          <span>Devices</span>
          <textarea
            className="mono"
            rows={4}
            placeholder={'192.168.1.50\n10.0.20.0/24'}
            value={members}
            onChange={(e) => setMembers(e.target.value)}
          />
          <small>IP addresses or CIDR ranges, one per line.</small>
        </label>
        {err && (
          <div className="error" role="alert">
            {err}
          </div>
        )}
        <button type="submit" hidden />
      </form>
    </Modal>
  )
}
