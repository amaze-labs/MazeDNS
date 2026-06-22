import { useEffect, useState } from 'react'
import { api, type Settings as S, type ForwardGroup } from '../api'

const linesToList = (s: string) =>
  s.split(/[\n,]+/).map((x) => x.trim()).filter(Boolean)

export default function Settings() {
  const [s, setS] = useState<S | null>(null)
  const [upstreams, setUpstreams] = useState('')
  const [forwarders, setForwarders] = useState<ForwardGroup[]>([])
  const [err, setErr] = useState('')
  const [ok, setOk] = useState(false)
  const [saving, setSaving] = useState(false)

  const load = async () => {
    try {
      const cur = await api.settings()
      setS(cur)
      setUpstreams((cur.upstreams || []).join('\n'))
      setForwarders(cur.forwarders || [])
    } catch (e: any) {
      setErr(e.message)
    }
  }
  useEffect(() => {
    load()
  }, [])

  if (!s) {
    return (
      <div>
        <h2>Settings</h2>
        {err ? <div className="error">{err}</div> : <p className="muted">Loading…</p>}
      </div>
    )
  }

  const patch = (p: Partial<S>) => setS({ ...s, ...p })
  const patchCache = (p: Partial<S['cache']>) => setS({ ...s, cache: { ...s.cache, ...p } })

  const setFwd = (i: number, f: Partial<ForwardGroup>) =>
    setForwarders(forwarders.map((g, j) => (j === i ? { ...g, ...f } : g)))
  const addFwd = () => setForwarders([...forwarders, { suffix: '', upstreams: [] }])
  const delFwd = (i: number) => setForwarders(forwarders.filter((_, j) => j !== i))

  const save = async () => {
    setSaving(true)
    setErr('')
    setOk(false)
    try {
      const body: S = {
        ...s,
        upstreams: linesToList(upstreams),
        forwarders: forwarders
          .map((g) => ({ suffix: g.suffix.trim(), upstreams: g.upstreams }))
          .filter((g) => g.suffix && g.upstreams.length > 0),
      }
      const saved = await api.saveSettings(body)
      setS(saved)
      setUpstreams((saved.upstreams || []).join('\n'))
      setForwarders(saved.forwarders || [])
      setOk(true)
    } catch (e: any) {
      setErr(e.message)
    } finally {
      setSaving(false)
    }
  }

  return (
    <div className="settings">
      <h2>Settings</h2>
      <p className="muted">
        Operational settings are stored in the database and applied live — no restart needed.
        Bootstrap options (listen addresses, TLS, admin credentials, SSO) stay in the config file / env.
      </p>
      {err && <div className="error">{err}</div>}
      {ok && <div className="ok-msg">Saved and applied.</div>}

      <section className="settings-card">
        <h3>Upstream resolvers</h3>
        <label className="muted">One per line, host:port (e.g. 1.1.1.1:53)</label>
        <textarea
          rows={4}
          value={upstreams}
          onChange={(e) => setUpstreams(e.target.value)}
          placeholder="1.1.1.1:53&#10;9.9.9.9:53"
        />
      </section>

      <section className="settings-card">
        <h3>Conditional forwarders</h3>
        <label className="muted">Route queries for a domain suffix to specific upstreams.</label>
        {forwarders.map((g, i) => (
          <div className="row" key={i}>
            <input
              placeholder="suffix (e.g. lan)"
              value={g.suffix}
              onChange={(e) => setFwd(i, { suffix: e.target.value })}
            />
            <input
              placeholder="upstreams, comma-separated"
              value={g.upstreams.join(', ')}
              onChange={(e) => setFwd(i, { upstreams: linesToList(e.target.value) })}
            />
            <button className="del" onClick={() => delFwd(i)}>
              ✕
            </button>
          </div>
        ))}
        <button onClick={addFwd}>+ Add forwarder</button>
      </section>

      <section className="settings-card">
        <h3>Filtering & protocol</h3>
        <div className="field">
          <label>Block response</label>
          <select value={s.block_response} onChange={(e) => patch({ block_response: e.target.value })}>
            <option value="nxdomain">NXDOMAIN</option>
            <option value="zeroip">Zero IP (0.0.0.0 / ::)</option>
          </select>
        </div>
        <div className="field">
          <label>Rate limit (queries/min per client, 0 = off)</label>
          <input
            type="number"
            min={0}
            value={s.rate_limit_qpm}
            onChange={(e) => patch({ rate_limit_qpm: Number(e.target.value) })}
          />
        </div>
        <div className="field">
          <label>
            <input type="checkbox" checked={s.dnssec} onChange={(e) => patch({ dnssec: e.target.checked })} />{' '}
            Request DNSSEC validation (set DO bit, surface AD)
          </label>
        </div>
      </section>

      <section className="settings-card">
        <h3>Cache</h3>
        <div className="field">
          <label>
            <input
              type="checkbox"
              checked={s.cache.enabled}
              onChange={(e) => patchCache({ enabled: e.target.checked })}
            />{' '}
            Enable response cache
          </label>
        </div>
        <div className="field">
          <label>Max entries</label>
          <input
            type="number"
            min={0}
            value={s.cache.max_entries}
            onChange={(e) => patchCache({ max_entries: Number(e.target.value) })}
          />
        </div>
        <div className="field">
          <label>Min TTL (sec)</label>
          <input
            type="number"
            min={0}
            value={s.cache.min_ttl_sec}
            onChange={(e) => patchCache({ min_ttl_sec: Number(e.target.value) })}
          />
        </div>
        <div className="field">
          <label>Max TTL (sec)</label>
          <input
            type="number"
            min={0}
            value={s.cache.max_ttl_sec}
            onChange={(e) => patchCache({ max_ttl_sec: Number(e.target.value) })}
          />
        </div>
      </section>

      <div className="row">
        <button onClick={save} disabled={saving}>
          {saving ? 'Saving…' : 'Save & apply'}
        </button>
        <button className="del" onClick={load} disabled={saving}>
          Reset
        </button>
      </div>
    </div>
  )
}
