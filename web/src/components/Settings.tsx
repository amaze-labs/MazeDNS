import { useEffect, useRef, useState } from 'react'
import { api, type Settings as S, type ForwardGroup, type ClassifierSettings } from '../api'

const linesToList = (s: string) =>
  s.split(/[\n,]+/).map((x) => x.trim()).filter(Boolean)

// onClassifierChange lets the app refresh its nav (the AI tab appears/disappears
// with the classifier's enabled state).
export default function Settings({ onClassifierChange }: { onClassifierChange?: () => void }) {
  const [s, setS] = useState<S | null>(null)
  const [upstreams, setUpstreams] = useState('')
  const [forwarders, setForwarders] = useState<ForwardGroup[]>([])
  const [err, setErr] = useState('')
  const [ok, setOk] = useState(false)
  const [saving, setSaving] = useState(false)
  const [importMode, setImportMode] = useState<'merge' | 'replace'>('merge')
  const [importMsg, setImportMsg] = useState('')
  const fileRef = useRef<HTMLInputElement>(null)

  // Classifier settings (separate endpoint; null until loaded / if unavailable).
  const [cls, setCls] = useState<ClassifierSettings | null>(null)
  const [clsSaving, setClsSaving] = useState(false)
  const [clsOk, setClsOk] = useState(false)

  const load = async () => {
    try {
      const cur = await api.settings()
      setS(cur)
      setUpstreams((cur.upstreams || []).join('\n'))
      setForwarders(cur.forwarders || [])
    } catch (e: any) {
      setErr(e.message)
    }
    api.classifier().then((st) => setCls(st.settings)).catch(() => setCls(null))
  }
  useEffect(() => {
    load()
  }, [])

  const saveClassifier = async () => {
    if (!cls) return
    setClsSaving(true)
    setErr('')
    setClsOk(false)
    try {
      const saved = await api.saveClassifierSettings(cls)
      setCls(saved)
      setClsOk(true)
      onClassifierChange?.()
    } catch (e: any) {
      setErr(e.message)
    } finally {
      setClsSaving(false)
    }
  }

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

  const doExport = async () => {
    setErr('')
    try {
      const blob = await api.exportConfig()
      const url = URL.createObjectURL(blob)
      const a = document.createElement('a')
      a.href = url
      a.download = `mazedns-config-${new Date().toISOString().slice(0, 10)}.json`
      a.click()
      URL.revokeObjectURL(url)
    } catch (e: any) {
      setErr(e.message)
    }
  }

  const doImport = async (file: File) => {
    setErr('')
    setImportMsg('')
    if (
      importMode === 'replace' &&
      !window.confirm('Replace mode clears all existing rules and rewrites before importing. Continue?')
    ) {
      if (fileRef.current) fileRef.current.value = ''
      return
    }
    try {
      const bundle = JSON.parse(await file.text())
      const res = await api.importConfig(bundle, importMode)
      setImportMsg(
        `Imported ${res.rules} rules, ${res.rewrites} rewrites${res.settings ? ', settings applied' : ''} (${res.mode}).`,
      )
      await load()
    } catch (e: any) {
      setErr(e.message)
    } finally {
      if (fileRef.current) fileRef.current.value = ''
    }
  }

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
        <button className="btn ghost" onClick={addFwd}>
          + Add forwarder
        </button>
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
          <label className="toggle">
            <input type="checkbox" checked={s.dnssec} onChange={(e) => patch({ dnssec: e.target.checked })} />
            <span className="track">
              <span className="thumb" />
            </span>
            <span className="toggle-label">Request DNSSEC validation (set DO bit, surface AD)</span>
          </label>
        </div>
      </section>

      <section className="settings-card">
        <h3>Cache</h3>
        <div className="field">
          <label className="toggle">
            <input
              type="checkbox"
              checked={s.cache.enabled}
              onChange={(e) => patchCache({ enabled: e.target.checked })}
            />
            <span className="track">
              <span className="thumb" />
            </span>
            <span className="toggle-label">Enable response cache</span>
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

      <div className="settings-actions">
        <button className="btn primary" onClick={save} disabled={saving}>
          {saving ? 'Saving…' : 'Save & apply'}
        </button>
        <button className="btn ghost-danger" onClick={load} disabled={saving}>
          Reset
        </button>
        <span className="hint">Changes apply live — no restart.</span>
      </div>

      {cls && (
        <section className="settings-card">
          <h3>AI classification (local LLM)</h3>
          <label className="muted">
            Classify newly-seen domains with a local OpenAI-compatible model (Ollama, llama.cpp, LM Studio) instead of
            maintaining blocklists. Runs on the master; auto-blocks also propagate to workers.
          </label>
          {clsOk && <div className="ok-msg">Classifier settings saved.</div>}
          <div className="field">
            <label className="toggle">
              <input type="checkbox" checked={cls.enabled} onChange={(e) => setCls({ ...cls, enabled: e.target.checked })} />
              <span className="track">
                <span className="thumb" />
              </span>
              <span className="toggle-label">Enable classification</span>
            </label>
          </div>
          <div className="field">
            <label>Enforcement mode</label>
            <select value={cls.mode} onChange={(e) => setCls({ ...cls, mode: e.target.value })}>
              <option value="off">Off</option>
              <option value="suggest">Suggest &amp; approve</option>
              <option value="auto">Auto-block</option>
            </select>
          </div>
          <div className="field">
            <label>Model endpoint (OpenAI-compatible base URL)</label>
            <input
              value={cls.endpoint}
              onChange={(e) => setCls({ ...cls, endpoint: e.target.value })}
              placeholder="http://localhost:11434/v1"
            />
          </div>
          <div className="field">
            <label>Model</label>
            <input value={cls.model} onChange={(e) => setCls({ ...cls, model: e.target.value })} placeholder="llama3.2" />
          </div>
          <div className="field">
            <label>API key (optional; usually empty for local models)</label>
            <input
              type="password"
              value={cls.api_key}
              onChange={(e) => setCls({ ...cls, api_key: e.target.value })}
              placeholder="leave blank to keep current"
            />
          </div>
          <div className="field">
            <label>Min gap between model calls (ms)</label>
            <input
              type="number"
              min={0}
              value={cls.min_gap_ms}
              onChange={(e) => setCls({ ...cls, min_gap_ms: Number(e.target.value) })}
            />
          </div>
          <div className="settings-actions">
            <button className="btn primary" onClick={saveClassifier} disabled={clsSaving}>
              {clsSaving ? 'Saving…' : 'Save classifier'}
            </button>
            <span className="hint">Review verdicts in the AI tab.</span>
          </div>
        </section>
      )}

      <section className="settings-card danger-zone">
        <h3>⚠ Danger zone — backup &amp; restore</h3>
        <label className="muted">
          Export downloads settings, rules, and rewrites as one JSON file. Import restores it —
          <em> merge</em> upserts on top of what's here; <em> replace</em> wipes all rules and rewrites first
          (irreversible).
        </label>
        {importMsg && <div className="ok-msg">{importMsg}</div>}
        <div className="row">
          <button className="btn" onClick={doExport}>
            ⬇ Export config
          </button>
          <span className="import-group">
            <select value={importMode} onChange={(e) => setImportMode(e.target.value as 'merge' | 'replace')}>
              <option value="merge">Merge</option>
              <option value="replace">Replace</option>
            </select>
            <button className="btn" onClick={() => fileRef.current?.click()}>
              ⬆ Import file…
            </button>
          </span>
          <input
            ref={fileRef}
            type="file"
            accept="application/json,.json"
            hidden
            onChange={(e) => e.target.files?.[0] && doImport(e.target.files[0])}
          />
        </div>
      </section>
    </div>
  )
}
