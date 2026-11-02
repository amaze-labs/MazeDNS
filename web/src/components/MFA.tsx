import { useEffect, useMemo, useState, type FormEvent } from 'react'
import qrcode from 'qrcode-generator'
import { api, type MFASetup, type SessionUser } from '../api'
import '../styles/mfa.css'

// Two-factor sign-in (TOTP) pieces shared by the sign-in page and the account
// page: the QR code, the setup steps and the recovery codes.

// QRCode draws text as an SVG of dark modules, so it follows the theme's
// colours (on a light plate, which scanners need) and needs no inline HTML.
export function QRCode({ text, size = 176 }: { text: string; size?: number }) {
  const { n, path } = useMemo(() => {
    const qr = qrcode(0, 'M')
    qr.addData(text)
    qr.make()
    const n = qr.getModuleCount()
    let path = ''
    for (let r = 0; r < n; r++)
      for (let c = 0; c < n; c++) if (qr.isDark(r, c)) path += `M${c} ${r}h1v1h-1z`
    return { n, path }
  }, [text])
  const pad = 4 // the quiet zone scanners expect
  return (
    <svg
      className="mfa-qr"
      viewBox={`${-pad} ${-pad} ${n + 2 * pad} ${n + 2 * pad}`}
      width={size}
      height={size}
      role="img"
      aria-label="QR code for your authenticator app"
      shapeRendering="crispEdges"
    >
      <rect x={-pad} y={-pad} width={n + 2 * pad} height={n + 2 * pad} fill="#fff" />
      <path d={path} fill="#000" />
    </svg>
  )
}

// CodeInput is the one-time code field: digits for an authenticator code, or a
// recovery code when allowRecovery is set.
export function CodeInput({
  value,
  onChange,
  allowRecovery = false,
  autoFocus = true,
}: {
  value: string
  onChange: (v: string) => void
  allowRecovery?: boolean
  autoFocus?: boolean
}) {
  return (
    <label className="field">
      <span>{allowRecovery ? 'Code from your authenticator app, or a recovery code' : 'Code from your authenticator app'}</span>
      <input
        className="mono mfa-code"
        value={value}
        onChange={(e) => onChange(allowRecovery ? e.target.value : e.target.value.replace(/\D/g, '').slice(0, 6))}
        inputMode={allowRecovery ? 'text' : 'numeric'}
        autoComplete="one-time-code"
        autoCapitalize="none"
        spellCheck={false}
        placeholder={allowRecovery ? '123456 or abcde-fghjk' : '123456'}
        autoFocus={autoFocus}
      />
    </label>
  )
}

// RecoveryCodes shows freshly made recovery codes once, with copy and download.
export function RecoveryCodes({ codes, onDone, doneLabel = 'I’ve saved them' }: { codes: string[]; onDone: () => void; doneLabel?: string }) {
  const [copied, setCopied] = useState(false)
  const text = codes.join('\n') + '\n'
  const copy = async () => {
    try {
      await navigator.clipboard.writeText(text)
      setCopied(true)
    } catch {
      /* the codes stay on screen to copy by hand */
    }
  }
  const download = () => {
    const a = document.createElement('a')
    a.href = URL.createObjectURL(new Blob([text], { type: 'text/plain' }))
    a.download = `mazedns-recovery-codes-${window.location.hostname}.txt`
    a.click()
    URL.revokeObjectURL(a.href)
  }
  return (
    <div className="mfa-recovery">
      <p className="muted">
        Each code signs you in once if you lose your phone. Keep them somewhere safe, like a password manager. They won’t be
        shown again.
      </p>
      <ol className="mono mfa-codes">
        {codes.map((c) => (
          <li key={c}>{c}</li>
        ))}
      </ol>
      <div className="mfa-actions">
        <button type="button" className="btn sm" onClick={copy}>
          {copied ? 'Copied' : 'Copy'}
        </button>
        <button type="button" className="btn sm" onClick={download}>
          Download
        </button>
        <span className="spacer" />
        <button type="button" className="btn primary" onClick={onDone}>
          {doneLabel}
        </button>
      </div>
    </div>
  )
}

// MFASetupSteps enrolls an authenticator: scan (or type) the secret, confirm a
// code. challenge is set during sign-in (the policy requires MFA); without it,
// it acts for the signed-in user. onEnabled gets the recovery codes, and the
// user when this also completed a sign-in.
export function MFASetupSteps({
  challenge,
  onEnabled,
  onCancel,
}: {
  challenge?: string
  onEnabled: (codes: string[], user?: SessionUser) => void
  onCancel?: () => void
}) {
  const [setup, setSetup] = useState<MFASetup | null>(null)
  const [code, setCode] = useState('')
  const [err, setErr] = useState('')
  const [busy, setBusy] = useState(false)
  const [showKey, setShowKey] = useState(false)

  useEffect(() => {
    api
      .mfaSetup(challenge)
      .then(setSetup)
      .catch((e) => setErr(e.message))
  }, [challenge])

  const confirm = async (e: FormEvent) => {
    e.preventDefault()
    setErr('')
    setBusy(true)
    try {
      const r = await api.mfaEnable(code, challenge)
      onEnabled(r.recovery_codes, r.user)
    } catch (e: any) {
      setErr(e.message)
      setCode('')
    } finally {
      setBusy(false)
    }
  }

  return (
    <form className="mfa-setup" onSubmit={confirm}>
      {err && <div className="error">{err}</div>}
      <ol className="mfa-steps">
        <li>
          <b>Scan this with an authenticator app</b>
          <span className="muted small">1Password, Bitwarden, Google Authenticator, Aegis, Microsoft Authenticator…</span>
          <div className="mfa-qr-wrap">{setup ? <QRCode text={setup.uri} /> : <div className="mfa-qr skel" />}</div>
          {setup &&
            (showKey ? (
              <span className="small">
                Or enter this key: <code className="mfa-key">{setup.secret.replace(/(.{4})/g, '$1 ').trim()}</code>
              </span>
            ) : (
              <button type="button" className="btn sm quiet" onClick={() => setShowKey(true)}>
                Can’t scan? Enter a key instead
              </button>
            ))}
        </li>
        <li>
          <b>Enter the code it shows</b>
          <CodeInput value={code} onChange={setCode} autoFocus={false} />
        </li>
      </ol>
      <div className="mfa-actions">
        {onCancel && (
          <button type="button" className="btn quiet" onClick={onCancel}>
            Cancel
          </button>
        )}
        <span className="spacer" />
        <button type="submit" className="btn primary" disabled={busy || !setup || code.length !== 6}>
          {busy ? 'Checking…' : 'Turn on'}
        </button>
      </div>
    </form>
  )
}
