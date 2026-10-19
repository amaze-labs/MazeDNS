import { useEffect, useState } from 'react'

// Avatar is a person's picture (an upload or the identity provider's), or
// their initial when there is none or it fails to load. One component for the
// top-bar chip, the account menu, the Account page and the people list.
export default function Avatar({ name, url, size = 34, className = '' }: { name: string; url?: string; size?: number; className?: string }) {
  const [broken, setBroken] = useState(false)
  useEffect(() => setBroken(false), [url])
  const initial = (name.trim()[0] || '?').toUpperCase()
  return (
    <span className={`avatar-pic ${className}`} style={{ width: size, height: size, fontSize: Math.round(size * 0.4) }} aria-hidden="true">
      {url && !broken ? <img src={url} alt="" referrerPolicy="no-referrer" onError={() => setBroken(true)} /> : initial}
    </span>
  )
}
