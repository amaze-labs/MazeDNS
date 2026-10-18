import { useEffect, useRef, useState } from 'react'
import { flushSync } from 'react-dom'

// Motion helpers. Every animation is skipped when the system asks for reduced
// motion; the CSS side does the same with a prefers-reduced-motion rule.

export const reducedMotion = (): boolean =>
  typeof window !== 'undefined' && window.matchMedia('(prefers-reduced-motion: reduce)').matches

// useCountUp eases a number from where it was to `target` (from 0 the first
// time), so a figure that changes visibly counts to its new value instead of
// jumping. Returns the value to show.
export function useCountUp(target: number | null | undefined, ms = 700): number | null {
  const [shown, setShown] = useState<number | null>(target ?? null)
  const from = useRef(0)
  const raf = useRef(0)
  useEffect(() => {
    if (target == null) {
      setShown(null)
      return
    }
    const start = from.current
    if (reducedMotion() || start === target) {
      from.current = target
      setShown(target)
      return
    }
    const t0 = performance.now()
    const step = (now: number) => {
      const p = Math.min(1, (now - t0) / ms)
      const eased = 1 - Math.pow(1 - p, 3) // ease-out cubic
      const v = start + (target - start) * eased
      setShown(p < 1 ? Math.round(v) : target)
      if (p < 1) raf.current = requestAnimationFrame(step)
      else from.current = target
    }
    raf.current = requestAnimationFrame(step)
    return () => {
      cancelAnimationFrame(raf.current)
      from.current = target
    }
  }, [target, ms])
  return shown
}

// withViewTransition runs a state change inside a view transition where the
// browser supports it (a cross-fade between the old and new rendering, used
// for the theme switch), and plainly otherwise.
export function withViewTransition(update: () => void) {
  const doc = document as Document & { startViewTransition?: (cb: () => void) => unknown }
  if (!doc.startViewTransition || reducedMotion()) {
    update()
    return
  }
  doc.startViewTransition(() => flushSync(update))
}

// useFirstPaint is true until shortly after `ready` first becomes true: charts
// animate in once when their data arrives, then stay still through the
// polling refreshes that follow.
export function useFirstPaint(ready: boolean, ms = 900): boolean {
  const [first, setFirst] = useState(true)
  useEffect(() => {
    if (!ready || !first) return
    const t = setTimeout(() => setFirst(false), ms)
    return () => clearTimeout(t)
  }, [ready, first, ms])
  return first && !reducedMotion()
}
