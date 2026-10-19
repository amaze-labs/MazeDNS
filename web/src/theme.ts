import { useCallback, useEffect, useState } from 'react'

export type Theme = 'light' | 'dark'
// The user's choice: a fixed theme, or follow the operating system.
export type ThemeMode = Theme | 'system'
const KEY = 'mazedns.theme'

const systemTheme = (): Theme => (window.matchMedia('(prefers-color-scheme: light)').matches ? 'light' : 'dark')

function storedMode(): ThemeMode {
  try {
    const v = localStorage.getItem(KEY)
    if (v === 'light' || v === 'dark') return v
  } catch {
    /* storage unavailable: follow the system */
  }
  return 'system'
}

// useTheme exposes the chosen mode, the theme it resolves to, and setMode.
// "system" (the default, stored as no value) follows the OS setting live; the
// pre-paint script in index.html applies the same rule before first render.
export function useTheme(): { mode: ThemeMode; theme: Theme; setMode: (m: ThemeMode) => void; toggle: () => void } {
  const [mode, setModeState] = useState<ThemeMode>(storedMode)
  const [sys, setSys] = useState<Theme>(systemTheme)
  const theme: Theme = mode === 'system' ? sys : mode

  useEffect(() => {
    document.documentElement.setAttribute('data-theme', theme)
  }, [theme])

  useEffect(() => {
    const mq = window.matchMedia('(prefers-color-scheme: light)')
    const onChange = (e: MediaQueryListEvent) => setSys(e.matches ? 'light' : 'dark')
    mq.addEventListener('change', onChange)
    return () => mq.removeEventListener('change', onChange)
  }, [])

  const setMode = useCallback((m: ThemeMode) => {
    setModeState(m)
    try {
      if (m === 'system') localStorage.removeItem(KEY)
      else localStorage.setItem(KEY, m)
    } catch {
      /* the choice just won't persist */
    }
  }, [])

  // toggle flips between light and dark (a fixed choice).
  const toggle = useCallback(() => setMode(theme === 'dark' ? 'light' : 'dark'), [setMode, theme])

  return { mode, theme, setMode, toggle }
}
