// Monochrome, stroke-based icon set (Feather/Lucide style). Every glyph inherits
// the current text color via `stroke="currentColor"` and carries no fill, so icons
// read as a calm, consistent set rather than the multi-colored emoji they replace.
import type { SVGProps } from 'react'

type IconName =
  | 'dashboard'
  | 'queries'
  | 'clients'
  | 'filtering'
  | 'rewrites'
  | 'cluster'
  | 'logs'
  | 'settings'
  | 'account'
  | 'brand'
  | 'chevrons-left'
  | 'chevrons-right'
  | 'sun'
  | 'moon'

// Each entry is the inner markup of a 24×24 viewBox icon.
const PATHS: Record<IconName, JSX.Element> = {
  // layout / dashboard
  dashboard: (
    <>
      <rect x="3" y="3" width="7" height="9" rx="1.5" />
      <rect x="14" y="3" width="7" height="5" rx="1.5" />
      <rect x="14" y="12" width="7" height="9" rx="1.5" />
      <rect x="3" y="16" width="7" height="5" rx="1.5" />
    </>
  ),
  // search / requests
  queries: (
    <>
      <circle cx="11" cy="11" r="7" />
      <path d="M21 21l-4.3-4.3" />
    </>
  ),
  // monitor / clients
  clients: (
    <>
      <rect x="2" y="4" width="20" height="13" rx="2" />
      <path d="M8 21h8M12 17v4" />
    </>
  ),
  // shield / filtering
  filtering: <path d="M12 3l7 3v5c0 4.5-3 7.5-7 9-4-1.5-7-4.5-7-9V6l7-3z" />,
  // shuffle / rewrites
  rewrites: (
    <>
      <path d="M16 3h5v5" />
      <path d="M4 20L21 3" />
      <path d="M21 16v5h-5" />
      <path d="M15 15l6 6" />
      <path d="M4 4l5 5" />
    </>
  ),
  // network / cluster
  cluster: (
    <>
      <circle cx="12" cy="5" r="2.5" />
      <circle cx="5" cy="19" r="2.5" />
      <circle cx="19" cy="19" r="2.5" />
      <path d="M12 7.5V12M12 12l-5.2 4.8M12 12l5.2 4.8" />
    </>
  ),
  // scroll-with-lines / logs
  logs: (
    <>
      <path d="M6 3h12a1 1 0 011 1v16a1 1 0 01-1 1H6a1 1 0 01-1-1V4a1 1 0 011-1z" />
      <path d="M9 8h6M9 12h6M9 16h4" />
    </>
  ),
  // sliders / settings
  settings: (
    <>
      <path d="M4 6h10M18 6h2M4 12h2M10 12h10M4 18h6M14 18h6" />
      <circle cx="16" cy="6" r="2" />
      <circle cx="8" cy="12" r="2" />
      <circle cx="12" cy="18" r="2" />
    </>
  ),
  // user / account
  account: (
    <>
      <circle cx="12" cy="8" r="4" />
      <path d="M4 20c0-3.3 3.6-6 8-6s8 2.7 8 6" />
    </>
  ),
  // compass / brand (MazeDNS navigation motif)
  brand: (
    <>
      <circle cx="12" cy="12" r="9" />
      <path d="M15.5 8.5l-2 5-5 2 2-5 5-2z" />
    </>
  ),
  'chevrons-left': <path d="M11 7l-5 5 5 5M18 7l-5 5 5 5" />,
  'chevrons-right': <path d="M13 7l5 5-5 5M6 7l5 5-5 5" />,
  sun: (
    <>
      <circle cx="12" cy="12" r="4" />
      <path d="M12 2v2M12 20v2M4.9 4.9l1.4 1.4M17.7 17.7l1.4 1.4M2 12h2M20 12h2M4.9 19.1l1.4-1.4M17.7 6.3l1.4-1.4" />
    </>
  ),
  moon: <path d="M21 12.8A9 9 0 1111.2 3a7 7 0 009.8 9.8z" />,
}

export function Icon({
  name,
  size = 18,
  ...props
}: { name: IconName; size?: number } & Omit<SVGProps<SVGSVGElement>, 'name'>) {
  return (
    <svg
      width={size}
      height={size}
      viewBox="0 0 24 24"
      fill="none"
      stroke="currentColor"
      strokeWidth={1.75}
      strokeLinecap="round"
      strokeLinejoin="round"
      aria-hidden="true"
      {...props}
    >
      {PATHS[name]}
    </svg>
  )
}

export type { IconName }
