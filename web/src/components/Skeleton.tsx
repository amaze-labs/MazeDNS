// Loading placeholders shaped like what they stand in for, with a soft
// shimmer: the page keeps its layout while data arrives, and nothing jumps
// when it does. Purely decorative, so hidden from assistive tech; the card
// around one carries aria-busy.

import type { CSSProperties } from 'react'

// A fixed sequence of heights (percent) so the placeholder chart doesn't
// change shape between renders.
const BAR_HEIGHTS = [38, 52, 44, 61, 70, 58, 47, 66, 82, 74, 63, 55, 49, 60, 72, 86, 78, 64, 57, 50, 45, 59, 68, 54]

export function Skel({ w, h = 12, r, style, className = '' }: { w?: number | string; h?: number | string; r?: number; style?: CSSProperties; className?: string }) {
  return <span className={`skel ${className}`} style={{ width: w, height: h, borderRadius: r, ...style }} aria-hidden="true" />
}

// A stacked-bar chart's worth of columns standing on a baseline.
export function SkelBars({ height, bars = 24 }: { height: number; bars?: number }) {
  return (
    <div className="skel-bars" style={{ height }} aria-hidden="true">
      {BAR_HEIGHTS.slice(0, bars).map((p, i) => (
        <span key={i} className="skel" style={{ height: `${p}%`, animationDelay: `${i * 40}ms` }} />
      ))}
    </div>
  )
}

// A line chart: faint gridlines with a shimmering wave across them.
export function SkelLine({ height }: { height: number }) {
  return (
    <div className="skel-line" style={{ height }} aria-hidden="true">
      <svg viewBox="0 0 400 100" preserveAspectRatio="none">
        <path d="M0 62 C 40 40, 70 70, 110 52 S 180 30, 220 48 S 300 70, 340 44 S 380 36, 400 40" />
      </svg>
    </div>
  )
}

// A donut and its legend.
export function SkelDonut() {
  return (
    <div className="skel-donut" aria-hidden="true">
      <span className="skel ring" />
      <div>
        {[70, 56, 44].map((w) => (
          <div key={w} className="skel-key">
            <Skel w={10} h={10} r={3} />
            <Skel w={`${w}%`} />
            <Skel w={34} />
          </div>
        ))}
      </div>
    </div>
  )
}

// A ranked list: a label and a number over a meter, per row.
export function SkelRank({ rows = 5, columns = 1 }: { rows?: number; columns?: number }) {
  return (
    <div className="skel-rank" style={{ gridTemplateColumns: `repeat(${columns}, minmax(0, 1fr))` }} aria-hidden="true">
      {Array.from({ length: rows * columns }, (_, i) => (
        <div key={i}>
          <span className="skel-rank-head">
            <Skel w={`${40 + ((i * 17) % 35)}%`} />
            <Skel w={42} />
          </span>
          <Skel h={5} r={3} w={`${92 - ((i * 13) % 60)}%`} />
        </div>
      ))}
    </div>
  )
}

// Table rows: one placeholder per cell, the first a little wider.
export function SkelTableRows({ rows = 5, cols }: { rows?: number; cols: number }) {
  return (
    <>
      {Array.from({ length: rows }, (_, r) => (
        <tr key={r} className="skel-row" aria-hidden="true">
          {Array.from({ length: cols }, (_, c) => (
            <td key={c}>
              <Skel w={c === 0 ? `${60 + ((r * 11) % 30)}%` : `${45 + ((r + c) * 9) % 40}%`} />
            </td>
          ))}
        </tr>
      ))}
    </>
  )
}

// Lines of text of varying length (lists, log lines, small panels).
export function SkelList({ rows = 4, gap = 12 }: { rows?: number; gap?: number }) {
  return (
    <div className="skel-list" style={{ gap }} aria-hidden="true">
      {Array.from({ length: rows }, (_, i) => (
        <span key={i} className="skel-list-row">
          <Skel w={`${55 + ((i * 23) % 35)}%`} />
          <Skel w={`${18 + ((i * 7) % 14)}%`} />
        </span>
      ))}
    </div>
  )
}

// A settings section: groups of "title + explanation | fields".
export function SkelGroups({ groups = 3 }: { groups?: number }) {
  return (
    <div aria-hidden="true">
      {Array.from({ length: groups }, (_, g) => (
        <div key={g} className="skel-group">
          <div className="skel-stack">
            <Skel w="55%" h={14} />
            <Skel w="85%" />
            <Skel w="70%" />
          </div>
          <div className="skel-stack">
            <Skel w="30%" />
            <Skel w="100%" h={40} r={12} />
            {g % 2 === 0 && (
              <>
                <Skel w="24%" />
                <Skel w="60%" h={40} r={12} />
              </>
            )}
          </div>
        </div>
      ))}
    </div>
  )
}

// A detail panel: a row of figures, then label/value lines.
export function SkelDetail() {
  return (
    <div className="skel-stack" style={{ gap: 18 }} aria-hidden="true">
      <div className="skel-figures">
        {[0, 1, 2].map((i) => (
          <div key={i} className="skel-stack">
            <Skel w="50%" h={20} />
            <Skel w="70%" />
          </div>
        ))}
      </div>
      <Skel w="100%" h={8} r={4} />
      <SkelList rows={6} gap={14} />
    </div>
  )
}

// A grid of switches (category blocking): a label over a hint, and a toggle.
export function SkelToggles({ count = 12 }: { count?: number }) {
  return (
    <div className="skel-toggles" aria-hidden="true">
      {Array.from({ length: count }, (_, i) => (
        <div key={i}>
          <span className="skel-stack">
            <Skel w={`${40 + ((i * 19) % 40)}%`} />
            <Skel w={`${55 + ((i * 11) % 30)}%`} h={10} />
          </span>
          <Skel w={38} h={22} r={11} />
        </div>
      ))}
    </div>
  )
}

// The page-wide "updating" bar along the top of the window.
export function PageProgress() {
  return <div className="page-progress" role="progressbar" aria-label="Updating" />
}
