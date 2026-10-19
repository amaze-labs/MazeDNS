// Whether an agent runs current code. A release rebuilds only the image whose
// code changed, so after a control-plane-only release an agent on an earlier
// version still runs the latest agent code: agentBuild (from GET /api/version)
// names the release that agent code comes from.

const semver = (v: string): number[] | null => (/^\d+\.\d+\.\d+$/.test(v) ? v.split('.').map(Number) : null)

function before(a: number[], b: number[]): boolean {
  for (let i = 0; i < 3; i++) if (a[i] !== b[i]) return a[i] < b[i]
  return false
}

// versionKnown reports whether the control plane has a comparable version
// (local "dev" builds can't meaningfully flag anyone as outdated).
export const versionKnown = (cp?: string) => !!cp && cp !== 'dev'

// agentOutdated: the agent reports no version (it predates version reporting),
// or one older than the release its current code comes from. Without that
// release (an older or local control plane), anything but the control plane's
// own version counts as outdated.
export function agentOutdated(app: string, cp?: string, agentBuild?: string): boolean {
  if (!versionKnown(cp)) return false
  if (!app) return true
  if (app === cp) return false
  const a = semver(app)
  const b = semver(agentBuild ?? '')
  return a && b ? before(a, b) : true
}
