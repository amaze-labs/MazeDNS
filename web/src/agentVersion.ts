// Whether an agent runs current code. A release rebuilds only the image whose
// code changed, so after a control-plane-only release an agent on an earlier
// version still runs the latest agent code: agentBuild (from GET /api/version)
// names the release that agent code comes from.

const semver = (v: string): number[] | null => (/^\d+\.\d+\.\d+$/.test(v) ? v.split('.').map(Number) : null)

function before(a: number[], b: number[]): boolean {
  for (let i = 0; i < 3; i++) if (a[i] !== b[i]) return a[i] < b[i]
  return false
}

// latestAgent: the newest of what the running control plane knows (its
// agent_build) and what GitHub's releases say (agent_latest): an agent release
// can be out before the control plane is updated.
export function latestAgent(...known: (string | undefined)[]): string {
  let best = ''
  for (const v of known) {
    const p = semver(v ?? '')
    if (p && (!best || before(semver(best)!, p))) best = v!
  }
  return best
}

// versionKnown reports whether the control plane has a comparable version
// (local "dev" builds can't meaningfully flag anyone as outdated).
export const versionKnown = (cp?: string) => !!cp && cp !== 'dev'

// agentOutdated: the agent reports no version (it predates version reporting),
// or one older than the release the latest agent code comes from (latestAgent).
// Without that release (an older or local control plane, no update check),
// anything but the control plane's own version counts as outdated.
export function agentOutdated(app: string, cp?: string, latest?: string): boolean {
  if (!versionKnown(cp)) return false
  if (!app) return true
  const a = semver(app)
  const b = semver(latest ?? '')
  return a && b ? before(a, b) : app !== cp
}
