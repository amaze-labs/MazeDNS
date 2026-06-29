// pollWhileVisible runs fn() on an interval, but only while the tab is visible —
// a backgrounded or forgotten dashboard tab stops hammering the API (the windowed
// aggregations over the cluster-wide query_log are expensive). When the tab
// becomes visible again it fetches once immediately to catch up. Returns a cleanup
// to clear the interval and listener.
//
// The caller is still responsible for the initial fetch on mount.
export function pollWhileVisible(fn: () => void, intervalMs: number): () => void {
  const id = setInterval(() => {
    if (!document.hidden) fn()
  }, intervalMs)
  const onVisible = () => {
    if (!document.hidden) fn()
  }
  document.addEventListener('visibilitychange', onVisible)
  return () => {
    clearInterval(id)
    document.removeEventListener('visibilitychange', onVisible)
  }
}
