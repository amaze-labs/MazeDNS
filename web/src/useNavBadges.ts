import { useEffect, useState } from 'react'
import { api, type Node } from './api'
import { pollWhileVisible } from './poll'

// Agents count as needing attention when they wait for approval, are offline, or
// haven't applied the config the control plane expects them to run.
const ONLINE_WINDOW = 120 // seconds, matches the Agents page
export const agentNeedsAttention = (n: Node) =>
  !n.approved ||
  !n.last_seen ||
  Date.now() / 1000 - n.last_seen >= ONLINE_WINDOW ||
  (!!n.expected_version && n.version !== n.expected_version)

export interface NavBadges {
  agents: number // agents needing attention
  filtering: number // blocklists whose last refresh failed
}

// useNavBadges polls the few cheap endpoints behind the sidebar counters, so
// problems show up in the navigation instead of only on their own page.
export function useNavBadges(enabled: { agents: boolean; filtering: boolean }): NavBadges {
  const [badges, setBadges] = useState<NavBadges>({ agents: 0, filtering: 0 })
  useEffect(() => {
    if (!enabled.agents && !enabled.filtering) return
    let alive = true
    const load = () => {
      Promise.allSettled([
        enabled.agents ? api.clusterNodes() : Promise.resolve([] as Node[]),
        enabled.filtering ? api.lists() : Promise.resolve([]),
      ]).then(([nodes, lists]) => {
        if (!alive) return
        setBadges({
          agents: nodes.status === 'fulfilled' ? nodes.value.filter(agentNeedsAttention).length : 0,
          filtering: lists.status === 'fulfilled' ? lists.value.filter((l) => l.enabled && l.last_error).length : 0,
        })
      })
    }
    load()
    const stop = pollWhileVisible(load, 30_000)
    return () => {
      alive = false
      stop()
    }
  }, [enabled.agents, enabled.filtering])
  return badges
}
