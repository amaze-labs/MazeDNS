import { useEffect, useState } from 'react'
import { api, type ClientIdentity } from './api'

// Shared client-IP -> identity (NetBird peer / reverse-DNS) resolver. Requests
// from every table are coalesced into one debounced batch and cached for the
// session, so the same IP is never looked up twice.
const cache = new Map<string, ClientIdentity>()
const inflight = new Set<string>()
const listeners = new Set<() => void>()
let queue = new Set<string>()
let timer: ReturnType<typeof setTimeout> | null = null

function flush() {
  timer = null
  const ips = [...queue].filter((ip) => !cache.has(ip) && !inflight.has(ip))
  queue = new Set()
  if (ips.length === 0) return
  ips.forEach((ip) => inflight.add(ip))
  api
    .resolveClients(ips)
    .then((res) => {
      // Cache misses too (empty identity), so an unmapped IP isn't re-requested.
      ips.forEach((ip) => cache.set(ip, res[ip] || { name: '', source: '' }))
    })
    .catch(() => {})
    .finally(() => {
      ips.forEach((ip) => inflight.delete(ip))
      listeners.forEach((l) => l())
    })
}

function request(ips: string[]) {
  let need = false
  for (const ip of ips) {
    if (ip && !cache.has(ip) && !inflight.has(ip)) {
      queue.add(ip)
      need = true
    }
  }
  if (need && !timer) timer = setTimeout(flush, 50)
}

// useClientNames resolves a set of client IPs and returns a lookup map. It
// re-renders the caller as identities arrive.
export function useClientNames(ips: string[]): Map<string, ClientIdentity> {
  const [, force] = useState(0)
  useEffect(() => {
    const l = () => force((n) => n + 1)
    listeners.add(l)
    return () => {
      listeners.delete(l)
    }
  }, [])
  const key = ips.join(',')
  useEffect(() => {
    request(ips)
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [key])
  return cache
}
