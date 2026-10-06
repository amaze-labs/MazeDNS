import { useEffect, useState } from 'react'
import { api, type ClientIdentity } from './api'

// Shared client-IP -> identity (static name / NetBird peer / rewrite / reverse-DNS) resolver. Requests
// from every table are coalesced into one debounced batch and cached for the
// session, so the same IP is never looked up twice unless it is invalidated.
const cache = new Map<string, ClientIdentity>()
const inflight = new Set<string>()
const listeners = new Set<() => void>()
// IPs whose cached identity is out of date: re-requested even though cached. The
// old identity keeps showing until the new one arrives, so a name never blinks
// out while it is being refreshed.
const stale = new Set<string>()
let queue = new Set<string>()
let timer: ReturnType<typeof setTimeout> | null = null

// The server resolves at most 500 IPs per request (and a long list would not fit
// in a URL anyway), so big lists go out in chunks.
const CHUNK = 200

const notify = () => listeners.forEach((l) => l())

function schedule() {
  if (!timer && queue.size > 0) timer = setTimeout(flush, 50)
}

function flush() {
  timer = null
  const ips = [...queue].filter((ip) => (!cache.has(ip) || stale.has(ip)) && !inflight.has(ip))
  queue = new Set()
  if (ips.length === 0) return
  for (let i = 0; i < ips.length; i += CHUNK) fetchChunk(ips.slice(i, i + CHUNK))
}

function fetchChunk(ips: string[]) {
  ips.forEach((ip) => {
    inflight.add(ip)
    stale.delete(ip)
  })
  api
    .resolveClients(ips)
    .then((res) => {
      // Cache misses too (empty identity), so an unmapped IP isn't re-requested.
      ips.forEach((ip) => cache.set(ip, res[ip] || { name: '', source: '' }))
    })
    .catch(() => {})
    .finally(() => {
      ips.forEach((ip) => inflight.delete(ip))
      // An IP invalidated while its lookup was in flight got an answer that may
      // predate the change: ask again.
      for (const ip of ips) if (stale.has(ip)) queue.add(ip)
      schedule()
      notify()
    })
}

// invalidateClientName refreshes a cached identity (e.g. after an operator sets a
// static hostname): the IP is looked up again right away and the new name shows
// everywhere without a full reload.
export function invalidateClientName(ip: string) {
  if (!ip) return
  if (cache.has(ip) || inflight.has(ip)) stale.add(ip)
  queue.add(ip)
  schedule()
  notify()
}

// invalidateAllClientNames refreshes every cached identity (e.g. after a Local
// DNS rewrite changes, which can rename any number of clients).
export function invalidateAllClientNames() {
  for (const ip of [...cache.keys(), ...inflight]) {
    stale.add(ip)
    queue.add(ip)
  }
  schedule()
  notify()
}

function request(ips: string[]) {
  for (const ip of ips) {
    if (ip && !cache.has(ip) && !inflight.has(ip)) queue.add(ip)
  }
  schedule()
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
