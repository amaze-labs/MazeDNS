// Grouping of local records by zone, for the Local DNS page.
//
// Each record goes under the most specific parent domain it shares with at
// least one other record ("pmox01.azzate.ferrario.dev" and
// "*.azzate.ferrario.dev" both under "azzate.ferrario.dev"); a record that
// shares nothing below its registered domain goes under that
// ("management.hatch.ferrario.dev" under "ferrario.dev").

// base is the name a record answers under: a wildcard's suffix, else the name.
const base = (name: string) => name.toLowerCase().replace(/\.$/, '').replace(/^\*\./, '')

// registrable is a light stand-in for the registered domain (no public-suffix
// list here): the last two labels, or three for a two-letter second level
// under a country code ("example.co.uk").
// Private-use top-level names: "nas.lan" and "printer.lan" share "lan".
const localTLDs = new Set(['lan', 'home', 'local', 'internal', 'corp', 'localdomain', 'intranet', 'private', 'test'])

function registrable(name: string): string {
  const labels = name.split('.')
  if (localTLDs.has(labels[labels.length - 1])) return labels.length > 2 ? labels.slice(-2).join('.') : labels[labels.length - 1]
  if (labels.length <= 2) return name
  const n = labels.length
  const cc = labels[n - 1].length === 2 && labels[n - 2].length <= 3 && ['co', 'com', 'net', 'org', 'ac', 'gov', 'edu'].includes(labels[n - 2])
  return labels.slice(cc ? -3 : -2).join('.')
}

// parents lists the zones a record could go under, most specific first: for a
// wildcard its own suffix too, for a name its parents; never above the
// registered domain.
function parents(name: string): string[] {
  const wild = name.toLowerCase().startsWith('*.')
  const b = base(name)
  const reg = registrable(b)
  const out: string[] = []
  let cur = wild ? b : b.slice(b.indexOf('.') + 1)
  if (!wild && b === reg) return [reg]
  while (cur.length >= reg.length) {
    out.push(cur)
    if (cur === reg) break
    const i = cur.indexOf('.')
    if (i < 0) break
    cur = cur.slice(i + 1)
  }
  return out.length ? out : [reg]
}

// zoneFor maps every name to its group.
export function zoneFor(names: string[]): Map<string, string> {
  const bases = names.map(base)
  const under = (zone: string) => bases.filter((b) => b === zone || b.endsWith('.' + zone)).length
  const counts = new Map<string, number>()
  const count = (z: string) => {
    let c = counts.get(z)
    if (c === undefined) {
      c = under(z)
      counts.set(z, c)
    }
    return c
  }
  const out = new Map<string, string>()
  for (const n of names) {
    const ps = parents(n)
    out.set(n, ps.find((z) => count(z) >= 2) ?? ps[ps.length - 1])
  }
  return out
}

// relName is a record's name inside its zone: "pmox01", "*", "@" for the zone
// itself, "*.cloud" for a wildcard below it.
export function relName(name: string, zone: string): string {
  const n = name.toLowerCase().replace(/\.$/, '')
  if (n === zone) return '@'
  return n.endsWith('.' + zone) ? n.slice(0, -(zone.length + 1)) : n
}
