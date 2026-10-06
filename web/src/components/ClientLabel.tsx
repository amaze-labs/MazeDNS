import { type ClientIdentity } from '../api'

// Where a client's name came from, in the words the UI uses everywhere.
export const SOURCE_LABEL: Record<string, string> = {
  manual: 'set by you',
  netbird: 'NetBird',
  rewrite: 'from rewrite',
  rdns: 'reverse DNS',
}

// clientName returns the resolved display name for an IP ('' when unknown).
export const clientName = (ip: string, names: Map<string, ClientIdentity>) => names.get(ip)?.name || ''

// ClientLabel renders a client: its resolved name (static name, NetBird peer,
// Local DNS rewrite, or reverse-DNS hostname) followed by the IP, or just the IP
// when no name is known. Pass the map from useClientNames.
//   ip={false}   hide the IP when a name is known (it stays in the tooltip)
//   source       add where the name came from ("reverse DNS", "set by you"…)
export default function ClientLabel({
  ip,
  names,
  showIp = true,
  source = false,
}: {
  ip: string
  names: Map<string, ClientIdentity>
  showIp?: boolean
  source?: boolean
}) {
  const id = names.get(ip)
  if (!id || !id.name) {
    return (
      <span className="mono" style={{ whiteSpace: 'nowrap' }}>
        {ip}
      </span>
    )
  }
  const aliases = id.aliases ?? []
  const src = SOURCE_LABEL[id.source] ?? ''
  const title = [ip, src && `name ${src}`, aliases.length > 0 && `also ${aliases.join(', ')}`].filter(Boolean).join(' · ')
  return (
    <span title={title}>
      <span style={{ fontWeight: 500, color: 'var(--text)' }}>{id.name}</span>
      {showIp && (
        <span className="mono muted" style={{ marginLeft: 6, whiteSpace: 'nowrap' }}>
          {ip}
        </span>
      )}
      {source && src && (
        <span className="faint" style={{ marginLeft: 6, fontSize: 12, whiteSpace: 'nowrap' }}>
          {src}
          {aliases.length > 0 ? ` +${aliases.length}` : ''}
        </span>
      )}
    </span>
  )
}
