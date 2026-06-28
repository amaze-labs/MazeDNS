import { type ClientIdentity } from '../api'

// ClientLabel renders a client IP, prefixed with its resolved name (NetBird peer
// or reverse-DNS hostname) when one is known. Pass the map from useClientNames.
export default function ClientLabel({ ip, names }: { ip: string; names: Map<string, ClientIdentity> }) {
  const id = names.get(ip)
  if (id && id.name) {
    return (
      <span className="client-id">
        <strong>{id.name}</strong> <span className="muted">{ip}</span>
        {id.source === 'netbird' && (
          <span className="badge info" title="NetBird peer" style={{ marginLeft: 6 }}>
            netbird
          </span>
        )}
      </span>
    )
  }
  return <>{ip}</>
}
