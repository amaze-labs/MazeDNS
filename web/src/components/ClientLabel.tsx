import { type ClientIdentity } from '../api'

// ClientLabel renders a client IP, prefixed with its resolved name (static name,
// NetBird peer, Local DNS rewrite, or reverse-DNS hostname) when one is known.
// Pass the map from useClientNames.
export default function ClientLabel({ ip, names }: { ip: string; names: Map<string, ClientIdentity> }) {
  const id = names.get(ip)
  if (id && id.name) {
    const aliases = id.aliases ?? []
    const alsoKnown = aliases.length > 0 ? `Also: ${aliases.join(', ')}` : undefined
    return (
      <span className="client-id">
        <strong title={alsoKnown}>{id.name}</strong> <span className="muted">{ip}</span>
        {id.source === 'netbird' && (
          <span className="badge info" title="NetBird peer" style={{ marginLeft: 6 }}>
            netbird
          </span>
        )}
        {id.source === 'manual' && (
          <span className="badge allow" title="Static hostname (assigned in the Clients tab)" style={{ marginLeft: 6 }}>
            static
          </span>
        )}
        {id.source === 'rewrite' && (
          <span
            className="badge rewrite"
            title={`Local DNS rewrite${alsoKnown ? ` — ${alsoKnown}` : ''}`}
            style={{ marginLeft: 6 }}
          >
            rewrite{aliases.length > 0 ? ` +${aliases.length}` : ''}
          </span>
        )}
      </span>
    )
  }
  return <>{ip}</>
}
