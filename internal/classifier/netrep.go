package classifier

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"net"
	"net/netip"
	"strconv"
	"strings"
	"sync/atomic"
	"time"
)

// Network reputation from free open data: Spamhaus DROP lists the netblocks
// (and ASN-DROP the whole networks) hijacked or run by criminals — "don't
// route or peer". A domain answering from one is hosted where nothing
// legitimate lives. The address's network (ASN) comes from Team Cymru's free
// DNS service, which only ever sees the address.

var netrepSources = struct{ v4, v6, asn string }{
	"https://www.spamhaus.org/drop/drop_v4.json",
	"https://www.spamhaus.org/drop/drop_v6.json",
	"https://www.spamhaus.org/drop/asndrop.json",
}

const netrepRefreshEvery = 24 * time.Hour

// NetRep is what the network check found for a domain.
type NetRep struct {
	Checked  bool
	IP       string
	ASN      uint32
	ASName   string // from ASN-DROP, when listed
	DropCIDR string // the DROP netblock the address is in
	DropASN  bool   // the address's network is on ASN-DROP
}

// Listed reports whether the domain is hosted on a DROP netblock or network.
func (n NetRep) Listed() bool { return n.DropCIDR != "" || n.DropASN }

type netrepLists struct {
	prefixes []netip.Prefix
	asns     map[uint32]string
}

type netrepHolder struct {
	lists  atomic.Pointer[netrepLists]
	loaded atomic.Int64
	busy   atomic.Bool
	// resolve and asnOf are swapped in tests.
	resolve func(ctx context.Context, domain string) string
	asnOf   func(ctx context.Context, ip netip.Addr) uint32
}

// ensure loads the lists when on and stale (in the background), drops them
// when off.
func (h *netrepHolder) ensure(on bool) {
	if !on {
		h.lists.Store(nil)
		h.loaded.Store(0)
		return
	}
	if time.Since(time.Unix(h.loaded.Load(), 0)) < netrepRefreshEvery || !h.busy.CompareAndSwap(false, true) {
		return
	}
	go func() {
		defer h.busy.Store(false)
		l, err := loadNetrep(context.Background())
		if err != nil {
			slog.Warn("Spamhaus DROP lists not loaded", "err", err)
			h.loaded.Store(time.Now().Add(-netrepRefreshEvery + time.Hour).Unix())
			return
		}
		h.lists.Store(l)
		h.loaded.Store(time.Now().Unix())
		slog.Info("Spamhaus DROP lists loaded", "netblocks", len(l.prefixes), "networks", len(l.asns))
	}()
}

func loadNetrep(ctx context.Context) (*netrepLists, error) {
	l := &netrepLists{asns: map[uint32]string{}}
	for _, src := range []string{netrepSources.v4, netrepSources.v6} {
		err := readJSONLines(ctx, src, func(raw []byte) {
			var e struct {
				CIDR string `json:"cidr"`
			}
			if json.Unmarshal(raw, &e) == nil {
				if p, err := netip.ParsePrefix(e.CIDR); err == nil {
					l.prefixes = append(l.prefixes, p.Masked())
				}
			}
		})
		if err != nil {
			return nil, err
		}
	}
	err := readJSONLines(ctx, netrepSources.asn, func(raw []byte) {
		var e struct {
			ASN    uint32 `json:"asn"`
			ASName string `json:"asname"`
		}
		if json.Unmarshal(raw, &e) == nil && e.ASN != 0 {
			l.asns[e.ASN] = e.ASName
		}
	})
	if err != nil {
		return nil, err
	}
	if len(l.prefixes) == 0 {
		return nil, fmt.Errorf("no DROP netblocks")
	}
	return l, nil
}

// readJSONLines calls fn for every JSON object line of a source (the last,
// metadata line is just another object the callers ignore).
func readJSONLines(ctx context.Context, src string, fn func([]byte)) error {
	r, err := openSource(ctx, src)
	if err != nil {
		return err
	}
	defer r.Close()
	sc := bufio.NewScanner(r)
	for sc.Scan() {
		if line := sc.Bytes(); len(line) > 0 && line[0] == '{' {
			fn(line)
		}
	}
	return sc.Err()
}

// check resolves the domain and checks its address against the lists.
func (h *netrepHolder) check(ctx context.Context, domain string) NetRep {
	l := h.lists.Load()
	if l == nil {
		return NetRep{}
	}
	resolve, asnOf := h.resolve, h.asnOf
	if resolve == nil {
		resolve = resolveIP
	}
	if asnOf == nil {
		asnOf = cymruASN
	}
	ipStr := resolve(ctx, domain)
	ip, err := netip.ParseAddr(ipStr)
	if err != nil {
		return NetRep{}
	}
	ip = ip.Unmap()
	r := NetRep{Checked: true, IP: ip.String()}
	for _, p := range l.prefixes {
		if p.Contains(ip) {
			r.DropCIDR = p.String()
			break
		}
	}
	if r.ASN = asnOf(ctx, ip); r.ASN != 0 {
		if name, ok := l.asns[r.ASN]; ok {
			r.DropASN, r.ASName = true, name
		}
	}
	return r
}

// cymruASN returns the origin network of an address from Team Cymru's free
// DNS service (0 when unknown).
func cymruASN(ctx context.Context, ip netip.Addr) uint32 {
	var q string
	if ip.Is4() {
		b := ip.As4()
		q = fmt.Sprintf("%d.%d.%d.%d.origin.asn.cymru.com", b[3], b[2], b[1], b[0])
	} else {
		b := ip.As16()
		var sb strings.Builder
		for i := 15; i >= 0; i-- {
			fmt.Fprintf(&sb, "%x.%x.", b[i]&0xf, b[i]>>4)
		}
		q = sb.String() + "origin6.asn.cymru.com"
	}
	ctx, cancel := context.WithTimeout(ctx, 3*time.Second)
	defer cancel()
	txts, err := net.DefaultResolver.LookupTXT(ctx, q)
	if err != nil || len(txts) == 0 {
		return 0
	}
	return parseCymru(txts[0])
}

// parseCymru reads the first ASN of a reply like "13335 | 1.1.1.0/24 | US | apnic | 2011-08-11".
func parseCymru(txt string) uint32 {
	f := strings.Fields(strings.SplitN(txt, "|", 2)[0])
	if len(f) == 0 {
		return 0
	}
	n, err := strconv.ParseUint(f[0], 10, 32)
	if err != nil {
		return 0
	}
	return uint32(n)
}
