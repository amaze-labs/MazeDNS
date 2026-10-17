package classifier

import (
	"bufio"
	"context"
	"fmt"
	"io"
	"net"
	"strings"
	"sync"
	"syscall"
	"time"

	"golang.org/x/net/publicsuffix"
)

// Port-43 WHOIS fallback for TLDs without RDAP (.io, .de, many ccTLDs). Without
// it every domain under those TLDs scored "registration date unknown". The
// registry's WHOIS server is found via IANA (whois.iana.org "whois:" line) and
// cached per TLD; the free-text reply is parsed for the handful of fields we use.

// whois43Timeout bounds each port-43 query. Lookups share the RDAP pacing slot,
// so a slow server must not hold it for long.
const whois43Timeout = 5 * time.Second

// whois43QueryFormat is the query syntax for servers that answer a bare domain
// with less data (DENIC returns only the status without "-T dn").
var whois43QueryFormat = map[string]string{
	"whois.denic.de": "-T dn %s",
}

// The IANA referral arrives over plain TCP, so it is untrusted input: the named
// server must look like a public hostname, every connection refuses non-public
// addresses (no reaching internal services on port 43), and referrals expire so
// a poisoned one doesn't stick for the life of the process.
const whoisServerTTL = 24 * time.Hour

type whoisServerEntry struct {
	server string // "" = the TLD has no WHOIS service
	exp    time.Time
}

var (
	whoisServersMu sync.Mutex
	whoisServers   = map[string]whoisServerEntry{} // tld -> registry WHOIS server
)

func lookupWhois43(ctx context.Context, domain string) (WhoisInfo, error) {
	tld := domain[strings.LastIndexByte(domain, '.')+1:]
	// Only real (ICANN) TLDs: a client can query made-up ones at will, and each
	// would otherwise cost an IANA query and a cache entry.
	if _, icann := publicsuffix.PublicSuffix(domain); !icann {
		return WhoisInfo{}, fmt.Errorf("whois: .%s is not a delegated TLD", tld)
	}
	server, err := whoisServerFor(ctx, tld)
	if err != nil {
		return WhoisInfo{}, err
	}
	if server == "" {
		return WhoisInfo{}, fmt.Errorf("whois: no RDAP or WHOIS service for .%s", tld)
	}
	query := domain
	if f, ok := whois43QueryFormat[server]; ok {
		query = fmt.Sprintf(f, domain)
	}
	text, err := whois43Query(ctx, server, query)
	if err != nil {
		return WhoisInfo{}, err
	}
	info := parseWhois43(domain, text)
	if info.Created == "" && info.Registrar == "" && len(info.Nameservers) == 0 {
		return WhoisInfo{}, fmt.Errorf("whois: %s returned no registration data", server)
	}
	return info, nil
}

func whoisServerFor(ctx context.Context, tld string) (string, error) {
	whoisServersMu.Lock()
	e, ok := whoisServers[tld]
	whoisServersMu.Unlock()
	if ok && time.Now().Before(e.exp) {
		return e.server, nil
	}
	text, err := whois43Query(ctx, "whois.iana.org", tld)
	if err != nil {
		return "", err
	}
	server := ""
	for _, line := range strings.Split(text, "\n") {
		if k, v, ok := whoisField(line); ok && (k == "whois" || k == "refer") {
			if !validWhoisHost(v) {
				return "", fmt.Errorf("whois: IANA referral for .%s is not a hostname", tld)
			}
			server = strings.ToLower(v)
			break
		}
	}
	whoisServersMu.Lock()
	if len(whoisServers) < 2048 { // ~1,500 TLDs exist; never grow past that
		whoisServers[tld] = whoisServerEntry{server: server, exp: time.Now().Add(whoisServerTTL)}
	}
	whoisServersMu.Unlock()
	return server, nil
}

// whois43Query sends one query to a WHOIS server and returns its reply.
func whois43Query(ctx context.Context, server, query string) (string, error) {
	ctx, cancel := context.WithTimeout(ctx, whois43Timeout)
	defer cancel()
	d := net.Dialer{Control: publicOnly}
	conn, err := d.DialContext(ctx, "tcp", net.JoinHostPort(server, "43"))
	if err != nil {
		return "", fmt.Errorf("whois: %w", err)
	}
	defer conn.Close()
	if dl, ok := ctx.Deadline(); ok {
		_ = conn.SetDeadline(dl)
	}
	if _, err := io.WriteString(conn, query+"\r\n"); err != nil {
		return "", fmt.Errorf("whois: %w", err)
	}
	b, err := io.ReadAll(io.LimitReader(conn, 256*1024))
	if err != nil && len(b) == 0 {
		return "", fmt.Errorf("whois: %w", err)
	}
	return string(b), nil
}

// validWhoisHost reports whether a referral names a plain DNS hostname (not an
// IP literal, no port or path).
func validWhoisHost(h string) bool {
	if len(h) > 253 || !strings.Contains(h, ".") || net.ParseIP(h) != nil {
		return false
	}
	for _, r := range h {
		if !(r >= 'a' && r <= 'z' || r >= 'A' && r <= 'Z' || r >= '0' && r <= '9' || r == '-' || r == '.') {
			return false
		}
	}
	return true
}

// publicOnly is a net.Dialer Control hook refusing connections to loopback,
// private, link-local, multicast and unspecified addresses, checked after DNS
// resolution so a public-looking name can't point inside the network.
func publicOnly(_, address string, _ syscall.RawConn) error {
	host, _, err := net.SplitHostPort(address)
	if err != nil {
		return err
	}
	ip := net.ParseIP(host)
	if ip == nil || ip.IsLoopback() || ip.IsPrivate() || ip.IsLinkLocalUnicast() || ip.IsLinkLocalMulticast() ||
		ip.IsInterfaceLocalMulticast() || ip.IsMulticast() || ip.IsUnspecified() {
		return fmt.Errorf("whois: refusing non-public address %s", host)
	}
	return nil
}

// whoisField splits a "Key: value" line into a lower-cased key and its value.
func whoisField(line string) (string, string, bool) {
	k, v, ok := strings.Cut(line, ":")
	if !ok {
		return "", "", false
	}
	k = strings.ToLower(strings.TrimSpace(k))
	v = strings.TrimSpace(v)
	return k, v, k != "" && v != ""
}

// parseWhois43 reads the fields registries commonly use (ICANN-style "Creation
// Date:", RIPE-style "created:", DENIC "Changed:", …). The first value wins.
func parseWhois43(domain, text string) WhoisInfo {
	info := WhoisInfo{Domain: domain, Source: "whois"}
	set := func(dst *string, v string) {
		if *dst == "" {
			*dst = v
		}
	}
	sc := bufio.NewScanner(strings.NewReader(text))
	for sc.Scan() {
		k, v, ok := whoisField(sc.Text())
		if !ok {
			continue
		}
		switch k {
		case "creation date", "created", "created on", "registered", "registered on",
			"registration date", "registration time", "domain registration date", "domain record activated":
			set(&info.Created, v)
		case "registry expiry date", "registrar registration expiration date", "expiry date",
			"expiration date", "expires", "expires on", "paid-till", "renewal date":
			set(&info.Expires, v)
		case "updated date", "last updated", "last-update", "changed", "last modified":
			set(&info.Updated, v)
		case "registrar", "sponsoring registrar":
			set(&info.Registrar, v)
		case "registrant organization", "registrant", "org":
			set(&info.Registrant, v)
		case "name server", "nserver", "nameserver", "nameservers":
			if ns := strings.ToLower(strings.TrimSuffix(strings.Fields(v)[0], ".")); ns != "" {
				info.Nameservers = append(info.Nameservers, ns)
			}
		case "domain status", "status":
			info.Status = append(info.Status, strings.Fields(v)[0])
		case "dnssec":
			v = strings.ToLower(v)
			info.DNSSEC = strings.HasPrefix(v, "signed") || v == "yes"
		}
	}
	if strings.Contains(strings.ToLower(info.Registrant), "redacted") {
		info.Registrant = ""
	}
	info.AgeDays = ageDays(info.Created)
	return info
}
