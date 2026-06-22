// Package ruleimport parses blocklist/allowlist text in common formats
// (AdGuard, Pi-hole/hosts, plain domain lists) into MazeDNS allow/deny rules.
//
// It supports the widely-used domain subset only: AdGuard network rules of the
// form ||domain^ (and @@||domain^ exceptions) and hosts/plain-domain lines.
// Rules it can't represent as a domain (regex, paths, element hiding, modifiers
// that change the matched host) are skipped.
package ruleimport

import (
	"bufio"
	"net"
	"strings"
)

// Rule is one parsed entry.
type Rule struct {
	Action string // "allow" | "deny"
	Domain string
}

// Parse extracts allow/deny domain rules from text, de-duplicated.
func Parse(text string) []Rule {
	var out []Rule
	seen := make(map[string]struct{})
	add := func(action, domain string) {
		domain = normalize(domain)
		if !validDomain(domain) {
			return
		}
		key := action + " " + domain
		if _, ok := seen[key]; ok {
			return
		}
		seen[key] = struct{}{}
		out = append(out, Rule{Action: action, Domain: domain})
	}

	sc := bufio.NewScanner(strings.NewReader(text))
	sc.Buffer(make([]byte, 0, 64*1024), 1024*1024)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" || strings.HasPrefix(line, "#") || strings.HasPrefix(line, "!") || strings.HasPrefix(line, "[") {
			continue
		}
		switch {
		case strings.HasPrefix(line, "@@||"): // AdGuard exception (allowlist)
			if d, ok := adguardDomain(line[4:]); ok {
				add("allow", d)
			}
		case strings.HasPrefix(line, "||"): // AdGuard network rule (blocklist)
			if d, ok := adguardDomain(line[2:]); ok {
				add("deny", d)
			}
		default:
			fields := strings.Fields(line)
			switch {
			case len(fields) >= 2 && net.ParseIP(fields[0]) != nil: // hosts format
				add("deny", fields[1])
			case len(fields) == 1: // plain domain list
				add("deny", fields[0])
			}
		}
	}
	return out
}

// adguardDomain extracts the host from the body of a ||...^ rule, rejecting
// anything with a path, wildcard, or regex we can't map to a single domain.
func adguardDomain(body string) (string, bool) {
	if i := strings.IndexByte(body, '^'); i >= 0 { // anchor ends the host
		body = body[:i]
	}
	if i := strings.IndexByte(body, '$'); i >= 0 { // strip $modifiers
		body = body[:i]
	}
	body = strings.TrimSpace(body)
	// A bare host only: reject paths, wildcards, regex, ports, alternation.
	if body == "" || strings.ContainsAny(body, "/*?=:|") {
		return "", false
	}
	return body, true
}

func normalize(domain string) string {
	return strings.ToLower(strings.TrimSuffix(strings.TrimSpace(domain), "."))
}

func validDomain(domain string) bool {
	if domain == "" || domain == "localhost" || !strings.Contains(domain, ".") {
		return false
	}
	for _, r := range domain {
		switch {
		case r >= 'a' && r <= 'z', r >= '0' && r <= '9', r == '.', r == '-', r == '_':
		default:
			return false
		}
	}
	return true
}
