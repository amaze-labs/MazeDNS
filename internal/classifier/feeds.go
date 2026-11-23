package classifier

// ThreatFeed is a built-in public threat-intelligence source the user can toggle.
type ThreatFeed struct {
	Key  string `json:"key"`
	Name string `json:"name"`
	Desc string `json:"desc"`
	URL  string `json:"url"`
}

// threatFeeds is the catalog of built-in, free, no-auth threat-intel feeds
// (domain / hosts / URL lists). Order is the display order.
var threatFeeds = []ThreatFeed{
	{"urlhaus", "URLhaus (malware-filter mirror)", "Domains hosting active malware", DefaultThreatURL},
	// abuse.ch ThreatFox is gone without an account key (HTTP 410); HaGeZi TIF
	// below aggregates it. A stored "threatfox" choice is simply skipped.
	{"phishing_filter", "malware-filter phishing", "Phishing domains from OpenPhish and PhishTank, cleaned", "https://malware-filter.gitlab.io/malware-filter/phishing-filter-domains.txt"},
	{"phishing_database", "Phishing.Database (active)", "Large community list of active phishing domains", "https://raw.githubusercontent.com/mitchellkrogza/Phishing.Database/master/phishing-domains-ACTIVE.txt"},
	{"phishing_army", "Phishing Army", "Phishing domains (extended blocklist)", "https://phishing.army/download/phishing_army_blocklist_extended.txt"},
	{"hagezi_tif", "HaGeZi TIF", "Aggregated malware/phishing/scam threat-intel feed", "https://raw.githubusercontent.com/hagezi/dns-blocklists/main/wildcard/tif.medium-onlydomains.txt"},
	{"openphish", "OpenPhish", "Community phishing feed", "https://openphish.com/feed.txt"},
}

// DefaultThreatFeeds are enabled out of the box (good coverage, well-maintained).
var DefaultThreatFeeds = []string{"urlhaus", "phishing_army", "hagezi_tif", "phishing_filter"}

// ThreatFeedCatalog returns the built-in feeds (for the UI).
func ThreatFeedCatalog() []ThreatFeed { return threatFeeds }

func threatFeedURL(key string) (string, bool) {
	for _, f := range threatFeeds {
		if f.Key == key {
			return f.URL, true
		}
	}
	return "", false
}

// ThreatFeedURLFor returns a built-in feed's download URL.
func ThreatFeedURLFor(key string) (string, bool) { return threatFeedURL(key) }
