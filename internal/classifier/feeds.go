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
	{"urlhaus", "abuse.ch URLhaus", "Domains hosting active malware", DefaultThreatURL},
	{"threatfox", "abuse.ch ThreatFox", "Malware IOCs (C2 / payload domains)", "https://threatfox.abuse.ch/downloads/hostfile/"},
	{"phishing_army", "Phishing Army", "Phishing domains (extended blocklist)", "https://phishing.army/download/phishing_army_blocklist_extended.txt"},
	{"hagezi_tif", "HaGeZi TIF", "Aggregated malware/phishing/scam threat-intel feed", "https://raw.githubusercontent.com/hagezi/dns-blocklists/main/domains/tif.txt"},
	{"openphish", "OpenPhish", "Community phishing feed", "https://openphish.com/feed.txt"},
}

// DefaultThreatFeeds are enabled out of the box (good coverage, well-maintained).
var DefaultThreatFeeds = []string{"urlhaus", "threatfox", "phishing_army", "hagezi_tif"}

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
