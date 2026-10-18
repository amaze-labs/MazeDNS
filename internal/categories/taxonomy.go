// Package categories labels domains by what they are (social, shopping,
// streaming, ads, …) from a dedicated categorisation database (UT1, published
// by Université Toulouse Capitole), independent of the blocklists a deployment
// happens to use. The control plane uses it to label every query; agents use the
// categories an operator chose to block.
package categories

// Category is one label. Security categories are what the classifier blocks on
// its own judgement; the rest describe legitimate traffic, and are blocked only
// when an operator chooses to block the whole category.
type Category struct {
	ID       string `json:"id"`
	Label    string `json:"label"`
	Security bool   `json:"security"`
}

// All is the taxonomy, in display order.
var All = []Category{
	{"phishing", "Phishing", true},
	{"malware", "Malware", true},
	{"ads", "Ads", true},
	{"trackers", "Trackers", true},
	{"adult", "Adult", false},
	{"gambling", "Gambling", false},
	{"dating", "Dating", false},
	{"social", "Social", false},
	{"chat", "Chat & messaging", false},
	{"streaming", "Streaming", false},
	{"gaming", "Gaming", false},
	{"shopping", "Shopping", false},
	{"news", "News", false},
	{"sports", "Sports", false},
	{"finance", "Finance", false},
	{"jobs", "Jobs", false},
	{"education", "Education", false},
	{"email", "Email", false},
	{"search", "Search", false},
	{"productivity", "Productivity", false},
	{"technology", "Technology", false},
	{"ai", "AI", false},
	{"vpn", "VPN & proxies", false},
	{"filesharing", "File sharing", false},
	{"cdn", "CDN", false},
	{"local", "Local network", false},
	{"other", "Other", false},
}

// Other is the label for a domain nothing knows.
const Other = "other"

// Local labels names that only exist inside a network: reverse lookups
// (in-addr.arpa), private-use TLDs (.lan, .home.arpa, .internal, …) and
// single-label hostnames. It comes from the name itself, never from the
// database or the model, and can't be blocked.
const Local = "local"

// precedence decides a domain listed in several categories (first wins): the
// more specific category first (a messaging app UT1 lists under both chat and
// social networks, like discord.com, is chat). A content category beats a
// security one: UT1's phishing and malware folders also list big legitimate
// brands that are phishing targets (bet365.com is in both gambling and
// phishing), and the classifier judges security on its own.
var precedence = []string{
	"adult", "gambling", "dating", "chat", "social", "streaming", "gaming", "shopping",
	"news", "sports", "finance", "jobs", "education", "email", "search", "productivity",
	"technology", "ai", "vpn", "filesharing", "cdn",
	"ads", "trackers", "malware", "phishing", "local", "other",
}

// byID indexes All; rank is a category's position in precedence (lower wins),
// and also its id in an Index entry (rank+1).
var (
	byID = func() map[string]Category {
		m := make(map[string]Category, len(All))
		for _, c := range All {
			m[c.ID] = c
		}
		return m
	}()
	rank = func() map[string]int {
		m := make(map[string]int, len(precedence))
		for i, id := range precedence {
			m[id] = i
		}
		return m
	}()
)

// Valid reports whether id is a known category.
func Valid(id string) bool {
	_, ok := byID[id]
	return ok
}

// IsSecurity reports whether id is a security category.
func IsSecurity(id string) bool { return byID[id].Security }

// Label returns the display name of id (id itself if unknown).
func Label(id string) string {
	if c, ok := byID[id]; ok {
		return c.Label
	}
	return id
}

// Content returns the IDs of the non-security categories, "other" last — the
// labels the language model may choose from for legitimate traffic ("local"
// isn't one: only the name decides it).
func Content() []string {
	var out []string
	for _, c := range All {
		if !c.Security && c.ID != Local {
			out = append(out, c.ID)
		}
	}
	return out
}
