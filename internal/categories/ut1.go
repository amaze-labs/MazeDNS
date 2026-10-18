package categories

// UT1 is the categorisation database published by Université Toulouse Capitole
// (https://dsi.ut-capitole.fr/blacklists/, CC BY-SA 4.0): about 80 folders of
// domains, each a category. ut1Folders maps the folders we use to our taxonomy;
// the rest (French-specific, redirectors, "drugs", …) are left out rather than
// forced into a wrong label.
var ut1Folders = map[string]string{
	"phishing":            "phishing",
	"malware":             "malware",
	"cryptojacking":       "malware",
	"stalkerware":         "malware",
	"publicite":           "ads",
	"marketingware":       "ads",
	"adult":               "adult",
	"mixed_adult":         "adult",
	"lingerie":            "adult",
	"gambling":            "gambling",
	"arjel":               "gambling",
	"dating":              "dating",
	"social_networks":     "social",
	"forums":              "social",
	"chat":                "chat",
	"audio-video":         "streaming",
	"radio":               "streaming",
	"games":               "gaming",
	"shopping":            "shopping",
	"press":               "news",
	"sports":              "sports",
	"bank":                "finance",
	"financial":           "finance",
	"bitcoin":             "finance",
	"jobsearch":           "jobs",
	"educational_games":   "education",
	"sexual_education":    "education",
	"webmail":             "email",
	"ai":                  "ai",
	"vpn":                 "vpn",
	"residential-proxies": "vpn",
	"filehosting":         "filesharing",
	"download":            "filesharing",
	"warez":               "filesharing",
}

// UT1 download locations: one archive with every category, and one per folder.
const (
	UT1AllURL     = "https://dsi.ut-capitole.fr/blacklists/download/blacklists.tar.gz"
	ut1FolderURLf = "https://dsi.ut-capitole.fr/blacklists/download/%s.tar.gz"
)

// foldersFor returns the UT1 folders that make up the given categories.
func foldersFor(cats []string) []string {
	want := make(map[string]bool, len(cats))
	for _, c := range cats {
		want[c] = true
	}
	var out []string
	for folder, cat := range ut1Folders {
		if want[cat] {
			out = append(out, folder)
		}
	}
	return out
}
