package categories

import "strings"

// builtin labels the platforms that make up most of a network's DNS traffic
// but that the category database doesn't list: operating-system and cloud
// services, CDNs, the big apps. Without it, the bulk of everyday traffic (an
// iPhone talking to Apple, a laptop to Microsoft, every page to a CDN) lands
// in "other" unless a language model is configured.
//
// Keys are domains matched with every subdomain ("googlevideo.com" covers
// "rr3---sn-x.googlevideo.com"); the most specific key wins, so
// "gemini.google.com" can be AI while "google.com" is search. The category
// database still wins over this list, and an operator's override over both.
var builtin = map[string]string{
	// Search
	"google.com": "search", "google.it": "search", "google.de": "search", "google.fr": "search", "google.co.uk": "search",
	"google.es": "search", "google.ch": "search", "bing.com": "search", "duckduckgo.com": "search", "yahoo.com": "search",
	"ecosia.org": "search", "startpage.com": "search", "qwant.com": "search", "yandex.ru": "search", "baidu.com": "search",
	"brave.com": "search", "search.brave.com": "search",

	// Technology: operating systems, device and developer services
	"apple.com": "technology", "icloud.com": "technology", "icloud-content.com": "technology", "mzstatic.com": "technology",
	"apple-dns.net": "technology", "aaplimg.com": "technology", "cdn-apple.com": "technology", "apple-cloudkit.com": "technology",
	"apple-mapkit.com": "technology", "itunes.com": "technology", "push.apple.com": "technology",
	"microsoft.com": "technology", "windows.com": "technology", "windowsupdate.com": "technology", "msftconnecttest.com": "technology",
	"msftncsi.com": "technology", "msedge.net": "technology", "microsoftonline.com": "productivity", "msn.com": "news",
	"windows.net": "technology", "azure.com": "technology", "azure.net": "technology", "visualstudio.com": "technology",
	"vscode-cdn.net": "technology", "live.net": "technology", "xboxlive.com": "gaming", "xbox.com": "gaming",
	"android.com": "technology", "googleapis.com": "technology", "gstatic.com": "cdn", "googleusercontent.com": "cdn",
	"ggpht.com": "cdn", "gvt1.com": "technology", "gvt2.com": "technology", "gvt3.com": "technology", "googletagservices.com": "ads",
	"google-analytics.com": "trackers", "googletagmanager.com": "trackers", "app-measurement.com": "trackers",
	"firebaseio.com": "technology", "firebase.com": "technology", "firebaseinstallations.googleapis.com": "technology",
	"crashlytics.com": "technology", "chromium.org": "technology", "chrome.com": "technology",
	"samsung.com": "technology", "samsungcloud.com": "technology", "samsungapps.com": "technology", "xiaomi.com": "technology",
	"miui.com": "technology", "huawei.com": "technology", "hicloud.com": "technology", "oneplus.com": "technology",
	"github.com": "technology", "githubusercontent.com": "technology", "github.io": "technology", "githubassets.com": "technology",
	"gitlab.com": "technology", "bitbucket.org": "technology", "docker.io": "technology", "docker.com": "technology",
	"npmjs.org": "technology", "npmjs.com": "technology", "pypi.org": "technology", "pythonhosted.org": "technology",
	"golang.org": "technology", "go.dev": "technology", "rust-lang.org": "technology", "crates.io": "technology",
	"ubuntu.com": "technology", "canonical.com": "technology", "snapcraft.io": "technology", "debian.org": "technology",
	"fedoraproject.org": "technology", "archlinux.org": "technology", "alpinelinux.org": "technology", "kernel.org": "technology",
	"mozilla.org": "technology", "mozilla.net": "technology", "mozilla.com": "technology", "firefox.com": "technology",
	"ntp.org": "technology", "pool.ntp.org": "technology", "time.apple.com": "technology", "letsencrypt.org": "technology",
	"lencr.org": "technology", "digicert.com": "technology", "sectigo.com": "technology", "globalsign.com": "technology",
	"amazonaws.com": "technology", "aws.amazon.com": "technology", "amazontrust.com": "technology", "awsstatic.com": "cdn",
	"cloudflare.com": "technology", "cloudflare-dns.com": "technology", "one.one.one.one": "technology",
	"digitalocean.com": "technology", "hetzner.com": "technology", "ovh.net": "technology", "oraclecloud.com": "technology",
	"tailscale.com": "vpn", "tailscale.io": "vpn", "netbird.io": "vpn", "zerotier.com": "vpn", "wireguard.com": "vpn",
	"nordvpn.com": "vpn", "expressvpn.com": "vpn", "protonvpn.com": "vpn", "mullvad.net": "vpn",
	"ui.com": "technology", "ubnt.com": "technology", "synology.com": "technology", "quickconnect.to": "technology",
	"plex.tv": "streaming", "plex.direct": "streaming", "home-assistant.io": "technology", "nabucasa.com": "technology",
	"tplinkcloud.com": "technology", "tuya.com": "technology", "tuyaeu.com": "technology", "tuyaus.com": "technology",
	"amazonalexa.com": "technology", "alexa.com": "technology", "sonos.com": "technology", "roku.com": "streaming",
	"hp.com": "technology", "hpeprint.com": "technology", "epson.com": "technology", "canon.com": "technology",
	"logitech.com": "technology", "nvidia.com": "technology", "intel.com": "technology", "dell.com": "technology",
	"lenovo.com": "technology", "jetbrains.com": "technology", "sentry.io": "technology", "datadoghq.com": "technology",

	// CDNs and edge networks
	"akamai.net": "cdn", "akamaiedge.net": "cdn", "akamaihd.net": "cdn", "akamaized.net": "cdn", "akadns.net": "cdn",
	"akamaitechnologies.com": "cdn", "edgekey.net": "cdn", "edgesuite.net": "cdn", "cloudfront.net": "cdn",
	"cloudflare.net": "cdn", "cdnjs.cloudflare.com": "cdn", "fastly.net": "cdn", "fastlylb.net": "cdn", "fastly.com": "cdn",
	"azureedge.net": "cdn", "azurefd.net": "cdn", "trafficmanager.net": "cdn", "b-cdn.net": "cdn", "bunny.net": "cdn",
	"jsdelivr.net": "cdn", "unpkg.com": "cdn", "cdnjs.com": "cdn", "llnwd.net": "cdn", "edgecastcdn.net": "cdn",
	"stackpathdns.com": "cdn", "cdn77.org": "cdn", "kxcdn.com": "cdn", "gcore.com": "cdn", "footprint.net": "cdn",

	// Productivity and collaboration
	"office.com": "productivity", "office.net": "productivity", "office365.com": "productivity", "sharepoint.com": "productivity",
	"onedrive.com": "filesharing", "onenote.com": "productivity", "teams.microsoft.com": "chat", "skype.com": "chat",
	"lync.com": "chat", "docs.google.com": "productivity", "drive.google.com": "filesharing", "meet.google.com": "chat",
	"notion.so": "productivity", "notion.com": "productivity", "atlassian.com": "productivity", "atlassian.net": "productivity",
	"trello.com": "productivity", "asana.com": "productivity", "monday.com": "productivity", "figma.com": "productivity",
	"canva.com": "productivity", "miro.com": "productivity", "zoom.us": "chat", "zoom.com": "chat", "webex.com": "chat",
	"slack.com": "chat", "slack-edge.com": "chat", "slack-msgs.com": "chat", "1password.com": "productivity",
	"bitwarden.com": "productivity", "lastpass.com": "productivity", "adobe.com": "productivity", "adobe.io": "productivity",
	"evernote.com": "productivity", "salesforce.com": "productivity", "hubspot.com": "productivity", "zendesk.com": "productivity",

	// File sharing and storage
	"dropbox.com": "filesharing", "dropboxapi.com": "filesharing", "dropboxusercontent.com": "filesharing",
	"box.com": "filesharing", "wetransfer.com": "filesharing", "mega.nz": "filesharing", "mega.io": "filesharing",

	// Email
	"gmail.com": "email", "googlemail.com": "email", "mail.google.com": "email", "outlook.com": "email",
	"outlook.office.com": "email", "outlook.office365.com": "email", "hotmail.com": "email", "live.com": "email",
	"proton.me": "email", "protonmail.com": "email", "protonmail.ch": "email", "mail.yahoo.com": "email",
	"fastmail.com": "email", "zoho.com": "email", "gmx.net": "email", "libero.it": "email", "tim.it": "email",

	// Chat and messaging
	"whatsapp.com": "chat", "whatsapp.net": "chat", "wa.me": "chat", "telegram.org": "chat", "t.me": "chat",
	"signal.org": "chat", "discord.com": "chat", "discord.gg": "chat", "discordapp.com": "chat", "discordapp.net": "chat",
	"messenger.com": "chat", "viber.com": "chat", "line.me": "chat", "wechat.com": "chat", "facetime.apple.com": "chat",

	// Social
	"facebook.com": "social", "facebook.net": "social", "fbcdn.net": "social", "fbsbx.com": "social", "instagram.com": "social",
	"cdninstagram.com": "social", "tiktok.com": "social", "tiktokv.com": "social", "tiktokcdn.com": "social",
	"tiktokcdn-us.com": "social", "byteoversea.com": "social", "ibytedtos.com": "social", "twitter.com": "social", "x.com": "social",
	"twimg.com": "social", "t.co": "social", "linkedin.com": "social", "licdn.com": "social", "reddit.com": "social",
	"redd.it": "social", "redditmedia.com": "social", "redditstatic.com": "social", "pinterest.com": "social", "pinimg.com": "social",
	"snapchat.com": "social", "sc-cdn.net": "social", "threads.net": "social", "tumblr.com": "social", "mastodon.social": "social",
	"bsky.app": "social", "quora.com": "social",

	// Streaming
	"youtube.com": "streaming", "youtu.be": "streaming", "googlevideo.com": "streaming", "ytimg.com": "streaming",
	"youtube-nocookie.com": "streaming", "netflix.com": "streaming", "netflix.net": "streaming", "nflxvideo.net": "streaming",
	"nflximg.net": "streaming", "nflxso.net": "streaming", "nflxext.com": "streaming", "spotify.com": "streaming",
	"scdn.co": "streaming", "spotifycdn.com": "streaming", "twitch.tv": "streaming", "ttvnw.net": "streaming",
	"jtvnw.net": "streaming", "disneyplus.com": "streaming", "disney-plus.net": "streaming", "dssott.com": "streaming",
	"bamgrid.com": "streaming", "primevideo.com": "streaming", "aiv-cdn.net": "streaming", "media-amazon.com": "streaming",
	"hulu.com": "streaming", "hbomax.com": "streaming", "max.com": "streaming", "paramountplus.com": "streaming",
	"dazn.com": "streaming", "deezer.com": "streaming", "soundcloud.com": "streaming", "vimeo.com": "streaming",
	"vimeocdn.com": "streaming", "music.apple.com": "streaming", "tv.apple.com": "streaming", "raiplay.it": "streaming",
	"mediasetplay.mediaset.it": "streaming", "nowtv.it": "streaming", "skyshowtime.com": "streaming", "crunchyroll.com": "streaming",

	// Gaming
	"steampowered.com": "gaming", "steamcommunity.com": "gaming", "steamstatic.com": "gaming", "steamcontent.com": "gaming",
	"steamserver.net": "gaming", "epicgames.com": "gaming", "epicgames.dev": "gaming", "unrealengine.com": "gaming",
	"playstation.net": "gaming", "playstation.com": "gaming", "sonyentertainmentnetwork.com": "gaming", "nintendo.net": "gaming",
	"nintendo.com": "gaming", "riotgames.com": "gaming", "leagueoflegends.com": "gaming", "ea.com": "gaming",
	"origin.com": "gaming", "blizzard.com": "gaming", "battle.net": "gaming", "ubisoft.com": "gaming", "ubi.com": "gaming",
	"roblox.com": "gaming", "rbxcdn.com": "gaming", "minecraft.net": "gaming", "mojang.com": "gaming",
	"rockstargames.com": "gaming", "supercell.com": "gaming",

	// Shopping
	"amazon.com": "shopping", "amazon.it": "shopping", "amazon.de": "shopping", "amazon.fr": "shopping", "amazon.es": "shopping",
	"amazon.co.uk": "shopping", "amazon.nl": "shopping", "ssl-images-amazon.com": "shopping", "images-amazon.com": "shopping",
	"ebay.com": "shopping", "ebay.it": "shopping", "ebay.de": "shopping", "ebayimg.com": "shopping", "aliexpress.com": "shopping",
	"alicdn.com": "shopping", "temu.com": "shopping", "shein.com": "shopping", "zalando.it": "shopping", "zalando.de": "shopping",
	"etsy.com": "shopping", "etsystatic.com": "shopping", "ikea.com": "shopping", "subito.it": "shopping", "vinted.it": "shopping",
	"vinted.com": "shopping", "shopify.com": "shopping", "myshopify.com": "shopping",

	// Finance
	"paypal.com": "finance", "paypalobjects.com": "finance", "stripe.com": "finance", "stripe.network": "finance",
	"revolut.com": "finance", "wise.com": "finance", "satispay.com": "finance", "klarna.com": "finance", "visa.com": "finance",
	"mastercard.com": "finance", "americanexpress.com": "finance", "coinbase.com": "finance", "binance.com": "finance",
	"intesasanpaolo.com": "finance", "unicredit.it": "finance", "poste.it": "finance", "fineco.it": "finance", "n26.com": "finance",

	// AI
	"openai.com": "ai", "chatgpt.com": "ai", "oaistatic.com": "ai", "oaiusercontent.com": "ai", "anthropic.com": "ai",
	"claude.ai": "ai", "claude.com": "ai", "gemini.google.com": "ai", "aistudio.google.com": "ai", "perplexity.ai": "ai",
	"mistral.ai": "ai", "huggingface.co": "ai", "cohere.com": "ai", "midjourney.com": "ai", "copilot.microsoft.com": "ai",
	"deepseek.com": "ai", "x.ai": "ai", "grok.com": "ai", "character.ai": "ai", "poe.com": "ai",

	// News
	"bbc.co.uk": "news", "bbc.com": "news", "bbci.co.uk": "news", "cnn.com": "news", "nytimes.com": "news", "theguardian.com": "news",
	"reuters.com": "news", "bloomberg.com": "news", "ansa.it": "news", "repubblica.it": "news", "corriere.it": "news",
	"lastampa.it": "news", "ilsole24ore.com": "news", "ilpost.it": "news", "rainews.it": "news", "tgcom24.mediaset.it": "news",
	"wikipedia.org": "education", "wikimedia.org": "education", "wiktionary.org": "education",

	// Sports
	"gazzetta.it": "sports", "corrieredellosport.it": "sports", "tuttosport.com": "sports", "espn.com": "sports",
	"skysports.com": "sports", "eurosport.com": "sports", "uefa.com": "sports", "fifa.com": "sports", "nba.com": "sports",

	// Ads and trackers the database may miss
	"doubleclick.net": "ads", "googlesyndication.com": "ads", "googleadservices.com": "ads", "adnxs.com": "ads",
	"criteo.com": "ads", "criteo.net": "ads", "taboola.com": "ads", "outbrain.com": "ads", "adsrvr.org": "ads",
	"amazon-adsystem.com": "ads", "scorecardresearch.com": "trackers", "appsflyer.com": "trackers", "adjust.com": "trackers",
	"branch.io": "trackers", "hotjar.com": "trackers", "mixpanel.com": "trackers", "segment.io": "trackers",
	"segment.com": "trackers", "amplitude.com": "trackers", "newrelic.com": "trackers", "nr-data.net": "trackers",
	"clarity.ms": "trackers",
}

// Builtin returns name's category from the built-in list of common
// platforms: the most specific listed domain that name is or is under.
func Builtin(name string) (string, bool) {
	name = strings.TrimSuffix(strings.ToLower(strings.TrimSpace(name)), ".")
	for name != "" {
		if cat, ok := builtin[name]; ok {
			return cat, true
		}
		i := strings.IndexByte(name, '.')
		if i < 0 {
			break
		}
		name = name[i+1:]
	}
	return "", false
}

// BuiltinDomains returns the built-in list's domains in the given
// categories, for agents (which block categories from the database and need
// these too) — plus any more specific entry under one of them, so an agent
// matching the most specific domain first labels "gemini.google.com" as AI
// even when search (google.com) is blocked, exactly as the control plane does.
func BuiltinDomains(cats map[string]bool) map[string]string {
	out := map[string]string{}
	for d, c := range builtin {
		if cats[c] {
			out[d] = c
		}
	}
	for d, c := range builtin {
		if _, in := out[d]; in {
			continue
		}
		for rest := d; ; {
			i := strings.IndexByte(rest, '.')
			if i < 0 {
				break
			}
			rest = rest[i+1:]
			if _, under := out[rest]; under && cats[out[rest]] {
				out[d] = c
				break
			}
		}
	}
	return out
}
