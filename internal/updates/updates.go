// Package updates tells the control plane whether a newer MazeDNS release
// exists, and what changed since the running one, from the project's GitHub
// releases. It is a read-only, unauthenticated call to a public API, cached
// for hours; MAZEDNS_UPDATE_CHECK=off turns it off (air-gapped installs).
package updates

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"
)

// ReleasesURL lists the project's releases, newest first.
const ReleasesURL = "https://api.github.com/repos/amaze-labs/MazeDNS/releases?per_page=40"

const (
	cacheFor     = 6 * time.Hour    // between automatic checks
	retryAfter   = 15 * time.Minute // after a failed check
	minRefresh   = time.Minute      // between checks someone asked for
	maxNotes     = 16 << 10         // per release
	maxResponse  = 4 << 20          // the whole listing
	shownIfFresh = 5                // releases listed when already up to date
)

// Release is one published version and its notes (markdown).
type Release struct {
	Version     string `json:"version"`
	Name        string `json:"name"`
	PublishedAt string `json:"published_at"`
	URL         string `json:"url"`
	Notes       string `json:"notes"`
	// The release each image's code comes from: Version when the release
	// rebuilt it, an earlier one when it only stamped the new version on it
	// (the notes say "unchanged since X").
	ControlPlaneBuild string `json:"control_plane_build"`
	AgentBuild        string `json:"agent_build"`
}

// Status is what the UI shows.
type Status struct {
	Current         string `json:"current"`
	Latest          string `json:"latest,omitempty"`
	UpdateAvailable bool   `json:"update_available"`
	// Comparable is false for builds that aren't a release (dev, a commit
	// stamp): they can't be placed among the releases.
	Comparable bool      `json:"comparable"`
	Disabled   bool      `json:"disabled,omitempty"`
	CheckedAt  int64     `json:"checked_at,omitempty"` // unix secs
	Error      string    `json:"error,omitempty"`
	Releases   []Release `json:"releases"` // newest first
	// AgentLatest is the release the latest agent code comes from: agents on
	// it or later are current, whatever the latest release number.
	AgentLatest string `json:"agent_latest,omitempty"`
}

// Checker caches the release listing.
type Checker struct {
	current  string
	disabled bool
	url      string
	client   *http.Client

	mu        sync.Mutex
	releases  []Release
	fetchedAt time.Time
	failedAt  time.Time
	err       string
}

// New returns a checker for the running version.
func New(current string, disabled bool) *Checker {
	return &Checker{current: current, disabled: disabled, url: ReleasesURL, client: &http.Client{Timeout: 15 * time.Second}}
}

// Status reports the running version against the releases, refreshing the
// listing when it is stale, or when refresh is set (at most once a minute).
func (c *Checker) Status(ctx context.Context, refresh bool) Status {
	st := Status{Current: c.current, Releases: []Release{}}
	cur, comparable := parse(c.current)
	st.Comparable = comparable
	if c.disabled {
		st.Disabled = true
		return st
	}

	c.mu.Lock()
	defer c.mu.Unlock()
	now := time.Now()
	// Due when never fetched or stale, or sooner when someone asks; after a
	// failure, wait before trying again (less long when asked).
	due := c.fetchedAt.IsZero() || now.Sub(c.fetchedAt) > cacheFor || refresh && now.Sub(c.fetchedAt) > minRefresh
	backoff := retryAfter
	if refresh {
		backoff = minRefresh
	}
	if due && (c.failedAt.IsZero() || now.Sub(c.failedAt) > backoff) {
		if rel, err := c.fetch(ctx); err != nil {
			c.err, c.failedAt = err.Error(), now
		} else {
			c.releases, c.fetchedAt, c.err, c.failedAt = rel, now, "", time.Time{}
		}
	}
	st.Error = c.err
	if !c.fetchedAt.IsZero() {
		st.CheckedAt = c.fetchedAt.Unix()
	}
	if len(c.releases) == 0 {
		return st
	}
	st.Latest = c.releases[0].Version
	st.AgentLatest = c.releases[0].AgentBuild
	if latest, _ := parse(st.Latest); comparable && less(cur, latest) {
		// What an update brings: every release newer than the running one.
		st.UpdateAvailable = true
		for _, r := range c.releases {
			if v, _ := parse(r.Version); !less(cur, v) {
				break
			}
			st.Releases = append(st.Releases, r)
		}
		return st
	}
	st.Releases = head(c.releases, shownIfFresh)
	return st
}

// fetch reads the release listing: published, non-prerelease, semver-tagged
// releases, newest version first.
func (c *Checker) fetch(ctx context.Context) ([]Release, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, c.url, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Accept", "application/vnd.github+json")
	req.Header.Set("User-Agent", "MazeDNS/"+c.current)
	resp, err := c.client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("couldn't reach GitHub: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("GitHub answered %s", resp.Status)
	}
	var raw []struct {
		Tag         string `json:"tag_name"`
		Name        string `json:"name"`
		Body        string `json:"body"`
		URL         string `json:"html_url"`
		PublishedAt string `json:"published_at"`
		Draft       bool   `json:"draft"`
		Prerelease  bool   `json:"prerelease"`
	}
	if err := json.NewDecoder(io.LimitReader(resp.Body, maxResponse)).Decode(&raw); err != nil {
		return nil, fmt.Errorf("unreadable release listing: %w", err)
	}
	var out []Release
	for _, r := range raw {
		if r.Draft || r.Prerelease {
			continue
		}
		if _, ok := parse(r.Tag); !ok {
			continue // the rolling "latest" build, or anything not a version
		}
		notes := r.Body
		if len(notes) > maxNotes {
			notes = notes[:maxNotes] + "\n\n…"
		}
		v := strings.TrimPrefix(r.Tag, "v")
		out = append(out, Release{
			Version: v, Name: r.Name, PublishedAt: r.PublishedAt, URL: r.URL, Notes: notes,
			ControlPlaneBuild: builtAt(r.Body, "control-plane", v),
			AgentBuild:        builtAt(r.Body, "agent", v),
		})
	}
	sort.SliceStable(out, func(i, j int) bool {
		a, _ := parse(out[i].Version)
		b, _ := parse(out[j].Version)
		return less(b, a)
	})
	return out, nil
}

// unchanged matches a release-notes image line that only got the version
// stamped: "`ghcr.io/amaze-labs/mazedns-agent:0.137.0` (unchanged since 0.136.6)".
var unchanged = regexp.MustCompile("mazedns-(control-plane|agent):[^`\\s]*`?\\s*\\(unchanged since v?([0-9]+\\.[0-9]+\\.[0-9]+)\\)")

// builtAt is the release an image's code in release v comes from, read from
// v's notes: v itself unless they say the image is unchanged since an earlier
// one (releases before per-image builds rebuilt both).
func builtAt(notes, image, v string) string {
	for _, m := range unchanged.FindAllStringSubmatch(notes, -1) {
		if m[1] == image {
			return m[2]
		}
	}
	return v
}

type semver [3]int

// parse reads "1.2.3" (an optional leading "v"); anything else isn't a release.
func parse(s string) (semver, bool) {
	var v semver
	parts := strings.Split(strings.TrimPrefix(strings.TrimSpace(s), "v"), ".")
	if len(parts) != 3 {
		return v, false
	}
	for i, p := range parts {
		n, err := strconv.Atoi(p)
		if err != nil || n < 0 {
			return v, false
		}
		v[i] = n
	}
	return v, true
}

func less(a, b semver) bool {
	for i := range a {
		if a[i] != b[i] {
			return a[i] < b[i]
		}
	}
	return false
}

func head(r []Release, n int) []Release {
	if len(r) > n {
		return r[:n]
	}
	return r
}
