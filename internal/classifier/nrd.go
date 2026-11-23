package classifier

import (
	"bufio"
	"context"
	"fmt"
	"hash/fnv"
	"io"
	"log/slog"
	"net/http"
	"os"
	"slices"
	"strings"
	"sync/atomic"
	"time"
)

// Newly registered domains (NRD): the free hagezi/nrd lists name every domain
// registered in the last days, in weekly bands. A domain on one is young
// whatever RDAP says — and the lists are downloaded whole, so no domain of
// this network is sent anywhere to find out. Millions of names are kept as
// sorted 64-bit hashes (8 bytes each), not strings.

// nrdBand is one list: domains registered at most MaxDays ago.
type nrdBand struct {
	URL     string
	MaxDays int
}

// nrdBands are the lists used: the last week, and the week before.
var nrdBands = []nrdBand{
	{"https://cdn.jsdelivr.net/gh/hagezi/nrd@latest/domains/nrd7.txt", 7},
	{"https://cdn.jsdelivr.net/gh/hagezi/nrd@latest/domains/nrd14-8.txt", 14},
}

const nrdRefreshEvery = 24 * time.Hour

// nrdSet is the loaded bands, each a sorted slice of domain hashes.
type nrdSet struct {
	bands []nrdBand
	sets  [][]uint64
}

func domainHash(d string) uint64 {
	h := fnv.New64a()
	_, _ = h.Write([]byte(d))
	return h.Sum64()
}

// days returns the band a registered domain is in (its maximum age in days),
// or 0 when it is on no list.
func (n *nrdSet) days(domain string) int {
	if n == nil {
		return 0
	}
	h := domainHash(domain)
	for i, s := range n.sets {
		if _, ok := slices.BinarySearch(s, h); ok {
			return n.bands[i].MaxDays
		}
	}
	return 0
}

func (n *nrdSet) count() int {
	if n == nil {
		return 0
	}
	c := 0
	for _, s := range n.sets {
		c += len(s)
	}
	return c
}

// parseNRD reads one list (plain domains, # comments) into a sorted hash set.
func parseNRD(r io.Reader) ([]uint64, error) {
	var out []uint64
	sc := bufio.NewScanner(r)
	sc.Buffer(make([]byte, 0, 64*1024), 1024*1024)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" || line[0] == '#' {
			continue
		}
		out = append(out, domainHash(strings.ToLower(strings.TrimSuffix(line, "."))))
	}
	slices.Sort(out)
	return slices.Compact(out), sc.Err()
}

func openSource(ctx context.Context, src string) (io.ReadCloser, error) {
	if !strings.HasPrefix(src, "http://") && !strings.HasPrefix(src, "https://") {
		return os.Open(src)
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, src, nil)
	if err != nil {
		return nil, err
	}
	resp, err := (&http.Client{Timeout: 5 * time.Minute}).Do(req)
	if err != nil {
		return nil, err
	}
	if resp.StatusCode != http.StatusOK {
		resp.Body.Close()
		return nil, fmt.Errorf("download %s: HTTP %d", src, resp.StatusCode)
	}
	return resp.Body, nil
}

// loadNRD downloads every band; a band that fails is skipped.
func loadNRD(ctx context.Context, bands []nrdBand) (*nrdSet, error) {
	set := &nrdSet{}
	var firstErr error
	for _, b := range bands {
		r, err := openSource(ctx, b.URL)
		if err == nil {
			var s []uint64
			s, err = parseNRD(r)
			r.Close()
			if err == nil {
				set.bands = append(set.bands, b)
				set.sets = append(set.sets, s)
				continue
			}
		}
		slog.Warn("newly-registered-domains list failed", "source", b.URL, "err", err)
		if firstErr == nil {
			firstErr = err
		}
	}
	if len(set.sets) == 0 {
		return nil, firstErr
	}
	return set, nil
}

// NRDLists are loaded newly-registered-domains lists (for classifier-eval).
type NRDLists = nrdSet

// LoadNRDLists downloads the built-in newly-registered-domains lists.
func LoadNRDLists(ctx context.Context) (*NRDLists, error) { return loadNRD(ctx, nrdBands) }

// nrdHolder keeps the lists loaded while the switch is on.
type nrdHolder struct {
	set    atomic.Pointer[nrdSet]
	loaded atomic.Int64 // unix seconds of the last load
	busy   atomic.Bool
}

// ensure loads the lists when on and stale (in the background, never blocking
// a classification), and drops them when off.
func (h *nrdHolder) ensure(on bool) {
	if !on {
		h.set.Store(nil)
		h.loaded.Store(0)
		return
	}
	if time.Since(time.Unix(h.loaded.Load(), 0)) < nrdRefreshEvery || !h.busy.CompareAndSwap(false, true) {
		return
	}
	go func() {
		defer h.busy.Store(false)
		set, err := loadNRD(context.Background(), nrdBands)
		if err != nil {
			slog.Warn("newly-registered-domains lists not loaded", "err", err)
			h.loaded.Store(time.Now().Add(-nrdRefreshEvery + time.Hour).Unix()) // retry in an hour
			return
		}
		h.set.Store(set)
		h.loaded.Store(time.Now().Unix())
		slog.Info("newly-registered-domains lists loaded", "domains", set.count())
	}()
}

func (h *nrdHolder) days(domain string) int { return h.set.Load().days(domain) }
