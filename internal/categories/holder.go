package categories

import (
	"context"
	"log/slog"
	"slices"
	"sync"
	"sync/atomic"
	"time"
)

// Refresh intervals: UT1 is republished daily; after a failed load, retry sooner.
const (
	refreshEvery = 24 * time.Hour
	retryEvery   = time.Hour
)

// Status describes the loaded index, for the UI.
type Status struct {
	Categories []string       `json:"categories"` // loaded categories (nil = all)
	Domains    int            `json:"domains"`
	Counts     map[string]int `json:"counts"`
	UpdatedAt  int64          `json:"updated_at"` // unix secs of the last successful load, 0 = never
	Loading    bool           `json:"loading"`
	Error      string         `json:"error,omitempty"`
}

// Holder keeps an Index loaded and refreshed in the background. The control
// plane holds every category (to label all traffic); an agent holds only the
// categories it is told to block (SetWanted), and nothing when there are none.
type Holder struct {
	src *Source
	all bool

	idx  atomic.Pointer[Index]
	kick chan struct{}

	mu     sync.Mutex
	wanted []string // sorted; ignored when all
	status Status
}

// NewHolder returns a Holder for every category (all) or only those set with
// SetWanted.
func NewHolder(src *Source, all bool) *Holder {
	return &Holder{src: src, all: all, kick: make(chan struct{}, 1)}
}

// SetWanted sets the categories to hold (agents) and reloads if they changed.
func (h *Holder) SetWanted(cats []string) {
	cats = slices.Clone(cats)
	slices.Sort(cats)
	cats = slices.Compact(cats)
	h.mu.Lock()
	changed := !slices.Equal(cats, h.wanted)
	h.wanted = cats
	h.mu.Unlock()
	if changed {
		select {
		case h.kick <- struct{}{}:
		default:
		}
	}
}

// Lookup returns name's category from the loaded index.
func (h *Holder) Lookup(name string) (string, bool) { return h.idx.Load().Lookup(name) }

// Status reports what is loaded.
func (h *Holder) Status() Status {
	h.mu.Lock()
	defer h.mu.Unlock()
	return h.status
}

// Run loads the index and keeps it fresh until ctx ends.
func (h *Holder) Run(ctx context.Context) {
	for {
		next := h.load(ctx)
		t := time.NewTimer(next)
		select {
		case <-ctx.Done():
			t.Stop()
			return
		case <-t.C:
		case <-h.kick:
			t.Stop()
		}
	}
}

// load (re)builds the index once and returns when to load next.
func (h *Holder) load(ctx context.Context) time.Duration {
	h.mu.Lock()
	var cats []string
	if !h.all {
		cats = slices.Clone(h.wanted)
	}
	h.status.Loading = true
	h.mu.Unlock()

	if !h.all && len(cats) == 0 {
		h.idx.Store(nil) // nothing to block: free the memory
		h.mu.Lock()
		h.status = Status{Categories: []string{}, Counts: map[string]int{}}
		h.mu.Unlock()
		return refreshEvery
	}
	start := time.Now()
	idx, err := h.src.Load(ctx, cats)
	h.mu.Lock()
	defer h.mu.Unlock()
	h.status.Loading = false
	if err != nil {
		h.status.Error = err.Error()
		slog.Warn("category database load failed", "categories", cats, "err", err)
		return retryEvery
	}
	if !h.all && !slices.Equal(cats, h.wanted) {
		return 0 // the wanted set changed while loading: load again now
	}
	h.idx.Store(idx)
	h.status = Status{Categories: cats, Domains: idx.Len(), Counts: idx.Counts(), UpdatedAt: time.Now().Unix()}
	which := any(cats)
	if h.all {
		which = "all"
	}
	slog.Info("category database loaded", "categories", which, "domains", idx.Len(), "took", time.Since(start).Round(time.Millisecond))
	return refreshEvery
}

// NewLoadedHolder returns a Holder already serving idx, without a source or
// refresh — for tests, and for callers that build an Index themselves.
func NewLoadedHolder(idx *Index) *Holder {
	h := &Holder{kick: make(chan struct{}, 1)}
	h.idx.Store(idx)
	h.status = Status{Domains: idx.Len(), Counts: idx.Counts(), UpdatedAt: time.Now().Unix()}
	return h
}
