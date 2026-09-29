package api

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/IPMaze/MazeDNS/internal/cluster"
	"github.com/IPMaze/MazeDNS/internal/store"
)

const (
	liveWait     = 10 * time.Second // agent long-poll hold, below the agent's 15s client timeout
	livePing     = 15 * time.Second // SSE keep-alive, below common proxy idle timeouts
	liveSubQueue = 512              // entries buffered per viewer before dropping
)

// liveHub fans the queries agents stream in out to the browsers watching the
// Live view. Nothing here is stored: persistence stays with the batched
// query-log shipping.
type liveHub struct {
	mu      sync.Mutex
	subs    map[*liveSub]struct{}
	changed chan struct{} // closed (and replaced) whenever the viewers change
	closing chan struct{} // closed on server shutdown
	once    sync.Once
}

type liveSub struct {
	nodes []string // node names ("" entries never match: the control plane serves no DNS); empty = all
	f     cluster.LiveFilter
	ch    chan store.QueryLogEntry
}

func newLiveHub() *liveHub {
	return &liveHub{subs: map[*liveSub]struct{}{}, changed: make(chan struct{}), closing: make(chan struct{})}
}

func (h *liveHub) close() { h.once.Do(func() { close(h.closing) }) }

// notify wakes every agent long poll; h.mu must be held.
func (h *liveHub) notify() {
	close(h.changed)
	h.changed = make(chan struct{})
}

func (h *liveHub) add(nodes []string, f cluster.LiveFilter) *liveSub {
	sub := &liveSub{nodes: nodes, f: f, ch: make(chan store.QueryLogEntry, liveSubQueue)}
	h.mu.Lock()
	h.subs[sub] = struct{}{}
	h.notify()
	h.mu.Unlock()
	return sub
}

func (h *liveHub) remove(sub *liveSub) {
	h.mu.Lock()
	delete(h.subs, sub)
	h.notify()
	h.mu.Unlock()
}

func (sub *liveSub) watches(node string) bool {
	return len(sub.nodes) == 0 || slices.Contains(sub.nodes, node)
}

// state returns what node should stream, and a channel closed on the next change.
func (h *liveHub) state(node string) (cluster.LiveState, <-chan struct{}) {
	h.mu.Lock()
	defer h.mu.Unlock()
	var fs []cluster.LiveFilter
	for sub := range h.subs {
		if sub.watches(node) {
			fs = append(fs, sub.f)
		}
	}
	return cluster.NewLiveState(fs), h.changed
}

// publish hands node's streamed queries to every viewer that wants them,
// dropping for a viewer whose queue is full.
func (h *liveHub) publish(node string, entries []store.QueryLogEntry) {
	h.mu.Lock()
	defer h.mu.Unlock()
	for sub := range h.subs {
		if !sub.watches(node) {
			continue
		}
		for _, e := range entries {
			if !sub.f.Match(e) {
				continue
			}
			e.Node = node
			select {
			case sub.ch <- e:
			default:
			}
		}
	}
}

// liveFilterFromQuery reads a viewer's filters from the stream URL.
func liveFilterFromQuery(q url.Values) cluster.LiveFilter {
	get := func(k string) string { return strings.TrimSpace(q.Get(k)) }
	return cluster.LiveFilter{
		Client: get("client"), Domain: strings.ToLower(get("domain")), QType: get("qtype"),
		Action: get("action"), Category: get("category"), Rcode: get("rcode"),
	}
}

// streamQueryLog serves the Live view as server-sent events: one "data:" event
// per query (JSON QueryLogEntry) from the agents in ?nodes= (all when empty),
// filtered by ?client= ?domain= ?qtype= ?action= ?category= ?rcode=.
func (s *Server) streamQueryLog(w http.ResponseWriter, r *http.Request) {
	sub := s.live.add(parseNodes(r), liveFilterFromQuery(r.URL.Query()))
	defer s.live.remove(sub)
	rc := http.NewResponseController(w)
	w.Header().Set("Content-Type", "text/event-stream")
	w.Header().Set("Cache-Control", "no-cache")
	w.Header().Set("X-Accel-Buffering", "no") // nginx: don't buffer the stream
	w.WriteHeader(http.StatusOK)
	if err := rc.Flush(); err != nil {
		return
	}
	ping := time.NewTicker(livePing)
	defer ping.Stop()
	for {
		select {
		case <-r.Context().Done():
			return
		case <-s.live.closing:
			return
		case <-ping.C:
			if _, err := fmt.Fprint(w, ": ping\n\n"); err != nil {
				return
			}
		case e := <-sub.ch:
			for more := true; more; {
				b, _ := json.Marshal(e)
				if _, err := fmt.Fprintf(w, "data: %s\n\n", b); err != nil {
					return
				}
				select {
				case e = <-sub.ch:
				default:
					more = false
				}
			}
		}
		if err := rc.Flush(); err != nil {
			return
		}
	}
}

// liveNode authenticates an agent's live-stream request by its node key.
func (s *Server) liveNode(w http.ResponseWriter, r *http.Request) *store.Node {
	node := s.nodeFromKey(r)
	if node == nil {
		writeError(w, http.StatusUnauthorized, "invalid node key")
		return nil
	}
	if !node.Approved {
		writeError(w, http.StatusForbidden, "node pending approval")
		return nil
	}
	return node
}

// clusterLiveState is the agents' long poll: it answers with the filters of the
// viewers watching the node as soon as their version differs from ?have=, or
// after liveWait unchanged.
func (s *Server) clusterLiveState(w http.ResponseWriter, r *http.Request) {
	node := s.liveNode(w, r)
	if node == nil {
		return
	}
	have := r.URL.Query().Get("have")
	timeout := time.NewTimer(liveWait)
	defer timeout.Stop()
	for {
		st, changed := s.live.state(node.Name)
		if st.Version != have {
			writeJSON(w, http.StatusOK, st)
			return
		}
		select {
		case <-changed:
		case <-timeout.C:
			writeJSON(w, http.StatusOK, st)
			return
		case <-r.Context().Done():
			return
		case <-s.live.closing:
			return
		}
	}
}

// clusterLivePush receives a batch of an agent's live queries.
func (s *Server) clusterLivePush(w http.ResponseWriter, r *http.Request) {
	node := s.liveNode(w, r)
	if node == nil {
		return
	}
	var entries []store.QueryLogEntry
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 4<<20)).Decode(&entries); err != nil {
		writeError(w, http.StatusBadRequest, "invalid JSON")
		return
	}
	s.live.publish(node.Name, entries)
	w.WriteHeader(http.StatusNoContent)
}
