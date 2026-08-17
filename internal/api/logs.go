package api

import (
	"encoding/json"
	"net/http"
	"strconv"
	"strings"
	"sync"

	"github.com/IPMaze/MazeDNS/internal/logbuf"
)

// Process-log viewing: the control plane keeps its own slog ring (wired by main
// via SetProcessLogs) plus one in-memory ring per agent, filled by agents
// shipping their recent lines on the poll cycle (POST /api/cluster/proclog).
// Nothing is persisted — history is bounded and lost on restart, like
// `docker logs`.

const (
	nodeProcLogCap  = 1000 // lines kept per agent
	procLogMaxLimit = 1000 // max lines returned by GET /api/logs
	// ControlPlaneLogSource selects the control plane's own ring in GET /api/logs.
	controlPlaneLogSource = "control-plane"
)

// nodeProcLog is one agent's shipped lines plus the dedupe cursor: seq numbers
// restart when the agent reboots, so the cursor is only valid within a boot_id.
type nodeProcLog struct {
	buf     *logbuf.Buffer
	bootID  string
	lastSeq uint64
}

type procLogStore struct {
	mu    sync.Mutex
	self  *logbuf.Buffer // control plane's own ring (may be nil)
	nodes map[string]*nodeProcLog
}

func newProcLogStore() *procLogStore {
	return &procLogStore{nodes: map[string]*nodeProcLog{}}
}

// The methods below tolerate a nil receiver so handlers stay safe on Server
// values built without New (as some tests do).

// ingest appends an agent's shipped lines, dropping any with seq <= the last
// ingested seq of the same boot (re-shipped after a lost response).
func (p *procLogStore) ingest(nodeID, bootID string, entries []logbuf.Entry) int {
	if p == nil {
		return 0
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	nl := p.nodes[nodeID]
	if nl == nil {
		nl = &nodeProcLog{buf: logbuf.New(nodeProcLogCap)}
		p.nodes[nodeID] = nl
	}
	if nl.bootID != bootID {
		nl.bootID = bootID
		nl.lastSeq = 0
	}
	n := 0
	for _, e := range entries {
		if e.Seq <= nl.lastSeq {
			continue
		}
		nl.lastSeq = e.Seq
		// Re-truncate at ingest: the ring is entry-counted, so a hostile agent
		// with a valid node key must not be able to pin memory via huge lines.
		e.Msg = logbuf.Truncate(e.Msg)
		nl.buf.AppendEntry(e)
		n++
	}
	return n
}

// get returns the buffered lines for a source: the control plane's own ring for
// controlPlaneLogSource, else the ring of the node with that id (empty if the
// node never shipped). Oldest first.
func (p *procLogStore) get(source string) []logbuf.Entry {
	if p == nil {
		return nil
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	if source == controlPlaneLogSource {
		if p.self == nil {
			return nil
		}
		return p.self.All()
	}
	if nl := p.nodes[source]; nl != nil {
		return nl.buf.All()
	}
	return nil
}

// forget drops a node's ring (called when the node is deleted or purged).
func (p *procLogStore) forget(nodeID string) {
	if p == nil {
		return
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	delete(p.nodes, nodeID)
}

// SetProcessLogs wires the control plane's own slog ring into the API so
// GET /api/logs can serve it.
func (s *Server) SetProcessLogs(ring *logbuf.Buffer) {
	if s.procLogs == nil {
		s.procLogs = newProcLogStore()
	}
	s.procLogs.self = ring
}

// clusterProcLog ingests a batch of process-log lines shipped by a worker
// (node-key auth), kept in a bounded per-node in-memory ring.
func (s *Server) clusterProcLog(w http.ResponseWriter, r *http.Request) {
	node := s.nodeFromKey(r)
	if node == nil {
		writeError(w, http.StatusUnauthorized, "invalid node key")
		return
	}
	if !node.Approved {
		writeError(w, http.StatusForbidden, "node pending approval")
		return
	}
	var body struct {
		BootID  string         `json:"boot_id"`
		Entries []logbuf.Entry `json:"entries"`
	}
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<20)).Decode(&body); err != nil {
		writeError(w, http.StatusBadRequest, "invalid JSON")
		return
	}
	n := s.procLogs.ingest(node.ID, body.BootID, body.Entries)
	writeJSON(w, http.StatusOK, map[string]any{"ingested": n})
}

// getLogs serves recent process-log lines for one source (admin only — process
// logs can contain client IPs and login usernames). ?source= is
// "control-plane" (default) or a node id; ?level= is the minimum level to
// include; ?search= is a case-insensitive substring match; ?limit= caps the
// returned lines (newest are kept). Entries are returned newest first.
func (s *Server) getLogs(w http.ResponseWriter, r *http.Request) {
	source := r.URL.Query().Get("source")
	if source == "" {
		source = controlPlaneLogSource
	}
	minRank := 0
	if lv := r.URL.Query().Get("level"); lv != "" {
		minRank = logbuf.LevelRank(lv)
	}
	search := strings.ToLower(strings.TrimSpace(r.URL.Query().Get("search")))
	limit := 300
	if v, err := strconv.Atoi(r.URL.Query().Get("limit")); err == nil && v > 0 {
		limit = min(v, procLogMaxLimit)
	}

	all := s.procLogs.get(source)
	kept := make([]logbuf.Entry, 0, len(all))
	for _, e := range all {
		if logbuf.LevelRank(e.Level) < minRank {
			continue
		}
		if search != "" && !strings.Contains(strings.ToLower(e.Msg), search) {
			continue
		}
		kept = append(kept, e)
	}
	if len(kept) > limit {
		kept = kept[len(kept)-limit:] // newest lines win the cap
	}
	// Newest first for display.
	for i, j := 0, len(kept)-1; i < j; i, j = i+1, j-1 {
		kept[i], kept[j] = kept[j], kept[i]
	}
	writeJSON(w, http.StatusOK, map[string]any{"entries": kept})
}
