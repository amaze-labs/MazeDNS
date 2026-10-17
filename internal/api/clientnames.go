package api

import (
	"context"
	"encoding/json"
	"net/http"
	"strings"
	"time"

	"github.com/IPMaze/MazeDNS/internal/clientname"
)

// resolveClients maps a batch of client IPs to display identities (static name /
// rewrite name / reverse-DNS hostname), so any table that shows a client IP can label it.
// IPs are passed comma-separated in ?ips=. Always 200 with {ip: {name, source}}.
func (s *Server) resolveClients(w http.ResponseWriter, r *http.Request) {
	out := map[string]clientname.Identity{}
	if s.enricher == nil {
		writeJSON(w, http.StatusOK, out)
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 8*time.Second)
	defer cancel()
	seen := 0
	for _, ip := range strings.Split(r.URL.Query().Get("ips"), ",") {
		ip = strings.TrimSpace(ip)
		if ip == "" {
			continue
		}
		if _, ok := out[ip]; ok {
			continue
		}
		if seen++; seen > 500 { // bound a single request
			break
		}
		if id := s.enricher.Lookup(ctx, ip); id.Name != "" {
			out[ip] = id
		}
	}
	writeJSON(w, http.StatusOK, out)
}

// getReverseDNS returns the per-node internal DNS resolvers plus the current node
// list, so the UI can offer one resolver field per node (nodes can be in
// different sites).
func (s *Server) getReverseDNS(w http.ResponseWriter, _ *http.Request) {
	resolvers := clientname.LoadResolvers(s.store)
	names := []string{"master"}
	if nodes, err := s.store.ListNodes(); err == nil {
		for _, n := range nodes {
			names = append(names, n.Name)
		}
	}
	writeJSON(w, http.StatusOK, map[string]any{"resolvers": resolvers, "nodes": names})
}

// putReverseDNS replaces the per-node internal DNS resolver map.
func (s *Server) putReverseDNS(w http.ResponseWriter, r *http.Request) {
	var in struct {
		Resolvers map[string]string `json:"resolvers"`
	}
	if err := json.NewDecoder(r.Body).Decode(&in); err != nil {
		writeError(w, http.StatusBadRequest, "invalid JSON")
		return
	}
	clean := map[string]string{}
	for node, addr := range in.Resolvers {
		if a := strings.TrimSpace(addr); a != "" {
			clean[node] = a
		}
	}
	if err := clientname.SaveResolvers(s.store, clean); err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"resolvers": clean})
}
