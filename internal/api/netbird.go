package api

import (
	"context"
	"encoding/json"
	"net/http"
	"strings"
	"time"

	"github.com/IPMaze/MazeDNS/internal/netbird"
)

// resolveClients maps a batch of client IPs to display identities (NetBird peer
// name / reverse-DNS hostname), so any table that shows a client IP can label it.
// IPs are passed comma-separated in ?ips=. Always 200 with {ip: {name, source}}.
func (s *Server) resolveClients(w http.ResponseWriter, r *http.Request) {
	out := map[string]netbird.Identity{}
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

// getNetbird returns the NetBird integration settings (token masked) and the
// number of peers currently mapped.
func (s *Server) getNetbird(w http.ResponseWriter, _ *http.Request) {
	cfg := netbird.LoadSettings(s.store, netbird.Settings{})
	hasToken := cfg.Token != ""
	cfg.Token = "" // never leak the token to the UI
	peers := 0
	if s.enricher != nil {
		peers = s.enricher.PeerCount()
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"settings": cfg, "has_token": hasToken, "peer_count": peers,
	})
}

// putNetbird saves the NetBird settings. An empty token means "leave unchanged"
// so the masked field round-trips.
func (s *Server) putNetbird(w http.ResponseWriter, r *http.Request) {
	var in netbird.Settings
	if err := json.NewDecoder(r.Body).Decode(&in); err != nil {
		writeError(w, http.StatusBadRequest, "invalid JSON")
		return
	}
	in.APIURL = strings.TrimSpace(in.APIURL)
	if in.Token == "" {
		in.Token = netbird.LoadSettings(s.store, netbird.Settings{}).Token
	}
	if err := netbird.SaveSettings(s.store, in); err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	in.Token = ""
	writeJSON(w, http.StatusOK, in)
}

// testNetbird validates the supplied NetBird settings by hitting the API once (an
// empty token falls back to the stored one). Always 200 with an {ok, ...} body.
func (s *Server) testNetbird(w http.ResponseWriter, r *http.Request) {
	var in netbird.Settings
	if err := json.NewDecoder(r.Body).Decode(&in); err != nil {
		writeError(w, http.StatusBadRequest, "invalid JSON")
		return
	}
	if in.Token == "" {
		in.Token = netbird.LoadSettings(s.store, netbird.Settings{}).Token
	}
	ctx, cancel := context.WithTimeout(r.Context(), 15*time.Second)
	defer cancel()
	n, err := netbird.FetchPeerCount(ctx, in)
	if err != nil {
		writeJSON(w, http.StatusOK, map[string]any{"ok": false, "error": err.Error()})
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"ok": true, "peer_count": n})
}
