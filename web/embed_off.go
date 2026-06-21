//go:build !embed_dist

// Package web serves the MazeDNS single-page app. Build with -tags embed_dist
// (after `npm --prefix web run build`) to embed the compiled frontend into the
// binary; without the tag, a placeholder is served and no build is required.
package web

import "net/http"

// Handler returns a placeholder explaining how to embed the frontend.
func Handler() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		http.Error(w,
			"MazeDNS UI is not embedded in this build.\n\n"+
				"Build the frontend and rebuild with the embed_dist tag:\n"+
				"  npm --prefix web install && npm --prefix web run build\n"+
				"  go build -tags embed_dist ./cmd/mazedns\n\n"+
				"For development, run `npm --prefix web run dev` (proxies /api to :8080).",
			http.StatusServiceUnavailable)
	})
}
