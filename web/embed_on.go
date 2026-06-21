//go:build embed_dist

package web

import (
	"embed"
	"io/fs"
	"net/http"
	"path"
	"strings"
)

//go:embed all:dist
var distFS embed.FS

// Handler serves the embedded SPA, falling back to index.html for client-side
// routes (any path that is not a real file).
func Handler() http.Handler {
	sub, err := fs.Sub(distFS, "dist")
	if err != nil {
		panic(err)
	}
	fileServer := http.FileServer(http.FS(sub))
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		name := path.Clean(strings.TrimPrefix(r.URL.Path, "/"))
		if name == "." {
			name = "index.html"
		}
		if _, statErr := fs.Stat(sub, name); statErr != nil {
			r.URL.Path = "/" // SPA fallback
		}
		fileServer.ServeHTTP(w, r)
	})
}
