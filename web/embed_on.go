//go:build embed_dist

package web

import (
	"embed"
	"io/fs"
	"mime"
	"net/http"
	"path"
	"strings"
)

// The web app manifest's type isn't in Go's built-in table (it would go out
// as text/plain, which browsers may ignore).
func init() { _ = mime.AddExtensionType(".webmanifest", "application/manifest+json") }

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
