package categories

import (
	"archive/tar"
	"bufio"
	"bytes"
	"compress/gzip"
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"path"
	"path/filepath"
	"strings"
	"time"
)

// maxArchive bounds one downloaded archive (the full UT1 archive is ~26 MB).
const maxArchive = 256 << 20

// Source downloads UT1 archives and builds an Index from them. Archives are
// kept in Dir and re-downloaded only when the server has a newer one, so a
// restart (or an outage of the server) reuses the last good copy.
type Source struct {
	Dir       string       // cache directory ("" = no cache)
	Client    *http.Client // nil = a client with a 2-minute timeout
	AllURL    string       // the every-category archive (UT1AllURL if empty)
	FolderURL string       // per-folder archive, with one %s (ut1FolderURLf if empty)
}

// Load builds an index of the given categories, or of every category when cats
// is nil: the full archive in one download, otherwise one archive per UT1
// folder that makes up those categories.
func (s *Source) Load(ctx context.Context, cats []string) (*Index, error) {
	var b Builder
	if cats == nil {
		if err := s.addArchive(ctx, s.allURL(), "all", nil, &b); err != nil {
			return nil, err
		}
		return b.Build(), nil
	}
	want := make(map[string]bool, len(cats))
	for _, c := range cats {
		want[c] = true
	}
	for _, folder := range foldersFor(cats) {
		url := fmt.Sprintf(s.folderURL(), folder)
		if err := s.addArchive(ctx, url, folder, want, &b); err != nil {
			return nil, fmt.Errorf("%s: %w", folder, err)
		}
	}
	return b.Build(), nil
}

func (s *Source) allURL() string {
	if s.AllURL != "" {
		return s.AllURL
	}
	return UT1AllURL
}

func (s *Source) folderURL() string {
	if s.FolderURL != "" {
		return s.FolderURL
	}
	return ut1FolderURLf
}

func (s *Source) client() *http.Client {
	if s.Client != nil {
		return s.Client
	}
	return &http.Client{Timeout: 2 * time.Minute}
}

// addArchive fetches one archive (or reuses the cached copy) and adds its
// domains to b, keeping only the categories in want (nil = all).
func (s *Source) addArchive(ctx context.Context, url, name string, want map[string]bool, b *Builder) error {
	f, err := s.fetch(ctx, url, name)
	if err != nil {
		return err
	}
	defer f.Close()
	return parseArchive(f, want, b)
}

// fetch returns the archive at url: downloaded if the server has a newer copy
// than the cached one, otherwise (or if the download fails) the cached copy.
func (s *Source) fetch(ctx context.Context, url, name string) (io.ReadCloser, error) {
	cached := ""
	if s.Dir != "" {
		cached = filepath.Join(s.Dir, "ut1-"+name+".tar.gz")
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, err
	}
	if st, err := os.Stat(cached); cached != "" && err == nil {
		req.Header.Set("If-Modified-Since", st.ModTime().UTC().Format(http.TimeFormat))
	}
	resp, err := s.client().Do(req)
	if err == nil {
		defer resp.Body.Close()
	}
	switch {
	case err == nil && resp.StatusCode == http.StatusOK:
		if cached == "" {
			body, rerr := io.ReadAll(io.LimitReader(resp.Body, maxArchive))
			if rerr != nil {
				return nil, rerr
			}
			return io.NopCloser(bytes.NewReader(body)), nil
		}
		if err := saveFile(cached, resp); err != nil {
			return nil, err
		}
	case err == nil && resp.StatusCode == http.StatusNotModified && cached != "":
		// the cached copy is current
	default:
		if err == nil {
			err = fmt.Errorf("status %d", resp.StatusCode)
		}
		if cached == "" {
			return nil, err
		}
		if _, serr := os.Stat(cached); serr != nil {
			return nil, err // nothing cached to fall back on
		}
	}
	return os.Open(cached)
}

// saveFile writes the response body to path atomically, stamped with the
// server's Last-Modified so the next request can ask If-Modified-Since.
func saveFile(path string, resp *http.Response) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return err
	}
	tmp, err := os.CreateTemp(filepath.Dir(path), ".ut1-*")
	if err != nil {
		return err
	}
	defer os.Remove(tmp.Name())
	n, err := io.Copy(tmp, io.LimitReader(resp.Body, maxArchive+1))
	if cerr := tmp.Close(); err == nil {
		err = cerr
	}
	if err != nil {
		return err
	}
	if n > maxArchive {
		return errors.New("archive too large")
	}
	if err := os.Rename(tmp.Name(), path); err != nil {
		return err
	}
	if lm, err := http.ParseTime(resp.Header.Get("Last-Modified")); err == nil {
		_ = os.Chtimes(path, lm, lm)
	}
	return nil
}

// parseArchive reads a UT1 tar.gz: each "<folder>/domains" file (under a
// "blacklists/" prefix in the full archive) lists one domain per line.
func parseArchive(r io.Reader, want map[string]bool, b *Builder) error {
	gz, err := gzip.NewReader(r)
	if err != nil {
		return err
	}
	defer gz.Close()
	tr := tar.NewReader(gz)
	for {
		h, err := tr.Next()
		if errors.Is(err, io.EOF) {
			return nil
		}
		if err != nil {
			return err
		}
		if h.Typeflag != tar.TypeReg || path.Base(h.Name) != "domains" {
			continue
		}
		cat, ok := ut1Folders[path.Base(path.Dir(h.Name))]
		if !ok || (want != nil && !want[cat]) {
			continue
		}
		sc := bufio.NewScanner(tr)
		sc.Buffer(make([]byte, 64*1024), 64*1024)
		for sc.Scan() {
			line := strings.TrimSpace(sc.Text())
			if line == "" || line[0] == '#' || net.ParseIP(line) != nil {
				continue
			}
			b.Add(line, cat)
		}
		if err := sc.Err(); err != nil {
			return err
		}
	}
}
