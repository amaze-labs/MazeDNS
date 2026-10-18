package categories

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"context"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"
)

// archive builds a UT1-style tar.gz from file name -> content.
func archive(t *testing.T, files map[string]string) []byte {
	t.Helper()
	var buf bytes.Buffer
	gz := gzip.NewWriter(&buf)
	tw := tar.NewWriter(gz)
	for name, body := range files {
		if err := tw.WriteHeader(&tar.Header{Name: name, Mode: 0o644, Size: int64(len(body)), Typeflag: tar.TypeReg}); err != nil {
			t.Fatal(err)
		}
		_, _ = tw.Write([]byte(body))
	}
	_ = tw.Close()
	_ = gz.Close()
	return buf.Bytes()
}

// ut1Server serves the full archive at /all.tar.gz and one per folder at
// /<folder>.tar.gz, honouring If-Modified-Since. down makes it answer 503.
func ut1Server(t *testing.T) (*httptest.Server, *atomic.Int32, *atomic.Bool) {
	t.Helper()
	all := archive(t, map[string]string{
		"blacklists/social_networks/domains": "facebook.com\ninstagram.com\n",
		"blacklists/adult/domains":           "adult.example\n# a comment\n\n10.0.0.1\n",
		"blacklists/adult/urls":              "adult.example/page\n", // not a domains file
		"blacklists/drogue/domains":          "unmapped.example\n",   // folder we don't use
		"blacklists/publicite/domains":       "ads.example\n",
	})
	adult := archive(t, map[string]string{"adult/domains": "adult.example\nmore-adult.example\n"})
	mixed := archive(t, map[string]string{"mixed_adult/domains": "mixed.example\n"})
	lingerie := archive(t, map[string]string{"lingerie/domains": ""})
	modified := time.Date(2026, 10, 1, 0, 0, 0, 0, time.UTC)
	var hits atomic.Int32
	var down atomic.Bool
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits.Add(1)
		if down.Load() {
			w.WriteHeader(http.StatusServiceUnavailable)
			return
		}
		if ims, err := http.ParseTime(r.Header.Get("If-Modified-Since")); err == nil && !modified.After(ims) {
			w.WriteHeader(http.StatusNotModified)
			return
		}
		w.Header().Set("Last-Modified", modified.Format(http.TimeFormat))
		switch r.URL.Path {
		case "/all.tar.gz":
			_, _ = w.Write(all)
		case "/adult.tar.gz":
			_, _ = w.Write(adult)
		case "/mixed_adult.tar.gz":
			_, _ = w.Write(mixed)
		case "/lingerie.tar.gz":
			_, _ = w.Write(lingerie)
		default:
			http.NotFound(w, r)
		}
	}))
	t.Cleanup(srv.Close)
	return srv, &hits, &down
}

func TestSourceLoadAll(t *testing.T) {
	srv, _, _ := ut1Server(t)
	s := &Source{AllURL: srv.URL + "/all.tar.gz"}
	x, err := s.Load(context.Background(), nil)
	if err != nil {
		t.Fatal(err)
	}
	for name, want := range map[string]string{
		"www.facebook.com": "social", "adult.example": "adult", "ads.example": "ads",
		"unmapped.example": "", "10.0.0.1": "",
	} {
		if got, _ := x.Lookup(name); got != want {
			t.Errorf("%s = %q, want %q", name, got, want)
		}
	}
	if x.Len() != 4 {
		t.Errorf("Len = %d, want 4", x.Len())
	}
}

// An agent loads only the categories it blocks, one archive per UT1 folder.
func TestSourceLoadSomeCategories(t *testing.T) {
	srv, _, _ := ut1Server(t)
	s := &Source{FolderURL: srv.URL + "/%s.tar.gz"}
	x, err := s.Load(context.Background(), []string{"adult"})
	if err != nil {
		t.Fatal(err)
	}
	for name, want := range map[string]string{"more-adult.example": "adult", "mixed.example": "adult", "facebook.com": ""} {
		if got, _ := x.Lookup(name); got != want {
			t.Errorf("%s = %q, want %q", name, got, want)
		}
	}
}

// The archive is cached: an unchanged server answers 304 and the cached copy is
// used; with the server down, the cached copy still loads.
func TestSourceCache(t *testing.T) {
	srv, _, down := ut1Server(t)
	s := &Source{Dir: t.TempDir(), AllURL: srv.URL + "/all.tar.gz"}
	for i, label := range []string{"first download", "not modified"} {
		x, err := s.Load(context.Background(), nil)
		if err != nil || x.Len() != 4 {
			t.Fatalf("%s (%d): len %d err %v", label, i, x.Len(), err)
		}
	}
	down.Store(true)
	x, err := s.Load(context.Background(), nil)
	if err != nil || x.Len() != 4 {
		t.Fatalf("server down: len %d err %v; want the cached copy", x.Len(), err)
	}

	// Nothing cached and the server down: an error, not an empty index.
	if _, err := (&Source{Dir: t.TempDir(), AllURL: srv.URL + "/all.tar.gz"}).Load(context.Background(), nil); err == nil {
		t.Error("no cache, server down: want an error")
	}
}

func TestHolderWanted(t *testing.T) {
	srv, _, _ := ut1Server(t)
	h := NewHolder(&Source{FolderURL: srv.URL + "/%s.tar.gz"}, false)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go h.Run(ctx)

	waitFor := func(cond func() bool) {
		t.Helper()
		deadline := time.Now().Add(3 * time.Second)
		for !cond() {
			if time.Now().After(deadline) {
				t.Fatalf("timed out; status %+v", h.Status())
			}
			time.Sleep(5 * time.Millisecond)
		}
	}
	if _, ok := h.Lookup("adult.example"); ok {
		t.Fatal("nothing wanted yet, but a lookup matched")
	}
	h.SetWanted([]string{"adult"})
	waitFor(func() bool { _, ok := h.Lookup("adult.example"); return ok })
	if st := h.Status(); st.Domains != 3 || st.Counts["adult"] != 3 || st.UpdatedAt == 0 {
		t.Errorf("status = %+v", st)
	}
	h.SetWanted(nil)
	waitFor(func() bool { _, ok := h.Lookup("adult.example"); return !ok })
	if st := h.Status(); st.Domains != 0 {
		t.Errorf("after unblocking everything: status %+v, want the index released", st)
	}
}
