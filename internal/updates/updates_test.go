package updates

import (
	"context"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
)

const listing = `[
 {"tag_name":"latest","name":"Latest build","body":"rolling","html_url":"u0","published_at":"2026-10-18T10:00:00Z"},
 {"tag_name":"0.129.0","name":"0.129.0","body":"### Features\n- motion","html_url":"u1","published_at":"2026-10-18T09:00:00Z"},
 {"tag_name":"0.130.0-rc1","name":"rc","body":"","html_url":"u2","prerelease":true},
 {"tag_name":"0.128.10","name":"0.128.10","body":"### Fixes\n- a","html_url":"u3","published_at":"2026-10-17T09:00:00Z"},
 {"tag_name":"0.128.2","name":"0.128.2","body":"### Fixes\n- b","html_url":"u4","published_at":"2026-10-16T09:00:00Z"},
 {"tag_name":"0.200.0","name":"draft","body":"","html_url":"u5","draft":true}
]`

func server(t *testing.T, hits *atomic.Int32, status int) *httptest.Server {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits.Add(1)
		if status != http.StatusOK {
			http.Error(w, "nope", status)
			return
		}
		_, _ = w.Write([]byte(listing))
	}))
	t.Cleanup(srv.Close)
	return srv
}

func checker(current, url string) *Checker {
	c := New(current, false)
	c.url = url
	return c
}

// An older release sees every newer release (newest first, numeric order,
// no drafts, pre-releases or the rolling "latest" build).
func TestUpdateAvailable(t *testing.T) {
	var hits atomic.Int32
	srv := server(t, &hits, http.StatusOK)
	st := checker("0.128.2", srv.URL).Status(context.Background(), false)
	if !st.UpdateAvailable || st.Latest != "0.129.0" || !st.Comparable || st.Error != "" {
		t.Fatalf("status = %+v", st)
	}
	if len(st.Releases) != 2 || st.Releases[0].Version != "0.129.0" || st.Releases[1].Version != "0.128.10" {
		t.Errorf("releases = %+v, want 0.129.0 then 0.128.10 (numeric, not lexical, order)", st.Releases)
	}
}

func TestUpToDateAndDev(t *testing.T) {
	var hits atomic.Int32
	srv := server(t, &hits, http.StatusOK)
	st := checker("0.129.0", srv.URL).Status(context.Background(), false)
	if st.UpdateAvailable || st.Latest != "0.129.0" || len(st.Releases) != 3 {
		t.Errorf("up to date: %+v", st)
	}
	dev := checker("dev", srv.URL).Status(context.Background(), false)
	if dev.UpdateAvailable || dev.Comparable || dev.Latest != "0.129.0" || len(dev.Releases) == 0 {
		t.Errorf("dev build: %+v", dev)
	}
}

// The listing is cached; asking for a refresh re-fetches at most once a
// minute; a failure is reported and keeps the last good listing.
func TestCacheAndFailure(t *testing.T) {
	var hits atomic.Int32
	srv := server(t, &hits, http.StatusOK)
	c := checker("0.128.2", srv.URL)
	for i := 0; i < 3; i++ {
		c.Status(context.Background(), i > 0)
	}
	if hits.Load() != 1 {
		t.Errorf("fetched %d times, want 1 (cached, refresh rate-limited)", hits.Load())
	}

	var bad atomic.Int32
	failing := server(t, &bad, http.StatusForbidden)
	f := checker("0.128.2", failing.URL)
	if st := f.Status(context.Background(), false); st.Error == "" || st.UpdateAvailable {
		t.Errorf("failing listing: %+v", st)
	}
	f.Status(context.Background(), false)
	if bad.Load() != 1 {
		t.Errorf("retried a failure %d times at once", bad.Load())
	}
}

func TestDisabled(t *testing.T) {
	var hits atomic.Int32
	srv := server(t, &hits, http.StatusOK)
	c := New("0.128.2", true)
	c.url = srv.URL
	if st := c.Status(context.Background(), true); !st.Disabled || hits.Load() != 0 {
		t.Errorf("disabled: %+v, %d fetches", st, hits.Load())
	}
}
