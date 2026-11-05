package cluster

import (
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
)

// With a pinned master IP, requests to an unresolvable hostname must still reach
// the master (dialed at the IP), proving DNS is bypassed.
func TestMasterTransportPinsIP(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		io.WriteString(w, "ok")
	}))
	defer srv.Close()
	_, port, err := net.SplitHostPort(strings.TrimPrefix(srv.URL, "http://"))
	if err != nil {
		t.Fatal(err)
	}

	client := &http.Client{Transport: masterTransport("127.0.0.1")}
	// A hostname that does not resolve — only the pinned IP can satisfy this.
	resp, err := client.Get("http://master.invalid.local:" + port + "/")
	if err != nil {
		t.Fatalf("request failed despite pinned IP: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d", resp.StatusCode)
	}
}

// Without a pinned IP the same unresolvable host must fail (sanity check).
func TestMasterTransportNoPinFailsDNS(t *testing.T) {
	client := &http.Client{Transport: masterTransport("")}
	if _, err := client.Get("http://master.invalid.local:9/"); err == nil {
		t.Error("expected DNS failure without a pinned IP")
	}
}

// misdirectingServer answers 421 on every request over the first connection it
// accepts (as a proxy does on a connection it no longer serves the host on) and
// echoes the request body on any other connection.
func misdirectingServer(t *testing.T) (*httptest.Server, func() int) {
	t.Helper()
	var mu sync.Mutex
	bad, conns := "", map[string]bool{}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		if bad == "" {
			bad = r.RemoteAddr
		}
		conns[r.RemoteAddr] = true
		misdirected := r.RemoteAddr == bad
		mu.Unlock()
		if misdirected {
			http.Error(w, "Misdirected Request", http.StatusMisdirectedRequest)
			return
		}
		_, _ = io.Copy(w, r.Body)
	}))
	t.Cleanup(srv.Close)
	return srv, func() int { mu.Lock(); defer mu.Unlock(); return len(conns) }
}

// A 421 is retried on a new connection, with the body replayed, and later
// requests keep using the new connection instead of the misdirected one.
func TestMasterTransportRetries421OnNewConnection(t *testing.T) {
	srv, conns := misdirectingServer(t)
	client := &http.Client{Transport: masterTransport("")}
	for i := 0; i < 3; i++ {
		resp, err := client.Post(srv.URL+"/api/cluster/log", "application/json", strings.NewReader(`[1]`))
		if err != nil {
			t.Fatal(err)
		}
		body, _ := io.ReadAll(resp.Body)
		resp.Body.Close()
		if resp.StatusCode != http.StatusOK || string(body) != `[1]` {
			t.Fatalf("request %d: status %d body %q, want 200 [1]", i, resp.StatusCode, body)
		}
	}
	if n := conns(); n != 2 {
		t.Errorf("connections = %d, want 2 (the misdirected one, then one fresh one)", n)
	}
}

// A request whose body can't be rebuilt gets the 421 back; the next one goes
// out on the new connection.
func TestMasterTransport421NotReplayable(t *testing.T) {
	srv, _ := misdirectingServer(t)
	client := &http.Client{Transport: masterTransport("")}
	req, _ := http.NewRequest(http.MethodPost, srv.URL+"/", io.MultiReader(strings.NewReader("x")))
	resp, err := client.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusMisdirectedRequest {
		t.Fatalf("status = %d, want 421", resp.StatusCode)
	}
	resp, err = client.Get(srv.URL + "/")
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("next request: status = %d, want 200", resp.StatusCode)
	}
}
