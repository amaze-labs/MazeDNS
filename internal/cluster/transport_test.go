package cluster

import (
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
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
