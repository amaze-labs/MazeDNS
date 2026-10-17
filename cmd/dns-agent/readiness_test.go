package main

import (
	"bytes"
	"context"
	"encoding/json"
	"net"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/IPMaze/MazeDNS/internal/cluster"
	"github.com/IPMaze/MazeDNS/internal/config"
	"github.com/IPMaze/MazeDNS/internal/resolver"
)

func TestProbeAddr(t *testing.T) {
	for in, want := range map[string]string{
		"0.0.0.0:53":    "127.0.0.1:53",
		":53":           "127.0.0.1:53",
		"[::]:53":       "[::1]:53",
		"10.0.0.7:5353": "10.0.0.7:5353",
	} {
		if got := probeAddr(in); got != want {
			t.Errorf("probeAddr(%q) = %q, want %q", in, got, want)
		}
	}
}

// startDNS runs a real DNS server on a free loopback port and waits until both
// listeners are up.
func startDNS(t *testing.T, res *resolver.Resolver) *resolver.Server {
	t.Helper()
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	addr := l.Addr().String()
	l.Close()

	t.Setenv("MAZEDNS_UDP_LISTENERS", "1")
	srv := resolver.NewServer(addr, res)
	errc := make(chan error, 1)
	go func() { errc <- srv.ListenAndServe() }()
	t.Cleanup(func() { srv.Shutdown(context.Background()) })
	deadline := time.Now().Add(3 * time.Second)
	for {
		select {
		case err := <-errc:
			t.Skipf("cannot bind %s: %v", addr, err)
		default:
		}
		if udp, tcp := srv.Listening(); udp && tcp {
			return srv
		}
		if time.Now().After(deadline) {
			t.Fatal("listeners never came up")
		}
		time.Sleep(10 * time.Millisecond)
	}
}

func getReady(t *testing.T, rd *readiness) (int, readyReport) {
	t.Helper()
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/readyz", nil)
	req.RemoteAddr = "127.0.0.1:40000" // the full report is for this host only
	rd.ServeHTTP(rec, req)
	var rep readyReport
	if err := json.Unmarshal(rec.Body.Bytes(), &rep); err != nil {
		t.Fatalf("decode %q: %v", rec.Body.String(), err)
	}
	return rec.Code, rep
}

// /readyz is 200 when the listener answers the probe over UDP and TCP — with no
// upstream and a control plane that was never reached, since neither is needed
// to serve local records — and 503 in maintenance or with the listener down.
func TestReadyz(t *testing.T) {
	res := resolver.New(resolver.Options{})
	srv := startDNS(t, res)
	sync := &cluster.SyncHealth{}
	rd := &readiness{res: res, srv: srv, sync: sync}

	code, rep := getReady(t, rd)
	if code != http.StatusOK || !rep.Ready || !rep.UDP.OK || !rep.TCP.OK {
		t.Fatalf("live listener: code=%d rep=%+v", code, rep)
	}
	if rep.ControlPlane == nil || rep.ControlPlane.LastSyncOK != "" || rep.Standalone {
		t.Fatalf("control plane state: %+v", rep)
	}

	res.SetMaintenance(true)
	code, rep = getReady(t, rd)
	if code != http.StatusServiceUnavailable || rep.Ready || !rep.Maintenance || !rep.UDP.OK {
		t.Fatalf("maintenance: code=%d rep=%+v", code, rep)
	}
	res.SetMaintenance(false)

	rd.sync = nil
	if _, rep = getReady(t, rd); !rep.Standalone || rep.ControlPlane != nil {
		t.Fatalf("standalone: %+v", rep)
	}

	srv.Shutdown(context.Background())
	code, rep = getReady(t, rd)
	if code != http.StatusServiceUnavailable || rep.Ready || rep.UDP.OK || rep.TCP.OK {
		t.Fatalf("listener down: code=%d rep=%+v", code, rep)
	}
	if rep.TCP.Error == "" {
		t.Fatal("listener down: no TCP probe error reported")
	}
}

// /readyz is unauthenticated: a caller other than this host gets the same status
// code but only the verdict, never the errors (upstream servers, the control
// plane's URL) or timestamps. X-Forwarded-For can't claim to be local.
func TestReadyzDetailsOnlyForLoopback(t *testing.T) {
	res := resolver.New(resolver.Options{})
	srv := startDNS(t, res)
	rd := &readiness{res: res, srv: srv, sync: &cluster.SyncHealth{}}

	for _, remote := range []string{"192.0.2.10:5000", "[2001:db8::1]:5000"} {
		rec := httptest.NewRecorder()
		req := httptest.NewRequest(http.MethodGet, "/readyz", nil)
		req.RemoteAddr = remote
		req.Header.Set("X-Forwarded-For", "127.0.0.1")
		rd.ServeHTTP(rec, req)
		body := rec.Body.String()
		if rec.Code != http.StatusOK {
			t.Fatalf("%s: code = %d, want 200", remote, rec.Code)
		}
		if strings.Contains(body, "control_plane") || strings.Contains(body, "resolver") || strings.Contains(body, "error") {
			t.Errorf("%s: details leaked: %s", remote, body)
		}
		var pub publicReport
		if err := json.Unmarshal(rec.Body.Bytes(), &pub); err != nil || !pub.Ready || !pub.UDP || !pub.TCP {
			t.Errorf("%s: public report = %s (err %v)", remote, body, err)
		}
	}

	if _, rep := getReady(t, rd); rep.ControlPlane == nil { // loopback
		t.Errorf("loopback report lacks details: %+v", rep)
	}
}

// -healthcheck exits 0 only on a 200 from /readyz, and prints the report.
func TestRunHealthcheck(t *testing.T) {
	status := http.StatusOK
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/readyz" {
			http.NotFound(w, r)
			return
		}
		w.WriteHeader(status)
		_, _ = w.Write([]byte(`{"ready":true}`))
	}))
	defer ts.Close()

	_, port, _ := net.SplitHostPort(ts.Listener.Addr().String())
	var cfg config.Config
	cfg.API.Address = "0.0.0.0" // wildcard bind -> probed on loopback
	cfg.API.Port, _ = strconv.Atoi(port)

	var out bytes.Buffer
	if code := runHealthcheck(cfg, &out); code != 0 || out.String() != `{"ready":true}` {
		t.Fatalf("ready: code=%d out=%q", code, out.String())
	}
	status = http.StatusServiceUnavailable
	if code := runHealthcheck(cfg, &bytes.Buffer{}); code != 1 {
		t.Fatalf("not ready: code=%d, want 1", code)
	}
	ts.Close()
	if code := runHealthcheck(cfg, &bytes.Buffer{}); code != 1 {
		t.Fatalf("unreachable: code=%d, want 1", code)
	}
}
