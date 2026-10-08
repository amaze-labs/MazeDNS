package main

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"strconv"
	"sync"
	"time"

	"github.com/miekg/dns"

	"github.com/IPMaze/MazeDNS/internal/cluster"
	"github.com/IPMaze/MazeDNS/internal/config"
	"github.com/IPMaze/MazeDNS/internal/resolver"
)

// probeTimeout bounds each of the readiness probe's UDP and TCP queries. The
// probe is answered in-process ahead of the whole pipeline, so anything slower
// than this means the listener itself is not serving.
const probeTimeout = time.Second

// readiness answers GET /readyz: whether this node's DNS listener answers the
// built-in probe record over UDP and TCP, plus what the resolver and the
// control-plane sync last did. Only the probe and maintenance decide readiness;
// upstream (WAN) and control-plane state are reported but never fail it, because
// a node that is offline from both still serves its local records.
type readiness struct {
	res  *resolver.Resolver
	srv  *resolver.Server
	sync *cluster.SyncHealth // nil in standalone mode
}

// readyReport is the /readyz body. Times are RFC 3339, omitted when never.
type readyReport struct {
	Ready        bool          `json:"ready"`
	UDP          probeResult   `json:"udp"`
	TCP          probeResult   `json:"tcp"`
	Maintenance  bool          `json:"maintenance"`
	Resolver     resolverState `json:"resolver"`
	ControlPlane *syncState    `json:"control_plane,omitempty"` // nil = standalone
	Standalone   bool          `json:"standalone,omitempty"`
}

type probeResult struct {
	OK    bool   `json:"ok"`
	RTTMs int64  `json:"rtt_ms,omitempty"`
	Error string `json:"error,omitempty"`
}

type resolverState struct {
	LastQuery        string `json:"last_query,omitempty"`
	LastForwardOK    string `json:"last_forward_ok,omitempty"`
	LastForwardError string `json:"last_forward_error,omitempty"`
	ForwardError     string `json:"forward_error,omitempty"`
}

type syncState struct {
	LastSyncOK    string `json:"last_sync_ok,omitempty"`
	LastSyncError string `json:"last_sync_error,omitempty"`
	Error         string `json:"error,omitempty"`
}

func rfc3339(t time.Time) string {
	if t.IsZero() {
		return ""
	}
	return t.UTC().Format(time.RFC3339)
}

// probeAddr is where the probe queries the listener: a wildcard bind is reached
// on loopback.
func probeAddr(listen string) string {
	host, port, err := net.SplitHostPort(listen)
	if err != nil {
		return listen
	}
	if ip := net.ParseIP(host); host == "" || (ip != nil && ip.IsUnspecified()) {
		if ip != nil && ip.To4() == nil {
			host = "::1"
		} else {
			host = "127.0.0.1"
		}
	}
	return net.JoinHostPort(host, port)
}

func probe(ctx context.Context, proto, addr string) probeResult {
	q := new(dns.Msg)
	q.SetQuestion(resolver.ProbeName, dns.TypeA)
	cl := &dns.Client{Net: proto, Timeout: probeTimeout}
	resp, rtt, err := cl.ExchangeContext(ctx, q, addr)
	switch {
	case err != nil:
		return probeResult{Error: err.Error()}
	case resp.Rcode != dns.RcodeSuccess || len(resp.Answer) == 0:
		return probeResult{Error: "unexpected answer: " + dns.RcodeToString[resp.Rcode]}
	}
	return probeResult{OK: true, RTTMs: rtt.Milliseconds()}
}

func (rd *readiness) check(ctx context.Context) readyReport {
	addr := probeAddr(rd.srv.Addr())
	var rep readyReport
	var wg sync.WaitGroup
	wg.Add(2)
	go func() { defer wg.Done(); rep.UDP = probe(ctx, "udp", addr) }()
	go func() { defer wg.Done(); rep.TCP = probe(ctx, "tcp", addr) }()
	wg.Wait()

	rep.Maintenance = rd.res.InMaintenance()
	rep.Ready = rep.UDP.OK && rep.TCP.OK && !rep.Maintenance

	h := rd.res.Health()
	rep.Resolver = resolverState{
		LastQuery:        rfc3339(h.LastQuery),
		LastForwardOK:    rfc3339(h.LastForwardOK),
		LastForwardError: rfc3339(h.LastForwardError),
		ForwardError:     h.ForwardError,
	}
	if rd.sync == nil {
		rep.Standalone = true
	} else {
		s := rd.sync.Status()
		rep.ControlPlane = &syncState{
			LastSyncOK:    rfc3339(s.LastOK),
			LastSyncError: rfc3339(s.LastError),
			Error:         s.Error,
		}
	}
	return rep
}

func (rd *readiness) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	rep := rd.check(r.Context())
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	if !rep.Ready {
		w.WriteHeader(http.StatusServiceUnavailable)
	}
	_ = json.NewEncoder(w).Encode(rep)
}

// runHealthcheck implements `dns-agent -healthcheck` for container health checks
// (the image is distroless: no shell or curl). It queries this node's own
// /readyz over loopback, prints the report, and returns the exit code: 0 ready,
// 1 not ready or unreachable.
func runHealthcheck(cfg config.Config, out io.Writer) int {
	host := cfg.API.Address
	if ip := net.ParseIP(host); host == "" || (ip != nil && ip.IsUnspecified()) {
		host = "127.0.0.1"
	}
	url := "http://" + net.JoinHostPort(host, strconv.Itoa(cfg.API.Port)) + "/readyz"
	cl := &http.Client{Timeout: 3 * probeTimeout}
	resp, err := cl.Get(url)
	if err != nil {
		fmt.Fprintln(out, "healthcheck:", err)
		return 1
	}
	defer resp.Body.Close()
	_, _ = io.Copy(out, io.LimitReader(resp.Body, 4096))
	if resp.StatusCode != http.StatusOK {
		return 1
	}
	return 0
}
