package resolver

import (
	"context"
	"log/slog"

	"github.com/miekg/dns"
)

// Server runs the UDP and TCP DNS listeners for a Resolver.
type Server struct {
	addr string
	udp  *dns.Server
	tcp  *dns.Server
}

// NewServer wires res as the handler for both UDP and TCP on addr.
func NewServer(addr string, res *Resolver) *Server {
	mux := dns.NewServeMux()
	mux.HandleFunc(".", res.Handle)
	return &Server{
		addr: addr,
		// UDPSize lets the listener read EDNS queries larger than the bare 512-byte
		// default (e.g. with cookies / client-subnet) without them being truncated.
		udp: &dns.Server{Addr: addr, Net: "udp", Handler: mux, UDPSize: largeUDPSize},
		tcp: &dns.Server{Addr: addr, Net: "tcp", Handler: mux},
	}
}

// ListenAndServe starts both listeners and blocks until one returns an error.
func (s *Server) ListenAndServe() error {
	errc := make(chan error, 2)
	go func() {
		slog.Info("listener up", "net", "udp", "addr", s.addr)
		errc <- s.udp.ListenAndServe()
	}()
	go func() {
		slog.Info("listener up", "net", "tcp", "addr", s.addr)
		errc <- s.tcp.ListenAndServe()
	}()
	return <-errc
}

// Shutdown gracefully stops both listeners.
func (s *Server) Shutdown(ctx context.Context) {
	_ = s.udp.ShutdownContext(ctx)
	_ = s.tcp.ShutdownContext(ctx)
}
