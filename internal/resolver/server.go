package resolver

import (
	"context"
	"log/slog"
	"net"

	"github.com/miekg/dns"
)

// udpSocketBuf is the UDP receive/send socket buffer we request (SO_RCVBUF/
// SO_SNDBUF). A busy resolver — e.g. fronting many containers that burst DNS
// concurrently — overflows the small kernel default (~208KB), silently dropping
// packets which clients then retry, showing up as high tail latency. The kernel
// caps the actual size at net.core.rmem_max/wmem_max, so raise those too:
//
//	sysctl -w net.core.rmem_max=16777216 net.core.wmem_max=16777216
const udpSocketBuf = 8 << 20 // 8 MiB

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

// ListenAndServe starts both listeners and blocks until one returns an error. The
// UDP socket is created explicitly so we can enlarge its receive/send buffers
// (the default is too small for bursty container DNS — see udpSocketBuf).
func (s *Server) ListenAndServe() error {
	errc := make(chan error, 2)
	go func() {
		pc, err := net.ListenPacket("udp", s.addr)
		if err != nil {
			errc <- err
			return
		}
		if uc, ok := pc.(*net.UDPConn); ok {
			if e := uc.SetReadBuffer(udpSocketBuf); e != nil {
				slog.Warn("udp set read buffer", "err", e)
			}
			if e := uc.SetWriteBuffer(udpSocketBuf); e != nil {
				slog.Warn("udp set write buffer", "err", e)
			}
		}
		s.udp.PacketConn = pc
		slog.Info("listener up", "net", "udp", "addr", s.addr)
		errc <- s.udp.ActivateAndServe()
	}()
	go func() {
		l, err := net.Listen("tcp", s.addr)
		if err != nil {
			errc <- err
			return
		}
		s.tcp.Listener = l
		slog.Info("listener up", "net", "tcp", "addr", s.addr)
		errc <- s.tcp.ActivateAndServe()
	}()
	return <-errc
}

// Shutdown gracefully stops both listeners.
func (s *Server) Shutdown(ctx context.Context) {
	_ = s.udp.ShutdownContext(ctx)
	_ = s.tcp.ShutdownContext(ctx)
}
