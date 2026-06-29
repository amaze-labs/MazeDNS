package resolver

import (
	"context"
	"log/slog"
	"net"
	"os"
	stdruntime "runtime"
	"strconv"

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

// maxUDPListeners bounds how many SO_REUSEPORT UDP sockets we may open.
const maxUDPListeners = 8

// udpListeners returns how many UDP sockets to open. Multi-socket SO_REUSEPORT
// ingestion is OPT-IN via MAZEDNS_UDP_LISTENERS (default 1 = a single socket, the
// long-standing behavior). Set it to >1 (e.g. the core count) to spread the UDP
// read loop across cores. Defaulting to 1 keeps the safe single-listener path
// unless an operator explicitly enables the multi-socket path.
func udpListeners() int {
	v, _ := strconv.Atoi(os.Getenv("MAZEDNS_UDP_LISTENERS"))
	if v <= 1 {
		return 1
	}
	if n := stdruntime.GOMAXPROCS(0); v > n {
		v = n
	}
	if v > maxUDPListeners {
		v = maxUDPListeners
	}
	return v
}

// Server runs the UDP and TCP DNS listeners for a Resolver. UDP uses a single
// socket by default, or several sharing the port via SO_REUSEPORT when
// MAZEDNS_UDP_LISTENERS > 1.
type Server struct {
	addr string
	udp  []*dns.Server
	tcp  *dns.Server
}

// NewServer wires res as the handler for both UDP and TCP on addr.
func NewServer(addr string, res *Resolver) *Server {
	mux := dns.NewServeMux()
	mux.HandleFunc(".", res.Handle)
	n := udpListeners()
	s := &Server{
		addr: addr,
		tcp:  &dns.Server{Addr: addr, Net: "tcp", Handler: mux},
	}
	// UDPSize lets the listeners read EDNS queries larger than the bare 512-byte
	// default (e.g. with cookies / client-subnet) without them being truncated.
	for i := 0; i < n; i++ {
		s.udp = append(s.udp, &dns.Server{Addr: addr, Net: "udp", Handler: mux, UDPSize: largeUDPSize})
	}
	return s
}

// ListenAndServe starts the TCP listener and the UDP listener(s) and blocks until
// one returns an error. UDP sockets are created explicitly so we can enlarge their
// buffers (see udpSocketBuf) and enable SO_REUSEPORT so multiple sockets share the
// port and the kernel spreads packets across them.
func (s *Server) ListenAndServe() error {
	errc := make(chan error, len(s.udp)+1)

	// With a single socket use a plain listener (the long-standing path); only set
	// SO_REUSEPORT when several sockets must share the port. The first must bind; if
	// additional ones fail (e.g. SO_REUSEPORT unsupported), we carry on with however
	// many came up.
	lc := net.ListenConfig{}
	if len(s.udp) > 1 {
		lc.Control = reusePortControl
	}
	var bound int
	for i := range s.udp {
		pc, err := lc.ListenPacket(context.Background(), "udp", s.addr)
		if err != nil {
			if bound == 0 {
				return err // couldn't bind even one socket
			}
			slog.Warn("udp extra listener bind failed (continuing)", "err", err, "have", bound)
			break
		}
		if uc, ok := pc.(*net.UDPConn); ok {
			if e := uc.SetReadBuffer(udpSocketBuf); e != nil {
				slog.Warn("udp set read buffer", "err", e)
			}
			if e := uc.SetWriteBuffer(udpSocketBuf); e != nil {
				slog.Warn("udp set write buffer", "err", e)
			}
		}
		srv := s.udp[i]
		srv.PacketConn = pc
		bound++
		go func() { errc <- srv.ActivateAndServe() }()
	}
	s.udp = s.udp[:bound]
	slog.Info("listener up", "net", "udp", "addr", s.addr, "sockets", bound)

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

// Shutdown gracefully stops every listener.
func (s *Server) Shutdown(ctx context.Context) {
	for _, u := range s.udp {
		_ = u.ShutdownContext(ctx)
	}
	_ = s.tcp.ShutdownContext(ctx)
}
