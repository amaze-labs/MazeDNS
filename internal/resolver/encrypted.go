package resolver

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"io"
	"math/big"
	"net"
	"net/http"
	"time"

	"github.com/miekg/dns"
)

// TLSCert loads a cert/key pair from files, or generates a self-signed cert when
// both paths are empty. The bool reports whether the cert was self-generated.
func TLSCert(certFile, keyFile string) (tls.Certificate, bool, error) {
	if certFile != "" && keyFile != "" {
		c, err := tls.LoadX509KeyPair(certFile, keyFile)
		return c, false, err
	}
	c, err := selfSignedCert()
	return c, true, err
}

func selfSignedCert() (tls.Certificate, error) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return tls.Certificate{}, err
	}
	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		return tls.Certificate{}, err
	}
	tmpl := x509.Certificate{
		SerialNumber:          serial,
		Subject:               pkix.Name{CommonName: "mazedns"},
		DNSNames:              []string{"mazedns", "localhost"},
		IPAddresses:           []net.IP{net.IPv4(127, 0, 0, 1), net.IPv6loopback},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().AddDate(1, 0, 0),
		KeyUsage:              x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
	}
	der, err := x509.CreateCertificate(rand.Reader, &tmpl, &tmpl, &key.PublicKey, key)
	if err != nil {
		return tls.Certificate{}, err
	}
	return tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key}, nil
}

// NewDoTServer builds a DNS-over-TLS server (RFC 7858) sharing the resolver handler.
func NewDoTServer(addr string, cert tls.Certificate, res *Resolver) *dns.Server {
	mux := dns.NewServeMux()
	mux.HandleFunc(".", res.Handle)
	return &dns.Server{
		Addr:      addr,
		Net:       "tcp-tls",
		Handler:   mux,
		TLSConfig: &tls.Config{Certificates: []tls.Certificate{cert}},
	}
}

// NewDoHServer builds a DNS-over-HTTPS server (RFC 8484) serving res at path.
func NewDoHServer(addr, path string, cert tls.Certificate, res *Resolver) *http.Server {
	mux := http.NewServeMux()
	mux.HandleFunc(path, res.DoHHandler())
	return &http.Server{
		Addr:              addr,
		Handler:           mux,
		TLSConfig:         &tls.Config{Certificates: []tls.Certificate{cert}},
		ReadHeaderTimeout: 5 * time.Second,
	}
}

// DoHHandler implements RFC 8484 (GET ?dns=<base64url> and POST application/dns-message).
func (r *Resolver) DoHHandler() http.HandlerFunc {
	return func(w http.ResponseWriter, req *http.Request) {
		var wire []byte
		var err error
		switch req.Method {
		case http.MethodGet:
			wire, err = base64.RawURLEncoding.DecodeString(req.URL.Query().Get("dns"))
		case http.MethodPost:
			wire, err = io.ReadAll(io.LimitReader(req.Body, 4096))
		default:
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		if err != nil || len(wire) == 0 {
			http.Error(w, "bad request", http.StatusBadRequest)
			return
		}
		msg := new(dns.Msg)
		if err := msg.Unpack(wire); err != nil {
			http.Error(w, "invalid dns message", http.StatusBadRequest)
			return
		}
		start := time.Now()
		client := httpClientIP(req)
		clientEDNS := msg.IsEdns0() != nil
		clientDO := false
		if o := msg.IsEdns0(); o != nil {
			clientDO = o.Do()
		}
		resp, action, category := r.Resolve(msg, client)
		// Don't return signature records to a client that didn't ask for DNSSEC
		// (the AD flag is kept). DoH is over HTTP, so no UDP truncation is needed.
		if !clientDO {
			stripDNSSEC(resp)
		}
		if !clientEDNS {
			removeOPT(resp)
		}
		out, err := resp.Pack()
		if err != nil {
			http.Error(w, "pack error", http.StatusInternalServerError)
			return
		}
		w.Header().Set("Content-Type", "application/dns-message")
		_, _ = w.Write(out)
		r.record(msg, resp, action, category, client, start)
	}
}

func httpClientIP(req *http.Request) string {
	if host, _, err := net.SplitHostPort(req.RemoteAddr); err == nil {
		return host
	}
	return req.RemoteAddr
}
