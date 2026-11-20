// Command load sends DNS queries to a resolver at a fixed rate, for the disk
// write benchmark (dev/iobench). Names cycle through a fixed synthetic set
// (with a share of names from the benchmark blocklist, so the log holds both
// forwarded and blocked entries); answers are not checked.
//
//	load -server resolver-a:53 -qps 6 -names 2000 -duration 180s
package main

import (
	"flag"
	"fmt"
	"log"
	"time"

	"github.com/miekg/dns"
)

func main() {
	server := flag.String("server", "127.0.0.1:53", "resolver address")
	qps := flag.Float64("qps", 6, "queries per second")
	names := flag.Int("names", 2000, "distinct query names")
	blockedEvery := flag.Int("blocked-every", 5, "every Nth query asks a blocklisted name (0 = never)")
	duration := flag.Duration("duration", time.Minute, "how long to send")
	flag.Parse()
	if *qps <= 0 || *names <= 0 {
		log.Fatal("qps and names must be positive")
	}

	c := &dns.Client{Net: "udp", Timeout: 2 * time.Second}
	tick := time.NewTicker(time.Duration(float64(time.Second) / *qps))
	defer tick.Stop()
	end := time.After(*duration)
	sent := 0
	for {
		select {
		case <-end:
			fmt.Printf("sent %d queries\n", sent)
			return
		case <-tick.C:
		}
		name := fmt.Sprintf("n%d.bench.invalid.", sent%*names)
		if *blockedEvery > 0 && sent%*blockedEvery == 0 {
			name = BlockedName(sent % *names)
		}
		m := new(dns.Msg)
		m.SetQuestion(name, dns.TypeA)
		go func() { _, _, _ = c.Exchange(m, *server) }()
		sent++
	}
}

// BlockedName is the i-th name of the benchmark blocklist (gen-list writes the
// same names).
func BlockedName(i int) string { return fmt.Sprintf("blocked%d.bench.test.", i) }
