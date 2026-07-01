package filter

import (
	"strconv"
	"testing"
)

// benchEngine builds an engine with n blocked domains plus a handful of names to
// look up (a mix of blocked, subdomain-of-blocked, and clean).
func benchEngine(n int) (*Engine, []string) {
	e := New()
	for i := 0; i < n; i++ {
		e.Add("blocked"+strconv.Itoa(i)+".example.com", "ads")
	}
	names := []string{
		"blocked1.example.com",           // exact hit
		"a.b.blocked2.example.com",       // subdomain hit (walks parents)
		"clean.example.org",              // clean, single label walk
		"deep.sub.domain.clean.test.net", // clean, several label walks
	}
	return e, names
}

func benchMatch(b *testing.B, sealed bool) {
	e, names := benchEngine(50000)
	if sealed {
		e.Seal()
	}
	b.ReportAllocs()
	b.ResetTimer()
	b.RunParallel(func(pb *testing.PB) {
		i := 0
		for pb.Next() {
			e.MatchNormalized(names[i&3])
			i++
		}
	})
}

// BenchmarkMatchLocked is the pre-P1 behavior: every lookup takes the RWMutex.
func BenchmarkMatchLocked(b *testing.B) { benchMatch(b, false) }

// BenchmarkMatchSealed is the P1 behavior: a sealed engine reads lock-free.
func BenchmarkMatchSealed(b *testing.B) { benchMatch(b, true) }
