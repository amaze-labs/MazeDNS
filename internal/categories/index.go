package categories

import (
	"hash/fnv"
	"slices"
	"strings"
)

// Index maps domains to categories in about 8 bytes per domain: a sorted array
// of 64-bit FNV-1a hashes whose low byte holds the category. UT1's adult folder
// alone lists ~5.5 million domains, which as a Go map would take well over half
// a gigabyte — too much for an agent on a Raspberry Pi. 56 bits of hash leave
// the odds of two domains colliding negligible (millions of entries in 2^56).
type Index struct {
	entries []uint64
}

// Builder collects (domain, category) pairs for an Index.
type Builder struct {
	entries []uint64
}

// Add records that domain belongs to category (ignored if unknown or empty).
func (b *Builder) Add(domain, category string) {
	id, ok := rank[category]
	domain = normalize(domain)
	if !ok || domain == "" {
		return
	}
	b.entries = append(b.entries, key(domain)|uint64(id+1))
}

// Len is the number of pairs added so far.
func (b *Builder) Len() int { return len(b.entries) }

// Build sorts and de-duplicates the pairs into an Index. The Builder must not be
// used afterwards.
func (b *Builder) Build() *Index {
	slices.Sort(b.entries)
	e := slices.Compact(b.entries)
	b.entries = nil
	return &Index{entries: slices.Clip(e)}
}

// Len is the number of (domain, category) entries.
func (x *Index) Len() int {
	if x == nil {
		return 0
	}
	return len(x.entries)
}

// Lookup returns the category of name: the entry for the most specific listed
// suffix (a.b.example.com, then b.example.com, then example.com), the
// highest-precedence category when that suffix is listed in several.
func (x *Index) Lookup(name string) (string, bool) {
	if x == nil || len(x.entries) == 0 {
		return "", false
	}
	name = normalize(name)
	for name != "" && strings.Contains(name, ".") {
		if id, ok := x.lookupExact(name); ok {
			return precedence[id-1], true
		}
		_, name, _ = strings.Cut(name, ".")
	}
	return "", false
}

// lookupExact returns the best category id (1-based) for exactly name.
func (x *Index) lookupExact(name string) (uint64, bool) {
	k := key(name)
	i, _ := slices.BinarySearch(x.entries, k)
	best := uint64(0)
	for ; i < len(x.entries) && x.entries[i]&^0xff == k; i++ {
		if id := x.entries[i] & 0xff; best == 0 || id < best {
			best = id
		}
	}
	return best, best != 0
}

// Counts returns how many entries each category has.
func (x *Index) Counts() map[string]int {
	out := map[string]int{}
	if x == nil {
		return out
	}
	for _, e := range x.entries {
		if id := int(e & 0xff); id >= 1 && id <= len(precedence) {
			out[precedence[id-1]]++
		}
	}
	return out
}

func key(domain string) uint64 {
	h := fnv.New64a()
	_, _ = h.Write([]byte(domain))
	return h.Sum64() &^ 0xff
}

func normalize(d string) string {
	d = strings.TrimSpace(d)
	d = strings.TrimSuffix(d, ".")
	d = strings.TrimPrefix(d, "*.")
	return strings.ToLower(d)
}
